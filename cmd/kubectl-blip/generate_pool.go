package main

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	goyaml "gopkg.in/yaml.v3"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	virtv1 "kubevirt.io/api/core/v1"
	poolv1beta1 "kubevirt.io/api/pool/v1beta1"
	"sigs.k8s.io/yaml"
)

//go:embed assets/blip.sh assets/register-host-key.sh
var assets embed.FS

type cloudConfig struct {
	DiskSetup      map[string]diskSetup `yaml:"disk_setup,omitempty"`
	FSSetup        []fsSetup            `yaml:"fs_setup,omitempty"`
	Mounts         [][]string           `yaml:"mounts,omitempty"`
	Users          []user               `yaml:"users,omitempty"`
	PackageUpdate  bool                 `yaml:"package_update"`
	PackageUpgrade bool                 `yaml:"package_upgrade"`
	Packages       []string             `yaml:"packages,omitempty"`
	WriteFiles     []writeFile          `yaml:"write_files,omitempty"`
	RunCmd         []interface{}        `yaml:"runcmd,omitempty"`
}

type diskSetup struct {
	TableType string `yaml:"table_type"`
	Overwrite bool   `yaml:"overwrite"`
}

type fsSetup struct {
	Device     string `yaml:"device"`
	Filesystem string `yaml:"filesystem"`
	Overwrite  bool   `yaml:"overwrite"`
}

type user struct {
	Name       string `yaml:"name"`
	Sudo       string `yaml:"sudo"`
	Shell      string `yaml:"shell"`
	LockPasswd bool   `yaml:"lock_passwd"`
}

type writeFile struct {
	Path        string `yaml:"path"`
	Permissions string `yaml:"permissions"`
	Content     string `yaml:"content"`
}

func mustReadAsset(name string) string {
	data, err := assets.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("read embedded asset %s: %v", name, err))
	}
	return string(data)
}

func buildCloudConfig() cloudConfig {
	blipScript := mustReadAsset("assets/blip.sh")
	registerHostKey := mustReadAsset("assets/register-host-key.sh")

	return cloudConfig{
		DiskSetup: map[string]diskSetup{
			"/dev/vdb": {
				TableType: "gpt",
				Overwrite: false,
			},
		},
		FSSetup: []fsSetup{
			{
				Device:     "/dev/vdb",
				Filesystem: "ext4",
				Overwrite:  false,
			},
		},
		Mounts: [][]string{
			{"/dev/vdb", "/home", "ext4", "defaults,nofail", "0", "2"},
		},
		Users: []user{
			{
				Name:       "runner",
				Sudo:       "ALL=(ALL) NOPASSWD:ALL",
				Shell:      "/bin/bash",
				LockPasswd: true,
			},
		},
		PackageUpdate:  true,
		PackageUpgrade: false,
		Packages:       []string{"ca-certificates"},
		WriteFiles: []writeFile{
			{
				Path:        "/usr/local/bin/blip",
				Permissions: "0755",
				Content:     blipScript,
			},
		},
		RunCmd: buildRunCmd(registerHostKey),
	}
}

func buildRunCmd(registerHostKey string) []interface{} {
	return []interface{}{
		// KubeVirt's serviceaccount ISO is 0640; copy to a world-readable
		// path instead of using cloud-init mounts (which would shadow the copy on remount).
		"mkdir -p /var/run/secrets/kubernetes.io/serviceaccount && mount -t iso9660 -o ro /dev/vdc /var/run/secrets/kubernetes.io/serviceaccount && cp -a /var/run/secrets/kubernetes.io/serviceaccount /var/run/secrets/kubernetes.io/serviceaccount-rw && umount /var/run/secrets/kubernetes.io/serviceaccount && rmdir /var/run/secrets/kubernetes.io/serviceaccount && mv /var/run/secrets/kubernetes.io/serviceaccount-rw /var/run/secrets/kubernetes.io/serviceaccount && chmod -R a+r /var/run/secrets/kubernetes.io/serviceaccount",
		[]string{"/bin/bash", "-c", registerHostKey},
		"chmod -x /etc/update-motd.d/*",
		// Memory optimisation: disable services unnecessary for ephemeral SSH VMs.
		"systemctl disable --now snapd.service snapd.socket snapd.seeded.service snapd.snap-repair.timer || true",
		"apt-get purge -y --auto-remove snapd && rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd || true",
		"systemctl disable --now multipathd.service multipathd.socket || true",
		"systemctl disable --now ModemManager.service || true",
		"systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer || true",
		"systemctl disable --now udisks2.service || true",
		"systemctl disable --now polkit.service || true",
		"systemctl disable --now fwupd.service || true",
		"systemctl disable --now packagekit.service || true",
		"systemctl disable --now networkd-dispatcher.service || true",
		"touch /etc/cloud/cloud-init.disabled",
		"mkdir -p /etc/systemd/journald.conf.d",
		"printf '[Journal]\\nSystemMaxUse=16M\\nRuntimeMaxUse=16M\\n' > /etc/systemd/journald.conf.d/size.conf",
		"systemctl restart systemd-journald",
		"sync && echo 3 > /proc/sys/vm/drop_caches || true",
	}
}

func cloudInitSecretName(poolName string) string {
	return poolName + "-cloudinit"
}

// buildCloudInitSecret creates a Secret for cloud-init userdata, which exceeds KubeVirt's inline 2048-byte limit.
func buildCloudInitSecret(namespace, poolName string) *k8sv1.Secret {
	cc := buildCloudConfig()
	userDataBytes, err := goyaml.Marshal(cc)
	if err != nil {
		panic(fmt.Sprintf("marshal cloud-config: %v", err))
	}
	userData := "#cloud-config\n" + string(userDataBytes)

	return &k8sv1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cloudInitSecretName(poolName),
			Namespace: namespace,
		},
		StringData: map[string]string{
			"userdata": userData,
		},
	}
}

func buildVMPool(namespace, name string, replicas int32) *poolv1beta1.VirtualMachinePool {
	runStrategy := virtv1.RunStrategyAlways
	terminationGracePeriod := int64(5)

	labels := map[string]string{
		"blip.io/pool": name,
	}

	return &poolv1beta1.VirtualMachinePool{
		TypeMeta: metav1.TypeMeta{
			APIVersion: poolv1beta1.SchemeGroupVersion.String(),
			Kind:       "VirtualMachinePool",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: poolv1beta1.VirtualMachinePoolSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			VirtualMachineTemplate: &poolv1beta1.VirtualMachineTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: virtv1.VirtualMachineSpec{
					RunStrategy: &runStrategy,
					Template: &virtv1.VirtualMachineInstanceTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: labels,
						},
						Spec: virtv1.VirtualMachineInstanceSpec{
							TerminationGracePeriodSeconds: &terminationGracePeriod,
							Domain: virtv1.DomainSpec{
								CPU: &virtv1.CPU{
									Cores:   2,
									Sockets: 1,
									Threads: 1,
								},
								Memory: &virtv1.Memory{
									Guest: resourceQuantityPtr("4Gi"),
								},
								Devices: virtv1.Devices{
									Disks: []virtv1.Disk{
										{
											Name:       "rootdisk",
											DiskDevice: virtv1.DiskDevice{Disk: &virtv1.DiskTarget{Bus: virtv1.DiskBusVirtio}},
										},
										{
											Name:       "datadisk",
											DiskDevice: virtv1.DiskDevice{Disk: &virtv1.DiskTarget{Bus: virtv1.DiskBusVirtio}},
										},
										{
											Name:       "sadisk",
											DiskDevice: virtv1.DiskDevice{Disk: &virtv1.DiskTarget{Bus: virtv1.DiskBusVirtio}},
										},
										{
											Name:       "cloudinitdisk",
											DiskDevice: virtv1.DiskDevice{Disk: &virtv1.DiskTarget{Bus: virtv1.DiskBusVirtio}},
										},
									},
									Interfaces: []virtv1.Interface{
										{
											Name: "default",
											InterfaceBindingMethod: virtv1.InterfaceBindingMethod{
												Masquerade: &virtv1.InterfaceMasquerade{},
											},
										},
									},
								},
								Resources: virtv1.ResourceRequirements{
									OvercommitGuestOverhead: true,
									Requests: k8sv1.ResourceList{
										k8sv1.ResourceMemory: resource.MustParse("1Gi"),
										k8sv1.ResourceCPU:    resource.MustParse("500m"),
									},
								},
							},
							Networks: []virtv1.Network{
								{
									Name: "default",
									NetworkSource: virtv1.NetworkSource{
										Pod: &virtv1.PodNetwork{},
									},
								},
							},
							ReadinessProbe: &virtv1.Probe{
								Handler: virtv1.Handler{
									TCPSocket: &k8sv1.TCPSocketAction{
										Port: intstr.FromInt32(22),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       3,
								FailureThreshold:    10,
							},
							Volumes: []virtv1.Volume{
								{
									Name: "rootdisk",
									VolumeSource: virtv1.VolumeSource{
										ContainerDisk: &virtv1.ContainerDiskSource{
											Image:           "quay.io/containerdisks/ubuntu:24.04",
											ImagePullPolicy: k8sv1.PullIfNotPresent,
										},
									},
								},
								{
									Name: "datadisk",
									VolumeSource: virtv1.VolumeSource{
										EmptyDisk: &virtv1.EmptyDiskSource{
											Capacity: resource.MustParse("20Gi"),
										},
									},
								},
								{
									Name: "sadisk",
									VolumeSource: virtv1.VolumeSource{
										ServiceAccount: &virtv1.ServiceAccountVolumeSource{
											ServiceAccountName: "vm-release",
										},
									},
								},
								{
									Name: "cloudinitdisk",
									VolumeSource: virtv1.VolumeSource{
										CloudInitNoCloud: &virtv1.CloudInitNoCloudSource{
											UserDataSecretRef: &k8sv1.LocalObjectReference{
												Name: cloudInitSecretName(name),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceQuantityPtr(s string) *resource.Quantity {
	q := resource.MustParse(s)
	return &q
}

func newGeneratePoolCmd() *cobra.Command {
	var (
		namespace string
		name      string
		replicas  int32
	)

	cmd := &cobra.Command{
		Use:   "generate-pool",
		Short: "Generate a VirtualMachinePool manifest",
		Long: `Generates a VirtualMachinePool YAML manifest for the Blip VM pool
and prints it to stdout. The cloud-init configuration, including
embedded shell scripts, is built programmatically.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGeneratePool(namespace, name, replicas)
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "blip", "Kubernetes namespace for the pool")
	cmd.Flags().StringVar(&name, "name", "default", "Name of the VirtualMachinePool")
	cmd.Flags().Int32Var(&replicas, "replicas", 5, "Number of VM replicas")

	return cmd
}

func runGeneratePool(namespace, name string, replicas int32) error {
	secret := buildCloudInitSecret(namespace, name)
	pool := buildVMPool(namespace, name, replicas)

	secretOut, err := yaml.Marshal(secret)
	if err != nil {
		return fmt.Errorf("marshal cloud-init Secret: %w", err)
	}

	poolOut, err := yaml.Marshal(pool)
	if err != nil {
		return fmt.Errorf("marshal VirtualMachinePool: %w", err)
	}

	filter := func(raw []byte) string {
		var filtered []string
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "status: {}" || trimmed == "creationTimestamp: null" {
				continue
			}
			filtered = append(filtered, line)
		}
		return strings.Join(filtered, "\n")
	}

	_, err = fmt.Fprintf(os.Stdout, "%s---\n%s", filter(secretOut), filter(poolOut))
	return err
}
