# Ubuntu 24.04 guest root for Blips, booted with the default spec.init
# [/sbin/init]: systemd owns the guest. Build from the repository root after
# `make build` (it copies bin/blip-meta and bin/kubectl-blip):
#   docker build -f images/blip-ubuntu/Dockerfile .
#
# - systemd-networkd: DHCP on any Ethernet NIC (no MAC pinning); the slot's
#   DHCP server leases the slot pod IP. systemd-resolved writes the DNS
#   servers and search domains to /etc/resolv.conf.
# - systemd-logind powers off on the ACPI power button (graceful Blip stop).
# - blip-creds.service: service account credentials from the blip-meta disk
#   in /run/secrets/kubernetes.io/serviceaccount (rotated).
# - blip-identity.service: /run/blip/{identity.json,name,namespace,uid},
#   hostname, one machine-id per Blip.
# - sshd: TCP 22 on the pod IP and vsock port 22 (Blip port forwarding).
#   Host keys and authorized_keys come from blip-ssh-bootstrap.service.
# - kubectl and kubectl-blip (bin/kubectl-blip): with no kubeconfig they use
#   the Blip's service account (KUBERNETES_SERVICE_HOST in /etc/environment),
#   so sessions can derive volumes from themselves and run more Blips; see
#   docs/kubectl-plugin.md, "Inside a Blip". Bash completes `kubectl` and
#   `kubectl blip` (kubectl_complete-blip) in login shells.
# - Tools for working in a session: git, vim-tiny, less, ps, ping, rsync.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv systemd-resolved udev dbus openssh-server \
      curl jq ca-certificates iproute2 openssh-client e2fsprogs \
      bash-completion less vim-tiny procps iputils-ping git rsync \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_*

# Units that are useless in a microVM or would wait for hardware.
RUN systemctl mask \
      systemd-timesyncd.service \
      getty@tty1.service serial-getty@ttyS0.service console-getty.service \
      getty-static.service getty.target \
      systemd-firstboot.service \
      apt-daily.timer apt-daily-upgrade.timer motd-news.timer \
      e2scrub_all.timer fstrim.timer dpkg-db-backup.timer \
 && rm -f /etc/hostname /etc/machine-id && touch /etc/machine-id \
 && systemctl set-default multi-user.target

# Keep kubectl within one minor version of the clusters' API servers.
ARG KUBECTL_VERSION=v1.33.13
ARG KUBECTL_SHA256_amd64=316d712726d857c20744c57cb36aa47cfc79bc0af7e82cebf3780244b654c073
ARG KUBECTL_SHA256_arm64=9fe8aadd5aab9421978c7ac95de6fad304a3c4c0ce9dbf4127579779e0699080
RUN arch=$(dpkg --print-architecture) \
 && case $arch in amd64) sum=$KUBECTL_SHA256_amd64 ;; arm64) sum=$KUBECTL_SHA256_arm64 ;; *) echo "unsupported $arch" >&2; exit 1 ;; esac \
 && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$arch/kubectl" \
 && echo "$sum  /usr/local/bin/kubectl" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/kubectl \
 && printf '%s\n' KUBERNETES_SERVICE_HOST=kubernetes.default.svc KUBERNETES_SERVICE_PORT=443 >>/etc/environment

COPY bin/blip-meta bin/kubectl-blip images/blip-ubuntu/kubectl_complete-blip /usr/local/bin/
COPY images/blip-ubuntu/blip-identity images/blip-ubuntu/blip-ssh-bootstrap /usr/local/sbin/
COPY images/blip-ubuntu/systemd/ /etc/systemd/system/
COPY images/blip-ubuntu/ssh.service.d/blip.conf /etc/systemd/system/ssh.service.d/blip.conf
COPY images/blip-ubuntu/network/80-blip.network /etc/systemd/network/80-blip.network
COPY images/blip-ubuntu/tmpfiles-blip.conf /etc/tmpfiles.d/blip.conf
COPY images/blip-ubuntu/sshd_config.d/blip.conf /etc/ssh/sshd_config.d/blip.conf
COPY images/blip-ubuntu/fstab /etc/fstab

# Plain ssh.service (no socket activation) so sshd always waits for the
# bootstrap; vsock connections use blip-sshd-vsock.socket.
RUN chmod 0755 /usr/local/bin/blip-meta /usr/local/bin/kubectl-blip /usr/local/bin/kubectl_complete-blip \
      /usr/local/sbin/blip-identity /usr/local/sbin/blip-ssh-bootstrap \
 && chmod 0644 /etc/ssh/sshd_config.d/blip.conf /etc/systemd/network/80-blip.network \
 && (systemctl disable ssh.socket || true) \
 && systemctl mask ssh.socket \
 && systemctl unmask systemd-networkd.service systemd-networkd.socket systemd-resolved.service \
 && systemctl enable systemd-networkd.service systemd-networkd-wait-online.service systemd-resolved.service \
      blip-creds.service blip-identity.service blip-ssh-bootstrap.service blip-sshd-vsock.socket ssh.service \
 && systemctl add-wants multi-user.target systemd-logind.service \
 && install -d -m 0700 /root/.ssh

# Completion, and a check that kubectl finds the plugin.
RUN kubectl completion bash >/usr/share/bash-completion/completions/kubectl \
 && kubectl-blip completion bash >/usr/share/bash-completion/completions/kubectl-blip \
 && kubectl plugin list 2>/dev/null | grep -qx /usr/local/bin/kubectl-blip \
 && kubectl blip version

CMD ["/sbin/init"]
