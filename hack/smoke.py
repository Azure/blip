#!/usr/bin/env python3
"""Smoke tests for the Blip platform on a local kind cluster.

Verifies:
  1. Ephemeral session: connect, confirm blip, disconnect -> VM deleted
  2. Retained session:  retain with TTL, reconnect, SCP, port-forward,
                        nested retain with identity propagation (retain inner
                        blip, direct reconnect bypassing outer, independence
                        after outer deleted), TTL expiry
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone

NAMESPACE = "blip"
POOL_NAME = "blip"
REPLICAS = 4
SSH_USER = "runner"
IMAGE_NAME = "localhost/blip:smoke"

# Resolved at runtime from the LoadBalancer service.
GATEWAY_HOST = None
GATEWAY_PORT = 22

# Paths set up by setup()
_tmpdir = None
_ssh_key = None
_known_hosts = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg=""):
    print(msg, flush=True)


def run(cmd, *, check=True, capture=True, timeout=120, verbose=False, **kw):
    """Run a command and return CompletedProcess."""
    if verbose:
        cmdstr = " ".join(cmd) if isinstance(cmd, list) else cmd
        log(f"  $ {cmdstr}")
    r = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout, **kw)
    if check and r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        cmdstr = " ".join(cmd) if isinstance(cmd, list) else cmd
        raise RuntimeError(f"command failed ({r.returncode}): {cmdstr}\n{out}")
    return r


def kubectl(*args, **kw):
    return run(["kubectl", *args], **kw)


def kubectl_json(*args):
    r = kubectl(*args, "-o", "json")
    return json.loads(r.stdout)


def _conn_opts():
    """Common SSH/SCP options for connecting through the gateway."""
    return [
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={_known_hosts}",
        "-o", "LogLevel=ERROR",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-i", _ssh_key,
    ]


def ssh_cmd(user, *extra_args):
    """Build an ssh command list targeting the gateway."""
    return [
        "ssh", *_conn_opts(),
        "-p", str(GATEWAY_PORT),
        *extra_args,
        f"{user}@{GATEWAY_HOST}",
    ]


def scp_cmd(*args):
    """Build an scp command list targeting the gateway."""
    return ["scp", *_conn_opts(), "-P", str(GATEWAY_PORT), *args]


def ssh_session(user, remote_cmd, *, timeout=60):
    """Open an SSH session, run remote_cmd, return (stdout, stderr, rc)."""
    cmd = ssh_cmd(user) + [remote_cmd]
    r = run(cmd, check=False, timeout=timeout)
    return r.stdout, r.stderr, r.returncode


def extract_session_id(stderr_text):
    """Extract blip-XXXXXXXXXX session ID from gateway banner text."""
    m = re.search(r"(blip-[0-9a-f]{10})", stderr_text)
    if not m:
        raise RuntimeError(f"Could not find session ID in output:\n{stderr_text}")
    return m.group(1)


def wait_for(predicate, description, timeout=60, interval=2):
    """Poll predicate() until truthy or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    raise TimeoutError(f"Timed out waiting for: {description}")


def resource_exists(*kubectl_args):
    """Check if a kubectl resource exists (returns bool)."""
    return kubectl(*kubectl_args, check=False).returncode == 0


def vm_annotation(session_id, key):
    """Read a specific annotation from the VM with the given session-id."""
    vms = kubectl_json("get", "vm", "-n", NAMESPACE,
                       "-l", f"blip.io/pool={POOL_NAME}",
                       "--ignore-not-found")
    for item in vms.get("items", []):
        ann = item.get("metadata", {}).get("annotations", {})
        if ann.get("blip.io/session-id") == session_id:
            return ann.get(key)
    return None


def vm_exists(session_id):
    """Check if a VM with the given session-id still exists."""
    return vm_annotation(session_id, "blip.io/session-id") is not None


def vm_name_for_session(session_id):
    """Return the VM name for a given session-id, or None."""
    vms = kubectl_json("get", "vm", "-n", NAMESPACE,
                       "-l", f"blip.io/pool={POOL_NAME}",
                       "--ignore-not-found")
    for item in vms.get("items", []):
        ann = item.get("metadata", {}).get("annotations", {})
        if ann.get("blip.io/session-id") == session_id:
            return item["metadata"]["name"]
    return None


def pvcs_for_vm(vm_name):
    """Return a list of (pvc_name, pvc_uid) tuples for PVCs associated with the VM.

    DataVolumeTemplates create the ownership chain VM -> DV -> PVC.
    We look for DataVolumes owned by the VM, then find PVCs owned by
    those DataVolumes.  We capture UIDs so that callers can distinguish
    the original PVC from a replacement created by the pool controller.
    """
    # Step 1: Find DataVolumes owned by the VM.
    dvs = kubectl_json("get", "dv", "-n", NAMESPACE, "--ignore-not-found")
    dv_names = []
    for dv in dvs.get("items", []):
        owners = dv.get("metadata", {}).get("ownerReferences", [])
        for owner in owners:
            if owner.get("name") == vm_name:
                dv_names.append(dv["metadata"]["name"])

    # Step 2: Find PVCs owned by those DataVolumes.
    if not dv_names:
        return []
    pvcs = kubectl_json("get", "pvc", "-n", NAMESPACE, "--ignore-not-found")
    result = []
    for pvc in pvcs.get("items", []):
        owners = pvc.get("metadata", {}).get("ownerReferences", [])
        for owner in owners:
            if owner.get("name") in dv_names:
                name = pvc["metadata"]["name"]
                uid = pvc["metadata"]["uid"]
                result.append((name, uid))
    return result


def wait_for_vm_deleted(session_id, timeout=60):
    wait_for(
        lambda: not vm_exists(session_id),
        f"VM {session_id} to be deleted",
        timeout=timeout,
    )
    log(f"    VM {session_id} deleted")


def wait_for_pool_ready(min_ready=1, timeout=600):
    """Wait until at least min_ready unclaimed VMs in the pool are Ready."""
    start = time.time()
    last_summary = ""

    def check():
        nonlocal last_summary
        try:
            vms = kubectl_json("get", "vm", "-n", NAMESPACE,
                               "-l", f"blip.io/pool={POOL_NAME}")
        except Exception as e:
            log(f"    [pool] failed to list VMs: {e}")
            return False

        items = vms.get("items", [])
        if not items:
            summary = "no VMs exist yet"
            if summary != last_summary:
                log(f"    [pool] {summary}")
                last_summary = summary
            return False

        ready = 0
        vm_states = []
        for item in items:
            name = item["metadata"]["name"]
            ann = item.get("metadata", {}).get("annotations", {})

            if "blip.io/session-id" in ann:
                vm_states.append(f"{name}:claimed")
                continue

            has_keys = bool(ann.get("blip.io/host-key") and ann.get("blip.io/client-key"))
            vmi_ready = False
            try:
                vmi = kubectl_json("get", "vmi", name, "-n", NAMESPACE)
                for cond in vmi.get("status", {}).get("conditions", []):
                    if cond.get("type") == "Ready" and cond.get("status") == "True":
                        vmi_ready = True
            except Exception:
                pass

            if vmi_ready and has_keys:
                ready += 1
                vm_states.append(f"{name}:ready")
            else:
                reasons = []
                if not vmi_ready:
                    reasons.append("vmi-not-ready")
                if not has_keys:
                    reasons.append("no-keys")
                # Check DataVolume status for additional context.
                try:
                    dvs = kubectl_json("get", "dv", "-n", NAMESPACE,
                                       "-l", f"kubevirt.io/created-by={item['metadata'].get('uid', '')}")
                except Exception:
                    dvs = {"items": []}
                for dv in dvs.get("items", []):
                    dv_phase = dv.get("status", {}).get("phase", "?")
                    if dv_phase != "Succeeded":
                        progress = dv.get("status", {}).get("progress", "?")
                        reasons.append(f"dv:{dv_phase}({progress})")
                vm_states.append(f"{name}:wait({','.join(reasons)})")

        elapsed = int(time.time() - start)
        summary = f"{ready}/{len(items)} ready ({elapsed}s) [{' '.join(vm_states)}]"
        if summary != last_summary:
            log(f"    [pool] {summary}")
            last_summary = summary
        return ready >= min_ready

    try:
        wait_for(check, f">= {min_ready} VM(s) ready", timeout=timeout, interval=5)
    except TimeoutError:
        dump_diagnostics()
        raise
    log(f"    Pool ready (>= {min_ready})")


# ---------------------------------------------------------------------------
# Diagnostics (called on failure only)
# ---------------------------------------------------------------------------

def dump_diagnostics():
    """Dump VM pool state and pod logs. Called only on failure/timeout."""
    log("\n=== Diagnostics ===")

    # Pool status
    try:
        pool = kubectl_json("get", "virtualmachinepool", POOL_NAME, "-n", NAMESPACE)
        spec_r = pool.get("spec", {}).get("replicas", "?")
        status = pool.get("status", {})
        log(f"  Pool: spec.replicas={spec_r} "
            f"status.replicas={status.get('replicas', '?')} "
            f"readyReplicas={status.get('readyReplicas', '?')}")
    except Exception as e:
        log(f"  Pool: {e}")

    # Per-VM detail
    try:
        vms = kubectl_json("get", "vm", "-n", NAMESPACE,
                           "-l", f"blip.io/pool={POOL_NAME}")
    except Exception as e:
        log(f"  VMs: {e}")
        vms = {"items": []}

    # DataVolume and PVC status
    try:
        dvs = kubectl_json("get", "dv", "-n", NAMESPACE)
        for dv in dvs.get("items", []):
            dv_name = dv["metadata"]["name"]
            dv_phase = dv.get("status", {}).get("phase", "?")
            dv_progress = dv.get("status", {}).get("progress", "?")
            log(f"  DV {dv_name}: phase={dv_phase} progress={dv_progress}")
    except Exception as e:
        log(f"  DataVolumes: {e}")

    try:
        pvcs = kubectl_json("get", "pvc", "-n", NAMESPACE)
        for pvc in pvcs.get("items", []):
            pvc_name = pvc["metadata"]["name"]
            pvc_phase = pvc.get("status", {}).get("phase", "?")
            pvc_cap = pvc.get("status", {}).get("capacity", {}).get("storage", "?")
            log(f"  PVC {pvc_name}: phase={pvc_phase} capacity={pvc_cap}")
    except Exception as e:
        log(f"  PVCs: {e}")

    for item in vms.get("items", []):
        name = item["metadata"]["name"]
        ann = item.get("metadata", {}).get("annotations", {})
        st = item.get("status", {})
        log(f"\n  VM {name}: status={st.get('printableStatus', '?')} "
            f"ready={st.get('ready', '?')} "
            f"host-key={'Y' if ann.get('blip.io/host-key') else 'N'} "
            f"client-key={'Y' if ann.get('blip.io/client-key') else 'N'} "
            f"session={ann.get('blip.io/session-id', 'none')}")

        # VMI
        try:
            vmi = kubectl_json("get", "vmi", name, "-n", NAMESPACE)
            vmi_st = vmi.get("status", {})
            conds = ", ".join(
                f"{c['type']}={c['status']}" for c in vmi_st.get("conditions", [])
            )
            ips = [iface.get("ip", "?") for iface in vmi_st.get("interfaces", [])]
            log(f"    VMI: phase={vmi_st.get('phase', '?')} "
                f"node={vmi_st.get('nodeName', '?')} "
                f"ip={','.join(ips) or 'none'} "
                f"conditions=[{conds}]")
        except Exception:
            log(f"    VMI: not found")

        # virt-launcher pod
        try:
            pods = kubectl_json("get", "pods", "-n", NAMESPACE,
                                "-l", f"kubevirt.io/domain={name}")
            for pod in pods.get("items", []):
                pname = pod["metadata"]["name"]
                phase = pod.get("status", {}).get("phase", "?")
                containers = []
                for cs in pod.get("status", {}).get("containerStatuses", []):
                    state_key = next(iter(cs.get("state", {})), "?")
                    containers.append(
                        f"{cs.get('name')}:{state_key}(restarts={cs.get('restartCount', 0)})"
                    )
                log(f"    Pod {pname}: phase={phase} [{', '.join(containers)}]")

                # Recent events
                try:
                    events = kubectl_json("get", "events", "-n", NAMESPACE,
                                          "--field-selector",
                                          f"involvedObject.name={pname}",
                                          "--sort-by=.lastTimestamp")
                    for ev in events.get("items", [])[-3:]:
                        log(f"      event: {ev.get('reason', '?')}: "
                            f"{ev.get('message', '?')}")
                except Exception:
                    pass
        except Exception:
            pass

    # VM serial console logs (cloud-init output goes to ttyS0)
    # KubeVirt stores the serial console log on the host node at a path
    # that varies by version.  We also try `virsh dumpxml` to find the
    # log device path dynamically.
    try:
        vms_for_console = kubectl_json("get", "vm", "-n", NAMESPACE,
                                       "-l", f"blip.io/pool={POOL_NAME}")
        for item in vms_for_console.get("items", []):
            name = item["metadata"]["name"]
            try:
                pods = kubectl_json("get", "pods", "-n", NAMESPACE,
                                    "-l", f"kubevirt.io/domain={name}")
                for pod in pods.get("items", []):
                    pname = pod["metadata"]["name"]
                    log(f"\n  --- serial console (cloud-init): {name} via {pname} ---")

                    found = False

                    # Approach 1: find the log file via virsh dumpxml
                    r = kubectl("exec", pname, "-n", NAMESPACE,
                                "-c", "compute", "--",
                                "bash", "-c",
                                "virsh dumpxml --domain default_blip-* 2>/dev/null"
                                " | grep -A2 'serial' | grep 'source' | head -5"
                                " || virsh list --name 2>/dev/null",
                                check=False, timeout=10)
                    if r.returncode == 0 and r.stdout:
                        log(f"    virsh serial info: {r.stdout.strip()}")

                    # Approach 2: try known paths
                    serial_paths = [
                        "/var/run/kubevirt-private/virt-serial0-log",
                        "/var/run/kubevirt/serial-console-log",
                        "/var/run/kubevirt-private/{name}/virt-serial0-log",
                    ]
                    for log_path in serial_paths:
                        log_path = log_path.format(name=name)
                        r = kubectl("exec", pname, "-n", NAMESPACE,
                                    "-c", "compute", "--",
                                    "cat", log_path,
                                    check=False, timeout=10)
                        if r.returncode == 0 and r.stdout:
                            lines = r.stdout.strip().splitlines()
                            for line in lines[-60:]:
                                log(f"    {line}")
                            found = True
                            break

                    # Approach 3: find any log files under /var/run/kubevirt*
                    if not found:
                        r = kubectl("exec", pname, "-n", NAMESPACE,
                                    "-c", "compute", "--",
                                    "bash", "-c",
                                    "find /var/run/kubevirt* -name '*serial*' -o -name '*log*' 2>/dev/null"
                                    " | head -20; echo '---';"
                                    " ls -laR /var/run/kubevirt-private/ 2>/dev/null | head -40",
                                    check=False, timeout=10)
                        if r.stdout:
                            log(f"    (searching for serial log files:)")
                            for line in r.stdout.strip().splitlines()[:50]:
                                log(f"    {line}")

                    # Approach 4: virt-launcher pod logs (sometimes captures serial)
                    if not found:
                        r = kubectl("logs", pname, "-n", NAMESPACE,
                                    "-c", "compute", "--tail=30",
                                    check=False, timeout=10)
                        if r.returncode == 0 and r.stdout:
                            log(f"    (compute container logs:)")
                            for line in r.stdout.strip().splitlines()[-30:]:
                                log(f"    {line}")

            except Exception as e:
                log(f"    serial console for {name}: {e}")
    except Exception:
        pass

    # Decode and dump the SA token from inside a virt-launcher pod.
    # This lets us check whether KubeVirt's serviceAccountVolume produces
    # a pod-bound token (with 'pod' in the claims) — needed by the
    # ValidatingAdmissionPolicy rule #1.
    try:
        vms_for_token = kubectl_json("get", "vm", "-n", NAMESPACE,
                                     "-l", f"blip.io/pool={POOL_NAME}")
        for item in vms_for_token.get("items", [])[:1]:  # Only need one
            name = item["metadata"]["name"]
            pods = kubectl_json("get", "pods", "-n", NAMESPACE,
                                "-l", f"kubevirt.io/domain={name}")
            for pod in pods.get("items", [])[:1]:
                pname = pod["metadata"]["name"]
                log(f"\n  --- SA token inspection for {name} via {pname} ---")

                # Read the token from the VM's SA disk (the ISO)
                # KubeVirt mounts the SA token at a path inside the compute
                # container that can be accessed.  We look for the token file
                # in the serviceaccount disk image that is generated for the VM.
                r = kubectl("exec", pname, "-n", NAMESPACE,
                            "-c", "compute", "--",
                            "bash", "-c",
                            # The SA disk is stored as a temporary file by
                            # KubeVirt.  Find the ISO file that contains the
                            # token.
                            "find /var/run/kubevirt-private /var/run/kubevirt "
                            "-name '*.iso' -o -name 'token' 2>/dev/null "
                            "| head -20",
                            check=False, timeout=10)
                if r.stdout:
                    log(f"    SA disk/token files: {r.stdout.strip()}")

                # Try to mount the ISO and read the token
                r = kubectl("exec", pname, "-n", NAMESPACE,
                            "-c", "compute", "--",
                            "bash", "-c",
                            "ISO=$(find /var/run/kubevirt* -name '*service*' -name '*.iso' 2>/dev/null | head -1);"
                            " if [ -n \"$ISO\" ]; then"
                            "   mkdir -p /tmp/sa_mount && mount -o loop,ro \"$ISO\" /tmp/sa_mount 2>/dev/null"
                            "   && cat /tmp/sa_mount/token"
                            "   && umount /tmp/sa_mount;"
                            " fi",
                            check=False, timeout=10)
                if r.returncode == 0 and r.stdout and r.stdout.startswith("ey"):
                    token = r.stdout.strip()
                    # Decode JWT claims
                    import base64
                    parts = token.split(".")
                    if len(parts) >= 2:
                        payload = parts[1]
                        # Add padding
                        payload += "=" * (4 - len(payload) % 4)
                        try:
                            claims = json.loads(base64.urlsafe_b64decode(payload))
                            log(f"    Token claims:")
                            for k, v in claims.items():
                                log(f"      {k}: {json.dumps(v)}")
                        except Exception as e:
                            log(f"    Failed to decode token: {e}")
                else:
                    log(f"    Could not read SA token from ISO (rc={r.returncode})")
                    if r.stderr:
                        log(f"    stderr: {r.stderr.strip()[:200]}")
    except Exception as e:
        log(f"  SA token inspection failed: {e}")

    # Node status
    try:
        nodes = kubectl_json("get", "nodes")
        for node in nodes.get("items", []):
            conds = {c["type"]: c["status"]
                     for c in node.get("status", {}).get("conditions", [])}
            log(f"  Node {node['metadata']['name']}: "
                f"Ready={conds.get('Ready', '?')} "
                f"MemPressure={conds.get('MemoryPressure', '?')} "
                f"DiskPressure={conds.get('DiskPressure', '?')}")
    except Exception as e:
        log(f"  Nodes: {e}")

    # Pod logs
    for label, ns in [("app=blip-controller", NAMESPACE),
                      ("app=ssh-gateway", NAMESPACE),
                      ("kubevirt.io=virt-handler", "kubevirt")]:
        try:
            pods = kubectl_json("get", "pods", "-n", ns, "-l", label)
            for pod in pods.get("items", []):
                pname = pod["metadata"]["name"]
                phase = pod.get("status", {}).get("phase", "?")
                log(f"\n  --- logs: {pname} ({ns}, {phase}) ---")
                r = kubectl("logs", pname, "-n", ns,
                            "--tail=80", "--all-containers",
                            check=False, timeout=15)
                log(r.stdout or "(empty)")
                if r.stderr:
                    log(r.stderr)
        except Exception as e:
            log(f"  [{label}] logs: {e}")

    # Kubernetes events (may capture admission rejections)
    try:
        r = kubectl("get", "events", "-n", NAMESPACE,
                    "--sort-by=.lastTimestamp",
                    check=False, timeout=10)
        if r.returncode == 0 and r.stdout:
            log(f"\n  --- events in {NAMESPACE} ---")
            lines = r.stdout.strip().splitlines()
            for line in lines[-40:]:
                log(f"    {line}")
    except Exception:
        pass

    log("\n=== End Diagnostics ===\n")


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def setup():
    """One-time setup: deploy blip, create pool, generate key."""
    global _tmpdir, _ssh_key, _known_hosts, GATEWAY_HOST

    _tmpdir = tempfile.mkdtemp(prefix="blip-smoke-")
    _ssh_key = os.path.join(_tmpdir, "id_ed25519")
    _known_hosts = os.path.join(_tmpdir, "known_hosts")

    log("\n=== Setup ===")

    # 1. Ensure KubeVirt CRDs are available
    log("  Checking KubeVirt...")
    kubectl("get", "crd", "virtualmachines.kubevirt.io")

    # 2. Build and load image
    log("  Building image...")
    run(["docker", "build", "-t", IMAGE_NAME, "-f", "Dockerfile", "."],
        timeout=300, verbose=True)
    log("  Loading image into kind...")
    run(["kind", "load", "docker-image", IMAGE_NAME], timeout=120, verbose=True)

    # 3. Apply manifests with image substitution.
    log("  Applying deploy manifest...")
    with open("manifests/deploy.yaml") as f:
        deploy = f.read()
    manifest = deploy.replace("${REGISTRY}/blip:${BLIP_TAG}", IMAGE_NAME)
    run(["kubectl", "apply", "-f", "-"], input=manifest)

    # Restart controller to pick up the new image (kind reuses the tag
    # so the deployment spec doesn't change and won't trigger a rollout).
    log("  Restarting blip-controller...")
    kubectl("rollout", "restart", "deploy/blip-controller", "-n", NAMESPACE)

    # 4. Wait for controller
    log("  Waiting for blip-controller...")
    kubectl("rollout", "status", "deploy/blip-controller",
            "-n", NAMESPACE, "--timeout=120s", timeout=150)

    # 5. Wait for all generated secrets and configmaps
    log("  Waiting for gateway keys...")
    required_resources = [
        ("secret", "ssh-host-key"),
        ("secret", "ssh-gateway-client-key"),
        ("configmap", "ssh-gateway-client-pubkey"),
        ("configmap", "ssh-gateway-host-pubkey"),
    ]
    wait_for(
        lambda: all(
            resource_exists("get", kind, name, "-n", NAMESPACE)
            for kind, name in required_resources
        ),
        "gateway secrets and configmaps",
        timeout=90,
    )

    # Restart gateway to pick up keys that may have been created after it started.
    log("  Restarting ssh-gateway...")
    kubectl("rollout", "restart", "deploy/ssh-gateway", "-n", NAMESPACE)

    # 6. Create VM pool and scale
    log("  Creating VM pool...")
    kubectl("apply", "-f", "manifests/pool.yaml")
    kubectl("patch", "virtualmachinepool", POOL_NAME, "-n", NAMESPACE,
            "--type=merge", "-p",
            f'{{"spec":{{"replicas":{REPLICAS}}}}}')

    # 7. Generate SSH keypair and add to gateway allow-list
    log("  Generating SSH key...")
    run(["ssh-keygen", "-t", "ed25519", "-f", _ssh_key, "-N", "", "-q"])
    with open(f"{_ssh_key}.pub") as f:
        pub_key = f.read().strip()
    # Register the pubkey as a ConfigMap with the blip.azure.com/user label,
    # which is what the gateway's AuthWatcher watches for allowed keys.
    cm_yaml = (
        f"apiVersion: v1\n"
        f"kind: ConfigMap\n"
        f"metadata:\n"
        f"  name: smoke-test-key\n"
        f"  namespace: {NAMESPACE}\n"
        f"  labels:\n"
        f"    blip.azure.com/user: smoke-test\n"
        f"data:\n"
        f"  pubkey: \"{pub_key}\"\n"
    )
    run(["kubectl", "apply", "-f", "-"], input=cm_yaml)

    # 8. Wait for gateway rollout
    log("  Waiting for ssh-gateway...")
    kubectl("rollout", "status", "deploy/ssh-gateway",
            "-n", NAMESPACE, "--timeout=120s", timeout=150)

    # 9. Resolve LoadBalancer IP (may take a moment after service creation)
    log("  Resolving gateway address...")
    GATEWAY_HOST = wait_for(resolve_gateway_ip, "gateway LoadBalancer IP", timeout=30)
    log(f"    Gateway: {GATEWAY_HOST}:{GATEWAY_PORT}")

    # 10. Wait for all VMs to be ready up-front.  The test sequence consumes
    #     VMs faster than the pool controller can replace them (each
    #     replacement VM takes 60-120s to boot on software-emulated KubeVirt).
    #     By ensuring all replicas are ready before the first test, every
    #     subsequent wait_for_pool_ready() is satisfied by VMs that were
    #     provisioned in this initial (and only) round:
    #
    #       Setup TOFU probe : 1 VM (ephemeral, deleted)
    #       test_ephemeral   : 1 VM (deleted)
    #       test_retained    : 2 VMs (outer retained + inner recursive)
    #                          ----
    #                          4 VMs consumed sequentially
    #
    #     With REPLICAS=4 and all 4 ready here, the pool always has enough
    #     unclaimed VMs for the next test without a second provisioning round.
    log("  Waiting for VMs...")
    wait_for_pool_ready(min_ready=REPLICAS, timeout=600)

    # 11. TOFU: record the gateway's host key. All replicas share the same
    #     stable key, so this mirrors the real user experience.
    log("  Recording gateway host key (TOFU)...")
    tofu_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={_known_hosts}",
        "-o", "LogLevel=ERROR",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-i", _ssh_key,
        "-p", str(GATEWAY_PORT),
        f"{SSH_USER}@{GATEWAY_HOST}",
        "true",
    ]
    r = run(tofu_cmd, check=False, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"TOFU probe failed (rc={r.returncode}): {r.stderr}")
    if not os.path.exists(_known_hosts) or os.path.getsize(_known_hosts) == 0:
        raise RuntimeError("TOFU probe did not record a host key")

    log("=== Setup complete ===\n")


def resolve_gateway_ip():
    """Return the LoadBalancer external IP, or None if not yet assigned."""
    try:
        svc = kubectl_json("get", "svc", "ssh-gateway", "-n", NAMESPACE)
        for ing in svc.get("status", {}).get("loadBalancer", {}).get("ingress", []):
            if ing.get("ip"):
                return ing["ip"]
    except Exception:
        pass
    return None


def teardown():
    log("\n=== Teardown ===")
    kubectl("delete", "virtualmachinepool", POOL_NAME,
            "-n", NAMESPACE, "--ignore-not-found", check=False)
    kubectl("delete", "vm", "--all", "-n", NAMESPACE, check=False)
    kubectl("delete", "dv", "--all", "-n", NAMESPACE, check=False)
    kubectl("delete", "pvc", "--all", "-n", NAMESPACE, check=False)
    if _tmpdir:
        shutil.rmtree(_tmpdir, ignore_errors=True)
    log("=== Teardown complete ===\n")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_ephemeral_session():
    """Connect, verify blip, disconnect -> VM and PVCs deleted."""
    wait_for_pool_ready(min_ready=1)

    stdout, stderr, rc = ssh_session(SSH_USER, "echo BLIP_OK && hostname")
    assert rc == 0, f"SSH failed (rc={rc}): {stderr}"
    assert "BLIP_OK" in stdout, f"Expected BLIP_OK in: {stdout}"

    session_id = extract_session_id(stderr)
    log(f"    Session: {session_id}")

    # Capture the VM name before deletion so we can verify PVC cleanup.
    vm_name = vm_name_for_session(session_id)
    assert vm_name, f"Could not find VM for session {session_id}"
    pvc_info = pvcs_for_vm(vm_name)
    pvc_names = [name for name, _ in pvc_info]
    pvc_uids = {uid for _, uid in pvc_info}
    log(f"    VM: {vm_name}, PVCs: {pvc_names}")

    log("    Waiting for VM deletion...")
    wait_for_vm_deleted(session_id)

    # Verify PVCs owned by the VM are also deleted (DataVolumeTemplates
    # set ownerReferences so the PVC is garbage-collected with the VM).
    # We check by UID because the pool controller may recreate a replacement
    # VM with the same name, which creates a new PVC with the same name.
    if pvc_uids:
        log("    Verifying PVC cleanup...")
        def original_pvcs_gone():
            pvcs = kubectl_json("get", "pvc", "-n", NAMESPACE,
                                "--ignore-not-found")
            for pvc in pvcs.get("items", []):
                if pvc["metadata"]["uid"] in pvc_uids:
                    return False
            return True
        wait_for(original_pvcs_gone, "PVCs deleted with VM", timeout=120)
        log("    PVCs cleaned up")


def test_retained_session():
    """Retained session with reconnect, SCP, port-forward, nested retain, and TTL.

    This consolidated test covers:
      - retain with --ttl: connect, retain with a 180s TTL
      - reconnect: disconnect and reconnect using session ID
      - SCP: upload and download a file via SCP
      - port-forward: TCP tunnel through the gateway
      - nested retain: from inside the retained VM, 'ssh blip' allocates a
        second VM, retains it, and verifies the user can reconnect directly
        to the inner blip (bypassing the outer), even after the outer is deleted
      - TTL expiry: the deallocation controller deletes the inner VM after TTL

    The test uses at most 2 VMs from the initial pool (the retained outer
    session and the recursive inner session), avoiding any need to wait for
    replacement VMs to be provisioned.
    """
    wait_for_pool_ready(min_ready=2)

    # -- Phase 1: Connect and retain with TTL --
    log("    Connecting and retaining with --ttl 180s...")
    # The `blip retain` command writes its status message to stderr inside
    # the VM, but the SSH bridge only forwards the main data stream (stdout)
    # — not extended-data / stderr.  Redirect retain's stderr into stdout
    # so the message is captured reliably on the client side.
    stdout, stderr, rc = ssh_session(
        SSH_USER, "blip retain --ttl 180s 2>&1 && echo RETAINED_OK")
    assert rc == 0, f"SSH failed (rc={rc}): {stderr}"
    assert "RETAINED_OK" in stdout, f"Retain did not succeed: {stdout}"
    assert "retained successfully" in stdout, \
        f"Expected retain status on stdout: {stdout}"

    session_id = extract_session_id(stderr)
    # Session ID should also appear on stdout (for scripting).
    assert session_id in stdout, \
        f"Expected session ID on stdout: {stdout}"
    log(f"    Session: {session_id}")

    # Verify VM is retained (not ephemeral, not deleted)
    wait_for(
        lambda: vm_annotation(session_id, "blip.io/ephemeral") == "false",
        "ephemeral=false after retain",
        timeout=10,
    )
    assert vm_exists(session_id), "Retained VM was deleted"

    # Verify TTL annotation was set.
    # max-duration is stored as elapsed + requested TTL (total seconds from
    # claimed-at), so it will be slightly larger than 180.
    max_dur = vm_annotation(session_id, "blip.io/max-duration")
    max_dur_int = int(max_dur)
    assert 180 <= max_dur_int <= 210, \
        f"Expected max-duration in [180, 210], got {max_dur!r}"
    log(f"    TTL annotation verified ({max_dur}s)")

    # Read claimed-at from the VM annotation for accurate TTL tracking.
    # The deallocation controller computes expiry as claimed-at + max-duration,
    # so we use the same reference point rather than a local monotonic clock.
    claimed_at_str = wait_for(
        lambda: vm_annotation(session_id, "blip.io/claimed-at"),
        "claimed-at annotation",
        timeout=10,
    )
    claimed_at = datetime.fromisoformat(claimed_at_str.replace("Z", "+00:00"))
    if claimed_at.tzinfo is None:
        claimed_at = claimed_at.replace(tzinfo=timezone.utc)
    log(f"    Claimed at: {claimed_at_str}")

    # -- Phase 2: Reconnect --
    log("    Reconnecting...")
    stdout, stderr, rc = ssh_session(session_id, "echo RECONNECTED_OK")
    assert rc == 0, f"Reconnect failed (rc={rc}): {stderr}"
    assert "RECONNECTED_OK" in stdout, f"Expected RECONNECTED_OK: {stdout}"
    assert "Reconnected" in stderr, f"Expected reconnect banner: {stderr}"

    # -- Phase 3: SCP upload + download --
    log("    Testing SCP upload...")
    test_file = os.path.join(_tmpdir, "scp_test.txt")
    with open(test_file, "w") as f:
        f.write("blip-scp-test-data\n")
    run(scp_cmd(test_file, f"{session_id}@{GATEWAY_HOST}:/tmp/scp_test.txt"))

    stdout, _, rc = ssh_session(session_id, "cat /tmp/scp_test.txt")
    assert rc == 0 and "blip-scp-test-data" in stdout, \
        f"SCP upload verify failed: {stdout}"

    log("    Testing SCP download...")
    dl_file = os.path.join(_tmpdir, "scp_download.txt")
    run(scp_cmd(f"{session_id}@{GATEWAY_HOST}:/tmp/scp_test.txt", dl_file))
    with open(dl_file) as f:
        assert "blip-scp-test-data" in f.read(), "Downloaded file content mismatch"

    # -- Phase 4: Port forwarding --
    log("    Testing port forwarding...")
    _, pf_stderr, pf_rc = ssh_session(
        session_id,
        "nohup bash -c 'echo PORT_FWD_OK | nc -l -p 9999 -q1' "
        "&>/dev/null &")
    assert pf_rc == 0, f"Failed to start nc listener (rc={pf_rc}): {pf_stderr}"

    pf_proc = subprocess.Popen(
        ssh_cmd(session_id, "-L", "18222:localhost:9999", "-N"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        # Poll until the tunnel is connectable instead of a fixed sleep.
        sock = None
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(("127.0.0.1", 18222))
                break
            except OSError:
                sock.close()
                sock = None
                time.sleep(0.5)
        assert sock is not None, "Could not connect to port-forward tunnel"
        sock.settimeout(10)
        data = sock.recv(1024).decode()
        sock.close()
        assert "PORT_FWD_OK" in data, f"Port forward data mismatch: {data}"
        log("    Port forwarding verified")
    finally:
        pf_proc.terminate()
        try:
            pf_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pf_proc.kill()
            pf_proc.communicate()

    # -- Phase 5: Recurse with retain and direct reconnect --
    # From inside the retained VM, allocate a nested blip, retain it, extract
    # its session ID, then reconnect to it directly from outside (bypassing
    # the outer blip) using the original user's SSH key.  This exercises the
    # fix that propagates the root user's auth-fingerprint through nested
    # blips, so that `blip retain` + direct reconnect work.
    log("    Testing recurse with retain and direct reconnect...")

    # Phase 5a: Allocate + retain nested blip from inside the outer VM,
    # capturing the nested session ID from the retain output.
    stdout, stderr, rc = ssh_session(
        session_id,
        # Retry loop: the inner gateway config injection may not be ready
        # immediately after the outer blip boots.
        # The inner `blip retain` writes its status to stderr inside the
        # nested VM, but the SSH bridge only forwards stdout.  Use
        # `2>&1` on the retain command so the message reaches the inner
        # SSH client's stdout, and again on the outer ssh invocation so
        # the gateway banner (also on stderr) is merged into $output.
        "for i in $(seq 1 30); do "
        "  output=$(ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=yes "
        "               -o BatchMode=yes blip 'blip retain --ttl 120s 2>&1' 2>&1) ; "
        "  if echo \"$output\" | grep -q 'retained successfully'; then "
        "    echo \"$output\" ; "
        "    exit 0 ; "
        "  fi ; "
        "  sleep 2 ; "
        "done ; "
        "echo \"$output\" ; "
        "exit 1",
        timeout=180,
    )
    assert rc == 0, f"Recurse+retain failed (rc={rc}): {stderr}"
    # The retain command prints the session ID to stdout; the SSH banner
    # (on stderr) also contains it. The inner SSH used 2>&1, so both
    # streams are merged into the outer stdout.
    combined_output = stdout + stderr
    inner_match = re.search(r"(blip-[0-9a-f]{10})", combined_output)
    assert inner_match, \
        f"Could not find inner session ID in output:\n{combined_output}"
    inner_session_id = inner_match.group(1)
    # Make sure we didn't accidentally pick up the outer session ID.
    if inner_session_id == session_id:
        # Find the next match.
        all_ids = re.findall(r"(blip-[0-9a-f]{10})", combined_output)
        inner_ids = [sid for sid in all_ids if sid != session_id]
        assert inner_ids, \
            f"Only found outer session ID in output:\n{combined_output}"
        inner_session_id = inner_ids[0]
    log(f"    Inner session: {inner_session_id}")

    # Verify the inner blip was retained.
    wait_for(
        lambda: vm_annotation(inner_session_id, "blip.io/ephemeral") == "false",
        "inner blip ephemeral=false after retain",
        timeout=30,
    )
    log("    Inner blip retained")

    # Phase 5b: Verify the inner blip has the same user identity as the outer.
    outer_user = vm_annotation(session_id, "blip.io/user")
    inner_user = vm_annotation(inner_session_id, "blip.io/user")
    assert outer_user and inner_user, \
        f"Missing user annotation: outer={outer_user!r}, inner={inner_user!r}"
    assert outer_user == inner_user, \
        f"Identity mismatch: outer={outer_user!r}, inner={inner_user!r}"
    log(f"    Identity propagated: {inner_user}")

    # Phase 5c: Verify the inner blip has the original user's auth fingerprint
    # (not the VM client key fingerprint).
    outer_auth_fp = vm_annotation(session_id, "blip.io/auth-fingerprint")
    inner_auth_fp = vm_annotation(inner_session_id, "blip.io/auth-fingerprint")
    assert outer_auth_fp and inner_auth_fp, \
        f"Missing auth-fingerprint: outer={outer_auth_fp!r}, inner={inner_auth_fp!r}"
    assert outer_auth_fp == inner_auth_fp, \
        f"Auth fingerprint mismatch: outer={outer_auth_fp!r}, inner={inner_auth_fp!r}"
    log(f"    Auth fingerprint propagated: {inner_auth_fp}")

    # Phase 5d: Reconnect directly to the inner blip from outside using the
    # original user's SSH key, bypassing the outer blip entirely.
    log("    Reconnecting directly to inner blip...")
    stdout, stderr, rc = ssh_session(inner_session_id, "echo DIRECT_RECONNECT_OK")
    assert rc == 0, f"Direct reconnect to inner blip failed (rc={rc}): {stderr}"
    assert "DIRECT_RECONNECT_OK" in stdout, \
        f"Expected DIRECT_RECONNECT_OK: {stdout}"
    assert "Reconnected" in stderr, \
        f"Expected reconnect banner: {stderr}"
    log("    Direct reconnect to inner blip verified")

    # Phase 5e: Release the outer blip, then reconnect to the inner blip again
    # to prove the inner blip is fully independent of the outer.
    log("    Releasing outer blip to prove inner blip independence...")
    # Find the outer VM by its session-id annotation and mark it for release.
    vms_json = kubectl_json("get", "vm", "-n", NAMESPACE,
                            "-l", f"blip.io/pool={POOL_NAME}")
    outer_released = False
    for item in vms_json.get("items", []):
        ann = item.get("metadata", {}).get("annotations", {})
        if ann.get("blip.io/session-id") == session_id:
            vm_name = item["metadata"]["name"]
            kubectl("annotate", "vm", vm_name, "-n", NAMESPACE,
                    "blip.io/release=true", "--overwrite")
            log(f"    Outer blip {vm_name} marked for release")
            outer_released = True
            break
    assert outer_released, f"Could not find outer VM with session {session_id}"

    # Wait for the outer blip to be deleted.
    wait_for_vm_deleted(session_id, timeout=60)

    # Reconnect to the inner blip again after the outer is gone.
    log("    Reconnecting to inner blip after outer deleted...")
    stdout, stderr, rc = ssh_session(inner_session_id, "echo INDEPENDENT_OK")
    assert rc == 0, \
        f"Reconnect to inner blip after outer deletion failed (rc={rc}): {stderr}"
    assert "INDEPENDENT_OK" in stdout, \
        f"Expected INDEPENDENT_OK: {stdout}"
    log("    Inner blip independence verified")

    # -- Phase 6: Wait for inner blip TTL expiry --
    # The inner blip was retained with 120s TTL. Wait for the deallocation
    # controller to delete it.
    inner_claimed_at_str = vm_annotation(inner_session_id, "blip.io/claimed-at")
    if inner_claimed_at_str:
        inner_claimed_at = datetime.fromisoformat(
            inner_claimed_at_str.replace("Z", "+00:00"))
        if inner_claimed_at.tzinfo is None:
            inner_claimed_at = inner_claimed_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        inner_elapsed = (now - inner_claimed_at).total_seconds()
        inner_remaining = max(0, 120 - inner_elapsed)
        log(f"    Waiting for inner blip TTL expiry "
            f"({inner_elapsed:.0f}s elapsed, ~{inner_remaining:.0f}s remaining)...")
        wait_for_vm_deleted(inner_session_id, timeout=int(inner_remaining) + 60)
    else:
        # Fallback: just wait a reasonable time.
        log("    Waiting for inner blip TTL expiry...")
        wait_for_vm_deleted(inner_session_id, timeout=180)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    tests = [
        test_ephemeral_session,   # 1 VM — pool has all replicas ready
        test_retained_session,    # 2 VMs — pool still has 2+ ready after ephemeral
    ]

    try:
        setup()
    except Exception:
        log("=== Setup FAILED ===")
        traceback.print_exc()
        dump_diagnostics()
        teardown()
        return 1

    passed = 0
    failed = 0
    try:
        for test in tests:
            name = test.__name__.replace("test_", "").replace("_", " ").title()
            log(f"--- {name} ---")
            t0 = time.time()
            try:
                test()
                passed += 1
                log(f"--- PASS: {name} ({time.time() - t0:.0f}s) ---\n")
            except Exception as e:
                failed += 1
                log(f"--- FAIL: {name} ({time.time() - t0:.0f}s): {e}\n")
                traceback.print_exc()
    finally:
        if failed > 0:
            dump_diagnostics()
        teardown()

    log(f"\n{'=' * 40}")
    log(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    log(f"{'=' * 40}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
