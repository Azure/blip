#!/usr/bin/env python3
"""Smoke tests for the Blip platform on a local kind cluster.

Verifies:
  1. Ephemeral session: connect, confirm blip, disconnect -> VM deleted
  2. Retained session:  retain with TTL, reconnect, SCP, port-forward,
                        nested retain with identity propagation (retain inner
                        blip, direct reconnect bypassing outer, independence
                        after outer deleted), TTL expiry
  3. GitHub Actions:     fake API server, job discovery, VM allocation,
                        runner provisioning, job completion, VM release
"""

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

NAMESPACE = "blip"
POOL_NAME = "blip"
REPLICAS = 3
SSH_USER = "runner"
IMAGE_NAME = "localhost/blip:smoke"
# The base image is loaded directly into kind as a containerDisk.
BASE_IMAGE_TAG = "blip-base:smoke"

# Fake GitHub API server port (bound on the host, reachable from kind via
# the Docker bridge gateway IP).
FAKE_GITHUB_API_PORT = 18443

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

    # Build and load the base VM image used by the pool's containerDisk.
    log("  Preparing base image...")
    base_image = f"localhost/{BASE_IMAGE_TAG}"
    r = run(["docker", "image", "inspect", "blip-base:test"], check=False, timeout=10)
    if r.returncode == 0:
        log("    Reusing existing blip-base:test image")
        run(["docker", "tag", "blip-base:test", base_image], timeout=10)
    else:
        log("    Building base image from scratch...")
        run(["docker", "build", "-t", base_image,
             "-f", "images/base/Containerfile", "."],
            timeout=600, verbose=True)
    log("  Loading base image into kind...")
    run(["kind", "load", "docker-image", base_image], timeout=120, verbose=True)

    # 3. Start fake GitHub Actions API and apply manifests.
    global _fake_github_api
    log("  Starting fake GitHub Actions API...")
    _fake_github_api = FakeGitHubAPI(FAKE_GITHUB_API_PORT)
    _fake_github_api.start(_tmpdir)

    # Determine the host IP accessible from inside kind (Docker bridge gateway).
    r = run(["docker", "network", "inspect", "kind", "-f",
             "{{range .IPAM.Config}}{{.Gateway}} {{end}}"], timeout=10)
    # Pick the IPv4 gateway (skip IPv6).
    host_ip = None
    for gw in r.stdout.strip().split():
        if "." in gw and ":" not in gw:
            host_ip = gw
            break
    if not host_ip:
        raise RuntimeError(f"Could not find IPv4 gateway for kind network: {r.stdout}")
    fake_api_url = f"https://{host_ip}:{FAKE_GITHUB_API_PORT}"
    log(f"    Fake API: {fake_api_url}")

    log("  Applying deploy manifest...")
    with open("manifests/deploy.yaml") as f:
        deploy = f.read()
    manifest = deploy.replace("${REGISTRY}/blip:${BLIP_TAG}", IMAGE_NAME)
    # Inject GITHUB_API_URL env var into the blip-controller container.
    manifest = manifest.replace(
        '        - name: VM_NAMESPACE\n',
        f'        - name: GITHUB_API_URL\n'
        f'          value: "{fake_api_url}"\n'
        f'        - name: VM_NAMESPACE\n')
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
    with open("manifests/pool.yaml") as f:
        pool_manifest = f.read()
    pool_manifest = pool_manifest.replace(
        "$REGISTRY/blip-base:$BLIP_TAG",
        f"localhost/{BASE_IMAGE_TAG}")
    run(["kubectl", "apply", "-f", "-"], input=pool_manifest)
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

    # 7b. Create GitHub Actions ConfigMap and PAT Secret for the Actions test.
    log("  Creating GitHub Actions config...")
    import base64
    pat_b64 = base64.b64encode(_fake_github_api.token.encode()).decode()
    actions_resources = (
        f"apiVersion: v1\n"
        f"kind: ConfigMap\n"
        f"metadata:\n"
        f"  name: github-actions\n"
        f"  namespace: {NAMESPACE}\n"
        f"data:\n"
        f'  runner-labels: "self-hosted,blip"\n'
        f'  repos: "test-org/test-repo"\n'
        f"---\n"
        f"apiVersion: v1\n"
        f"kind: Secret\n"
        f"metadata:\n"
        f"  name: github-pat\n"
        f"  namespace: {NAMESPACE}\n"
        f"data:\n"
        f'  token: "{pat_b64}"\n'
    )
    run(["kubectl", "apply", "-f", "-"], input=actions_resources)

    # 8. Wait for gateway rollout
    log("  Waiting for ssh-gateway...")
    kubectl("rollout", "status", "deploy/ssh-gateway",
            "-n", NAMESPACE, "--timeout=120s", timeout=150)

    # 9. Resolve LoadBalancer IP (may take a moment after service creation)
    log("  Resolving gateway address...")
    GATEWAY_HOST = wait_for(resolve_gateway_ip, "gateway LoadBalancer IP", timeout=30)
    log(f"    Gateway: {GATEWAY_HOST}:{GATEWAY_PORT}")

    # 10. Wait for the pool to be ready.  The single-node kind cluster used
    #     in CI has limited CPU, so we keep REPLICAS=3 — the highest
    #     concurrent need is 2 (test_retained uses an outer + inner VM).
    #     Each test calls wait_for_pool_ready() before starting, so the
    #     pool controller has time to replace consumed VMs between tests.
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
    """Return the gateway address, trying LoadBalancer IP first, then NodePort.

    When cloud-provider-kind is not running, the LoadBalancer IP may be
    assigned but not actually reachable.  In that case we fall back to the
    kind node IP + NodePort.
    """
    global GATEWAY_PORT
    try:
        svc = kubectl_json("get", "svc", "ssh-gateway", "-n", NAMESPACE)

        # Try LB IP first.
        for ing in svc.get("status", {}).get("loadBalancer", {}).get("ingress", []):
            ip = ing.get("ip")
            if ip:
                # Quick connectivity check — the LB IP may be allocated but
                # not actually proxied when cloud-provider-kind isn't running.
                import socket as _socket
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(2)
                try:
                    s.connect((ip, 22))
                    s.close()
                    GATEWAY_PORT = 22
                    return ip
                except OSError:
                    s.close()

        # Fall back to NodePort.
        for port_spec in svc.get("spec", {}).get("ports", []):
            if port_spec.get("name") == "ssh" and port_spec.get("nodePort"):
                node_port = port_spec["nodePort"]
                # Get the kind node IP.
                r = run(["docker", "inspect", "-f",
                         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                         "kind-control-plane"], check=False, timeout=10)
                if r.returncode == 0 and r.stdout.strip():
                    GATEWAY_PORT = node_port
                    return r.stdout.strip()
    except Exception:
        pass
    return None


def teardown():
    log("\n=== Teardown ===")
    if _fake_github_api:
        _fake_github_api.stop()
    kubectl("delete", "virtualmachinepool", POOL_NAME,
            "-n", NAMESPACE, "--ignore-not-found", check=False)
    kubectl("delete", "vm", "--all", "-n", NAMESPACE, check=False)
    if _tmpdir:
        shutil.rmtree(_tmpdir, ignore_errors=True)
    log("=== Teardown complete ===\n")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_ephemeral_session():
    """Connect, verify blip, disconnect -> VM deleted."""
    wait_for_pool_ready(min_ready=1)

    stdout, stderr, rc = ssh_session(SSH_USER, "echo BLIP_OK && hostname")
    assert rc == 0, f"SSH failed (rc={rc}): {stderr}"
    assert "BLIP_OK" in stdout, f"Expected BLIP_OK in: {stdout}"

    session_id = extract_session_id(stderr)
    log(f"    Session: {session_id}")

    vm_name = vm_name_for_session(session_id)
    assert vm_name, f"Could not find VM for session {session_id}"
    log(f"    VM: {vm_name}")

    log("    Waiting for VM deletion...")
    wait_for_vm_deleted(session_id)


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
# Fake GitHub Actions API
# ---------------------------------------------------------------------------

class FakeGitHubAPI:
    """Minimal fake GitHub Actions API for smoke testing.

    Manages a set of fake workflow runs/jobs. The controller polls for queued
    jobs, claims a VM, creates a JIT config, provisions the runner via SSH,
    then polls job status until completion.

    The fake server transitions jobs through states:
      queued -> in_progress (after JIT config is created) -> completed (on demand)

    Thread-safe: the HTTP handler runs in a background thread.
    """

    def __init__(self, port, token="smoke-test-token"):
        self.port = port
        self.token = token
        self._lock = threading.Lock()
        self._runs = {}       # run_id -> {"jobs": {job_id -> status}}
        self._next_run_id = 1000
        self._next_job_id = 5000
        self._jit_created = set()  # job IDs that received JIT configs
        self._server = None
        self._thread = None
        self._certfile = None
        self._keyfile = None

    def add_queued_job(self, labels=None):
        """Add a queued workflow run with one job. Returns (run_id, job_id)."""
        with self._lock:
            run_id = self._next_run_id
            job_id = self._next_job_id
            self._next_run_id += 1
            self._next_job_id += 1
            self._runs[run_id] = {
                "jobs": {
                    job_id: {
                        "status": "queued",
                        "labels": labels or ["self-hosted", "blip"],
                    }
                }
            }
            return run_id, job_id

    def complete_job(self, job_id):
        """Mark a job as completed."""
        with self._lock:
            for run in self._runs.values():
                if job_id in run["jobs"]:
                    run["jobs"][job_id]["status"] = "completed"
                    return
        raise ValueError(f"job {job_id} not found")

    def get_job_status(self, job_id):
        """Get the current status of a job."""
        with self._lock:
            for run in self._runs.values():
                if job_id in run["jobs"]:
                    return run["jobs"][job_id]["status"]
        return None

    def start(self, tmpdir):
        """Start the HTTPS server in a background thread."""
        # Generate a self-signed cert for HTTPS.
        self._certfile = os.path.join(tmpdir, "fake-gh.crt")
        self._keyfile = os.path.join(tmpdir, "fake-gh.key")
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", self._keyfile, "-out", self._certfile,
             "-days", "1", "-nodes", "-subj", "/CN=fake-github-api"],
            timeout=10)

        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # suppress request logs

            def _check_auth(self):
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {api.token}":
                    self.send_error(401, "Unauthorized")
                    return False
                return True

            def _json_response(self, code, data):
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if not self._check_auth():
                    return
                path = self.path.split("?")[0]

                # GET /repos/{owner}/{repo}/actions/runs?status=queued
                if path.endswith("/actions/runs"):
                    with api._lock:
                        runs = []
                        for rid, rdata in api._runs.items():
                            # Include run if it has any queued jobs.
                            if any(j["status"] == "queued"
                                   for j in rdata["jobs"].values()):
                                runs.append({"id": rid})
                        self._json_response(200, {"workflow_runs": runs})
                    return

                # GET /repos/{owner}/{repo}/actions/runs/{id}/jobs
                m = re.match(r".*/actions/runs/(\d+)/jobs", path)
                if m:
                    run_id = int(m.group(1))
                    with api._lock:
                        rdata = api._runs.get(run_id, {"jobs": {}})
                        jobs = []
                        for jid, jdata in rdata["jobs"].items():
                            jobs.append({
                                "id": jid,
                                "status": jdata["status"],
                                "labels": jdata.get("labels", []),
                            })
                    self._json_response(200, {"jobs": jobs})
                    return

                # GET /repos/{owner}/{repo}/actions/jobs/{id}
                m = re.match(r".*/actions/jobs/(\d+)", path)
                if m:
                    job_id = int(m.group(1))
                    status = api.get_job_status(job_id)
                    if status is None:
                        self.send_error(404, "Job not found")
                        return
                    self._json_response(200, {"status": status})
                    return

                self.send_error(404, "Not found")

            def do_POST(self):
                if not self._check_auth():
                    return
                path = self.path.split("?")[0]

                # POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig
                if path.endswith("/actions/runners/generate-jitconfig"):
                    length = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(length)) if length else {}
                    runner_name = body.get("name", "unknown")

                    # Transition all queued jobs to in_progress (the real API
                    # doesn't do this, but we use it as a signal that the
                    # controller picked up the job).
                    with api._lock:
                        for rdata in api._runs.values():
                            for jid, jdata in rdata["jobs"].items():
                                if jdata["status"] == "queued":
                                    jdata["status"] = "in_progress"
                                    api._jit_created.add(jid)

                    self._json_response(201, {
                        "encoded_jit_config": "eyJmYWtlIjogdHJ1ZX0=",
                        "runner": {
                            "id": 42,
                            "name": runner_name,
                        },
                    })
                    return

                self.send_error(404, "Not found")

        self._server = HTTPServer(("0.0.0.0", self.port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._certfile, self._keyfile)
        self._server.socket = ctx.wrap_socket(
            self._server.socket, server_side=True)

        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._thread.join(timeout=5)


# Global fake API instance, started during setup if Actions test is included.
_fake_github_api = None


def test_github_actions():
    """GitHub Actions flow: job discovery, VM allocation, provisioning, completion.

    This test verifies the end-to-end Actions runner lifecycle:
      1. A queued job appears in the fake GitHub API
      2. The actions controller discovers it and claims a VM
      3. The runner-config controller creates a JIT config and SSHes into the VM
      4. The job is marked completed in the fake API
      5. The actions-completion controller releases the VM
    """
    global _fake_github_api
    wait_for_pool_ready(min_ready=1)

    # Add a queued job to the fake API.
    run_id, job_id = _fake_github_api.add_queued_job(
        labels=["self-hosted", "blip"])
    log(f"    Queued fake job: run={run_id}, job={job_id}")

    # Wait for the controller to claim a VM for this job.
    session_id = f"actions-{job_id}"
    log("    Waiting for VM allocation...")
    wait_for(
        lambda: vm_exists(session_id),
        f"VM with session-id {session_id}",
        timeout=60,
    )
    log(f"    VM allocated for {session_id}")

    # Verify the VM has the runner annotations.
    wait_for(
        lambda: vm_annotation(session_id, "blip.io/runner-repo") is not None,
        "runner-repo annotation",
        timeout=30,
    )
    repo = vm_annotation(session_id, "blip.io/runner-repo")
    assert repo == "test-org/test-repo", \
        f"Expected repo test-org/test-repo, got {repo!r}"
    log(f"    Runner repo: {repo}")

    # Wait for the runner-config controller to provision the VM (it creates
    # a JIT config via the fake API and SSHes into the VM).
    log("    Waiting for runner provisioning...")
    wait_for(
        lambda: vm_annotation(session_id, "blip.io/runner-provisioned") == "true",
        "runner-provisioned annotation",
        timeout=120,
    )
    log("    Runner provisioned")

    # Mark the job as completed in the fake API.
    log("    Marking job as completed...")
    _fake_github_api.complete_job(job_id)

    # Wait for the actions-completion controller to release the VM.
    log("    Waiting for VM release...")
    wait_for(
        lambda: vm_annotation(session_id, "blip.io/release") == "true",
        "release annotation",
        timeout=60,
    )
    log("    VM marked for release")

    # Wait for VM deletion.
    log("    Waiting for VM deletion...")
    wait_for_vm_deleted(session_id, timeout=60)
    log("    VM deleted")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    tests = [
        test_ephemeral_session,   # 1 VM — each test waits for pool readiness
        test_retained_session,    # 2 VMs — highest concurrent need
        test_github_actions,      # 1 VM — tests the Actions runner lifecycle
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
