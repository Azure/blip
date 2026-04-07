#!/usr/bin/env python3
"""Smoke tests for the Blip platform on a local kind cluster.

Verifies:
  1. Ephemeral session: connect, confirm blip, disconnect -> VM deleted
  2. Retained session:  connect, retain, disconnect, reconnect -> SCP + port-forward
  3. Retained with TTL: connect, retain --ttl 1m -> VM expires -> disconnect -> VM deleted
  4. Recurse session:   SSH from one blip to another via "ssh blip"
"""

import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback

NAMESPACE = "blip"
POOL_NAME = "default"
REPLICAS = 2
SSH_USER = "runner"
IMAGE_NAME = "localhost/blip:smoke"

# Resolved at runtime from the LoadBalancer service.
GATEWAY_HOST = None
GATEWAY_PORT = 22

# Paths set up by setup()
_tmpdir = None
_ssh_key = None
_ssh_cert = None
_known_hosts = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, *, check=True, capture=True, timeout=120, **kw):
    """Run a command and return CompletedProcess."""
    print(f"  $ {' '.join(cmd) if isinstance(cmd, list) else cmd}", flush=True)
    r = subprocess.run(
        cmd, capture_output=capture, text=True, timeout=timeout, **kw,
    )
    if check and r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        cmdstr = ' '.join(cmd) if isinstance(cmd, list) else cmd
        raise RuntimeError(f"command failed ({r.returncode}): {cmdstr}\n{out}")
    return r


def kubectl(*args, **kw):
    return run(["kubectl", *args], **kw)


def kubectl_json(*args):
    r = kubectl(*args, "-o", "json")
    return json.loads(r.stdout)


def ssh_cmd(user, *extra_args, batch=True):
    """Build an ssh command list targeting the gateway."""
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={_known_hosts}",
        "-o", "LogLevel=ERROR",
        "-i", _ssh_key,
        "-o", f"CertificateFile={_ssh_cert}",
        "-p", str(GATEWAY_PORT),
    ]
    if batch:
        cmd += ["-o", "BatchMode=yes"]
    cmd += list(extra_args)
    cmd.append(f"{user}@{GATEWAY_HOST}")
    return cmd


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


def wait_for_vm_deleted(session_id, timeout=60):
    wait_for(
        lambda: not vm_exists(session_id),
        f"VM with session {session_id} to be deleted",
        timeout=timeout,
    )
    print(f"    VM {session_id} deleted", flush=True)


def wait_for_pool_ready(min_ready=1, timeout=300):
    """Wait until at least min_ready unclaimed VMs in the pool are Ready."""
    def check():
        try:
            vms = kubectl_json("get", "vm", "-n", NAMESPACE,
                               "-l", f"blip.io/pool={POOL_NAME}")
        except Exception:
            return False
        ready = 0
        for item in vms.get("items", []):
            ann = item.get("metadata", {}).get("annotations", {})
            if "blip.io/session-id" in ann:
                continue
            # host-key is written by cloud-init; VM isn't usable without it
            if not ann.get("blip.io/host-key"):
                continue
            name = item["metadata"]["name"]
            try:
                vmi = kubectl_json("get", "vmi", name, "-n", NAMESPACE)
                for cond in vmi.get("status", {}).get("conditions", []):
                    if cond.get("type") == "Ready" and cond.get("status") == "True":
                        ready += 1
                        break
            except Exception:
                continue
        return ready >= min_ready
    wait_for(check, f"at least {min_ready} VM(s) ready in pool",
             timeout=timeout, interval=5)
    print(f"    Pool has >= {min_ready} ready VM(s)", flush=True)


def resolve_gateway_ip():
    """Return the LoadBalancer external IP of the ssh-gateway service."""
    svc = kubectl_json("get", "svc", "ssh-gateway", "-n", NAMESPACE)
    for ing in svc.get("status", {}).get("loadBalancer", {}).get("ingress", []):
        if ing.get("ip"):
            return ing["ip"]
    raise RuntimeError("ssh-gateway service has no LoadBalancer IP")


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def setup():
    """One-time setup: deploy blip, create pool, sign key."""
    global _tmpdir, _ssh_key, _ssh_cert, _known_hosts, GATEWAY_HOST

    _tmpdir = tempfile.mkdtemp(prefix="blip-smoke-")
    _ssh_key = os.path.join(_tmpdir, "id_ed25519")
    _ssh_cert = os.path.join(_tmpdir, "id_ed25519-cert.pub")
    _known_hosts = os.path.join(_tmpdir, "known_hosts")

    print("\n=== Setup ===", flush=True)

    # 1. Ensure KubeVirt CRDs are available
    print("  Checking KubeVirt...", flush=True)
    kubectl("get", "crd", "virtualmachines.kubevirt.io")

    # 2. Build container image and load into kind
    print("  Building container image...", flush=True)
    run(["docker", "build", "-t", IMAGE_NAME, "-f", "Dockerfile", "."],
        timeout=300)
    print("  Loading image into kind...", flush=True)
    run(["kind", "load", "docker-image", IMAGE_NAME], timeout=120)

    # 3. Apply base manifests with image substitution
    print("  Applying deploy.yaml...", flush=True)
    with open("deploy.yaml") as f:
        manifest = f.read()
    manifest = manifest.replace("${REGISTRY}/blip:${BLIP_TAG}", IMAGE_NAME)
    run(["kubectl", "apply", "-f", "-"], input=manifest)

    # 4. Wait for controller (creates the CA secret + configmap)
    print("  Waiting for blip-controller...", flush=True)
    kubectl("rollout", "status", "deploy/blip-controller",
            "-n", NAMESPACE, "--timeout=120s", timeout=150)

    # 5. Wait for the SSH CA secret and host key secret
    print("  Waiting for ssh-ca-keypair secret...", flush=True)
    wait_for(
        lambda: kubectl("get", "secret", "ssh-ca-keypair",
                        "-n", NAMESPACE, check=False).returncode == 0,
        "ssh-ca-keypair secret", timeout=60,
    )
    print("  Waiting for ssh-host-key secret...", flush=True)
    wait_for(
        lambda: kubectl("get", "secret", "ssh-host-key",
                        "-n", NAMESPACE, check=False).returncode == 0,
        "ssh-host-key secret", timeout=60,
    )

    # Gateway pods may have started before the CA secret existed; restart.
    print("  Restarting ssh-gateway pods...", flush=True)
    kubectl("rollout", "restart", "deploy/ssh-gateway", "-n", NAMESPACE)

    # 6. Generate VM pool (Secret + VirtualMachinePool) and apply
    print("  Creating VM pool...", flush=True)
    pool_yaml = run(["go", "run", "./cmd/kubectl-blip", "generate-pool",
                     "-n", NAMESPACE, "--name", POOL_NAME,
                     "--replicas", str(REPLICAS)], timeout=120).stdout
    run(["kubectl", "apply", "-f", "-"], input=pool_yaml)

    # 7. Generate SSH keypair and sign it
    print("  Generating SSH key...", flush=True)
    run(["ssh-keygen", "-t", "ed25519", "-f", _ssh_key, "-N", "", "-q"])
    run(["go", "run", "./cmd/kubectl-blip", "sign-identity",
         "-i", f"{_ssh_key}.pub", "-o", _ssh_cert,
         "-n", NAMESPACE], timeout=120)

    # 8. Wait for gateway rollout
    print("  Waiting for ssh-gateway...", flush=True)
    kubectl("rollout", "status", "deploy/ssh-gateway",
            "-n", NAMESPACE, "--timeout=120s", timeout=150)

    # 9. Resolve the LoadBalancer IP
    GATEWAY_HOST = resolve_gateway_ip()
    print(f"    Gateway at {GATEWAY_HOST}:{GATEWAY_PORT}", flush=True)

    # 10. Wait for VMs to become ready
    print("  Waiting for VMs to become ready...", flush=True)
    wait_for_pool_ready(min_ready=1, timeout=600)

    # 11. TOFU: make an initial connection with accept-new to record the
    #     gateway's host key. All gateway replicas share the same stable
    #     host key, so this mirrors the real user experience: first
    #     connection trusts the key, subsequent ones verify it.
    print("  Recording gateway host key (TOFU)...", flush=True)
    tofu_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={_known_hosts}",
        "-o", "LogLevel=ERROR",
        "-o", "BatchMode=yes",
        "-i", _ssh_key,
        "-o", f"CertificateFile={_ssh_cert}",
        "-p", str(GATEWAY_PORT),
        f"{SSH_USER}@{GATEWAY_HOST}",
        "true",
    ]
    r = run(tofu_cmd, check=False, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(
            f"TOFU probe failed (rc={r.returncode}): {r.stderr}"
        )
    if not os.path.exists(_known_hosts) or os.path.getsize(_known_hosts) == 0:
        raise RuntimeError("TOFU probe did not record a host key")
    print(f"    Host key recorded in {_known_hosts}", flush=True)

    print("=== Setup complete ===\n", flush=True)


def teardown():
    print("\n=== Teardown ===", flush=True)
    kubectl("delete", "virtualmachinepool", POOL_NAME,
            "-n", NAMESPACE, "--ignore-not-found", check=False)
    kubectl("delete", "vm", "--all", "-n", NAMESPACE, check=False)
    if _tmpdir:
        shutil.rmtree(_tmpdir, ignore_errors=True)
    print("=== Teardown complete ===\n", flush=True)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_ephemeral_session():
    """Test 1: Connect, verify blip, disconnect -> VM should be deleted."""
    print("--- Test: Ephemeral Session ---", flush=True)

    wait_for_pool_ready(min_ready=1, timeout=300)

    stdout, stderr, rc = ssh_session(SSH_USER, "echo BLIP_OK && hostname")
    assert rc == 0, f"SSH failed (rc={rc}): {stderr}"
    assert "BLIP_OK" in stdout, f"Expected BLIP_OK in output: {stdout}"

    session_id = extract_session_id(stderr)
    print(f"    Session: {session_id}", flush=True)

    # After disconnect the gateway sets blip.io/release=true and the
    # deallocation controller deletes the VM.
    print("    Waiting for VM to be deleted...", flush=True)
    wait_for_vm_deleted(session_id)

    print("--- PASS: Ephemeral Session ---\n", flush=True)


def test_retained_session():
    """Test 2: Connect, retain, disconnect, reconnect, test SCP + port-forward."""
    print("--- Test: Retained Session ---", flush=True)

    wait_for_pool_ready(min_ready=1, timeout=300)

    # Connect and retain the VM
    stdout, stderr, rc = ssh_session(
        SSH_USER, "blip retain && echo RETAINED_OK"
    )
    assert rc == 0, f"SSH failed (rc={rc}): {stderr}"
    assert "RETAINED_OK" in stdout or "Blip retained successfully" in stdout, \
        f"Retain did not succeed: {stdout}"

    session_id = extract_session_id(stderr)
    print(f"    Session: {session_id}", flush=True)

    # Verify VM is no longer ephemeral
    time.sleep(2)
    ann = vm_annotation(session_id, "blip.io/ephemeral")
    assert ann == "false", f"Expected ephemeral=false after retain, got {ann}"

    # VM should NOT be deleted after disconnect
    time.sleep(5)
    assert vm_exists(session_id), "VM was deleted after retain - should not be"

    # Reconnect using session ID
    print("    Reconnecting...", flush=True)
    stdout, stderr, rc = ssh_session(session_id, "echo RECONNECTED_OK")
    assert rc == 0, f"Reconnect to {session_id} failed (rc={rc}): {stderr}"
    assert "RECONNECTED_OK" in stdout, f"Expected RECONNECTED_OK: {stdout}"
    assert "Reconnected" in stderr, f"Expected reconnect banner: {stderr}"

    # SCP upload
    print("    Testing SCP upload...", flush=True)
    test_file = os.path.join(_tmpdir, "scp_test.txt")
    with open(test_file, "w") as f:
        f.write("blip-scp-test-data\n")

    scp_base = [
        "scp",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={_known_hosts}",
        "-o", "LogLevel=ERROR",
        "-o", "BatchMode=yes",
        "-i", _ssh_key,
        "-o", f"CertificateFile={_ssh_cert}",
        "-P", str(GATEWAY_PORT),
    ]
    run(scp_base + [test_file, f"{session_id}@{GATEWAY_HOST}:/tmp/scp_test.txt"])

    stdout, _, rc = ssh_session(session_id, "cat /tmp/scp_test.txt")
    assert rc == 0 and "blip-scp-test-data" in stdout, \
        f"SCP upload verify failed: {stdout}"

    # SCP download
    print("    Testing SCP download...", flush=True)
    dl_file = os.path.join(_tmpdir, "scp_download.txt")
    run(scp_base + [f"{session_id}@{GATEWAY_HOST}:/tmp/scp_test.txt", dl_file])
    with open(dl_file) as f:
        assert "blip-scp-test-data" in f.read(), "Downloaded file content mismatch"

    # Port forwarding
    print("    Testing port forwarding...", flush=True)
    ssh_session(session_id,
                "nohup bash -c 'echo PORT_FWD_OK | nc -l -p 9999 -q1' "
                "&>/dev/null &")
    time.sleep(1)

    pf_proc = subprocess.Popen(
        ssh_cmd(session_id, "-L", "18222:localhost:9999", "-N"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        time.sleep(2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", 18222))
        data = sock.recv(1024).decode()
        sock.close()
        assert "PORT_FWD_OK" in data, f"Port forward data mismatch: {data}"
        print("    Port forwarding verified", flush=True)
    finally:
        pf_proc.terminate()
        pf_proc.wait()

    # Clean up: manually release the retained VM
    print("    Cleaning up retained VM...", flush=True)
    vms = kubectl_json("get", "vm", "-n", NAMESPACE,
                       "-l", f"blip.io/pool={POOL_NAME}")
    for item in vms.get("items", []):
        ann = item.get("metadata", {}).get("annotations", {})
        if ann.get("blip.io/session-id") == session_id:
            vm_name = item["metadata"]["name"]
            kubectl("annotate", "vm", vm_name, "-n", NAMESPACE,
                    "blip.io/release=true", "--overwrite")
            break

    wait_for_vm_deleted(session_id)
    print("--- PASS: Retained Session ---\n", flush=True)


def test_retained_with_ttl():
    """Test 3: retain --ttl 1m -> VM expires -> session ends -> VM deleted.

    'blip retain --ttl 1m' sets blip.io/max-duration=60 on the VM. The
    deallocation controller deletes the VM once claimed-at + 60s elapses.
    The upstream SSH connection breaks, terminating our session.
    """
    print("--- Test: Retained with TTL ---", flush=True)

    wait_for_pool_ready(min_ready=1, timeout=300)

    cmd = ssh_cmd(SSH_USER)
    cmd.append("blip retain --ttl 1m && echo TTL_RETAINED && sleep 300")

    print("    Connecting with --ttl 1m retain...", flush=True)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    # Watch for TTL_RETAINED on stdout
    stdout_lines = []
    stderr_text = ""

    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    sel.register(proc.stderr, selectors.EVENT_READ)

    retained = False
    deadline = time.time() + 30
    while time.time() < deadline and not retained:
        for key, _ in sel.select(timeout=1):
            data = key.fileobj.readline()
            if not data:
                continue
            if key.fileobj == proc.stdout:
                stdout_lines.append(data)
                if "TTL_RETAINED" in data:
                    retained = True
            else:
                stderr_text += data

    assert retained, (
        f"TTL retain did not succeed. stdout={stdout_lines}, stderr={stderr_text}"
    )

    # Drain remaining stderr to capture session ID
    extra_deadline = time.time() + 5
    while time.time() < extra_deadline:
        for key, _ in sel.select(timeout=0.5):
            data = key.fileobj.readline()
            if data and key.fileobj == proc.stderr:
                stderr_text += data

    session_id = extract_session_id(stderr_text)
    print(f"    Session: {session_id} (TTL 1m)", flush=True)
    sel.unregister(proc.stdout)
    sel.unregister(proc.stderr)
    sel.close()

    # Wait for the deallocation controller to delete the VM (~60s),
    # which breaks the upstream and terminates our session.
    print("    Waiting for session to end (VM deletion)...", flush=True)
    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise RuntimeError("Session was not terminated after TTL expiry")

    print(f"    Session terminated (rc={proc.returncode})", flush=True)

    print("    Waiting for VM to be deleted...", flush=True)
    wait_for_vm_deleted(session_id)

    print("--- PASS: Retained with TTL ---\n", flush=True)


def test_recurse_session():
    """Test 4: SSH from one blip into another via 'ssh blip'.

    The gateway injects SSH credentials and config into each VM so that
    running 'ssh blip' from inside a blip connects back to the gateway
    and allocates a new (recursive) blip. This test proves the full
    recursive path works end-to-end:

      local -> gateway -> VM-1  --ssh blip-->  gateway -> VM-2
    """
    print("--- Test: Recurse Session ---", flush=True)

    # We need two VMs: one for the outer session and one for the inner
    # recursive session.
    wait_for_pool_ready(min_ready=2, timeout=300)

    # The gateway injects the VM identity asynchronously after the
    # upstream connection is established, so the credentials may not be
    # available immediately. We retry the inner SSH a few times.
    stdout, stderr, rc = ssh_session(
        SSH_USER,
        "for i in $(seq 1 15); do "
        "  if ssh -o StrictHostKeyChecking=yes -o BatchMode=yes "
        "       blip 'echo RECURSE_OK'; then "
        "    exit 0; "
        "  fi; "
        "  sleep 2; "
        "done; "
        "exit 1",
        timeout=90,
    )
    assert rc == 0, f"Recurse SSH failed (rc={rc}): {stderr}"
    assert "RECURSE_OK" in stdout, f"Expected RECURSE_OK in output: {stdout}"

    session_id = extract_session_id(stderr)
    print(f"    Outer session: {session_id}", flush=True)

    # Both the outer and inner sessions are ephemeral, so the gateway
    # releases them on disconnect. Wait for the outer VM to be deleted
    # to confirm cleanup.
    print("    Waiting for outer VM to be deleted...", flush=True)
    wait_for_vm_deleted(session_id)

    print("--- PASS: Recurse Session ---\n", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    tests = [
        test_ephemeral_session,
        test_retained_session,
        test_retained_with_ttl,
        test_recurse_session,
    ]

    try:
        setup()
    except Exception:
        print("=== Setup FAILED ===", flush=True)
        traceback.print_exc()
        teardown()
        return 1

    passed = 0
    failed = 0
    try:
        for test in tests:
            try:
                test()
                passed += 1
            except Exception as e:
                failed += 1
                print(f"--- FAIL: {test.__name__}: {e}\n", flush=True)
                traceback.print_exc()
            # Wait for pool to replenish between tests
            try:
                wait_for_pool_ready(min_ready=1, timeout=300)
            except TimeoutError:
                print("  Warning: pool did not replenish", flush=True)
    finally:
        teardown()

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*40}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
