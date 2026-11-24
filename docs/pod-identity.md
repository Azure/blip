<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# Pod identity lookup

The node agent serves this read-only API on its existing stream listener, exposed
through the Kubernetes API server:

```text
GET /apis/identity.blip.dev/v1alpha1/namespaces/{ns}/podidentities/{pod}?uid={podUID}
```

It resolves a Pod to its **current unfinished, claimed Blip** and that Blip's
`spec.state` BlipState. The top-level `metadata` describes the **Pod**, not the
Blip. A current claim can be `Pending`, `Running`, or `Saving`; this is not a
running-VM health check or a historical lookup.

```sh
kubectl get --raw '/apis/identity.blip.dev/v1alpha1/namespaces/workloads/podidentities/warm-pod-1?uid=11111111-1111-1111-1111-111111111111'
```

Example response:

```json
{
  "apiVersion": "identity.blip.dev/v1alpha1",
  "kind": "PodIdentity",
  "metadata": {
    "namespace": "workloads",
    "name": "warm-pod-1",
    "uid": "11111111-1111-1111-1111-111111111111",
    "labels": {},
    "annotations": {}
  },
  "blip": {
    "namespace": "workloads",
    "name": "command-42",
    "uid": "22222222-2222-2222-2222-222222222222",
    "labels": {"chat.blip.dev/session": "session-7"},
    "annotations": {},
    "phase": "Running",
    "pool": "default"
  },
  "state": {
    "namespace": "workloads",
    "name": "session-7",
    "uid": "33333333-3333-3333-3333-333333333333",
    "labels": {"chat.blip.dev/session": "true"},
    "annotations": {"chat.blip.dev/profile": "restricted"}
  }
}
```

Metadata maps above are abbreviated; **all labels and annotations** on each
object are returned (absent maps may be `null`). Treat access as a privileged,
sensitive read permission.

## Lookup and failure semantics

- `200`: a current claim resolves to a Blip and its referenced BlipState.
- `404`: an object is missing, the Pod has no current claim, the claim is stale
  or finished, the Pod or Blip is deleting, or a Pod/Blip UID binding does not
  match. The state's UID must also match the Blip's pinned root-state UID, when
  set. A supplied `uid` must match the Pod UID.
- `500`: an unexpected lookup/backend error. Authentication and authorization
  failures are `401`/`403`; an unconfigured identity backend returns `503`.

The `uid` query parameter is optional but **strongly recommended** to prevent
confusing a replacement Pod with the original. It does not pin the Blip: a
reusable warm Pod can retain the same Pod UID while being reassigned to another
Blip. Do not positively cache identity across Blip reassignment. Reads can be
stale, including from Kubernetes caches, and the Pod, Blip, and state lookup is
not a transaction. There is no transactional guarantee between lookup and use.

## Caller authorization

The endpoint authenticates the **lookup caller** and uses a SubjectAccessReview
for namespaced `get` on `podidentities` in group `identity.blip.dev`. It does
**not** validate the VM's JWT or authorize the VM's requested operation.

Front-proxy identity headers require a client certificate verified against the
kube-apiserver's published front-proxy CA. The node agent reads
`requestheader-client-ca-file`, `requestheader-allowed-names`, and
`client-ca-file` from the `kube-system/extension-apiserver-authentication`
ConfigMap, so every node can verify the API server without a host path. The
API server publishes `requestheader-allowed-names` as a JSON array; an empty
array accepts any name the front-proxy CA issued. When
that ConfigMap has no request-header CA, the node agent rejects proxy headers
entirely and falls back to direct certificate or bearer-token authentication.
`--stream-client-ca` can name a CA file to override both CAs on clusters that do
not publish one. Direct bearer-token requests are verified with TokenReview.

For example, grant the Envoy service account access only in `workloads`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-identity-reader
  namespace: workloads
rules:
  - apiGroups: [identity.blip.dev]
    resources: [podidentities]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: envoy-pod-identity-reader
  namespace: workloads
subjects:
  - kind: ServiceAccount
    name: envoy
    namespace: gateway
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-identity-reader
```

The `gateway/envoy` service account must exist. Do **not** automatically grant
this permission to VM service accounts.

## Guest API identity

A Blip's guest reaches the Kubernetes API as the Blip's service account:
`spec.serviceAccountName` when set, otherwise its pool's. The node agent mints
a short-lived, unbound token for that account and refreshes it before it
expires. The pod's Envoy sidecar, bound to loopback port 15080, adds the token
to guest requests; the guest kubeconfig itself holds no credential. The
runtime redirects the guest's TAP gateway to that loopback port, so
`kube-apiserver` resolves through the sidecar, which also proxies the pool's
fixed HTTPS endpoints.

An endpoint with `podBound: true` instead gets a token issued to the pod's own
service account (usually `default`) and bound to the pod. Kubernetes rejects
bound tokens for any other account, and the pod is deliberately identity-free
so a warm VM can serve any Blip. Only services that verify the
`authentication.kubernetes.io/pod-name` claim, such as blipchat, need this.

Isolation is now RBAC on that service account. **Breaking change:** the
`blip-vm-owner` admission policy and its `blip-vm-owners` table are gone, so an
owner label no longer confines a restricted Blip by name. Blips that share a
pool service account share its permissions; give each trust boundary its own
service account and RBAC.

## Envoy ordering and trust boundaries

1. Run Envoy `jwt_authn` **first**, requiring successful validation of the VM
   JWT's signature, issuer, audience, and expiration (`exp`).
2. Derive the lookup namespace, Pod name, and UID only from the verified JWT
   payload in dynamic metadata: `kubernetes.io.namespace`,
   `kubernetes.io.pod.name`, and `kubernetes.io.pod.uid`. These identify fields in
   the nested `kubernetes.io` claim. Never use an unverified decoded payload or
   caller-supplied identity headers.
3. Call the lookup through **kube-apiserver**, authenticating with **Envoy's own
   Kubernetes service-account token with an API-server audience**. Do not forward
   the VM-audience token as the lookup credential. Provision and rotate Envoy's
   token securely.
4. Apply authorization policy only after a successful lookup. Fail closed: deny
   on every non-`200` response, timeout, malformed response, or missing required
   identity/policy context. Account for cache staleness and reassignment races.

A Lua filter can perform step 3 with `httpCall` to a configured kube-apiserver
cluster and read the JSON response before forwarding the request. Configure a
bounded timeout and validate the API server's TLS certificate. JWT verification
must run before the Lua filter; decoding a JWT in Lua is not verification.

The chat profile is `state.annotations["chat.blip.dev/profile"]`. Trust it only
for a **protected chat session**: the state must have label
`chat.blip.dev/session=true`, the Blip's `chat.blip.dev/session` label must equal
`state.name`, and the state must be the one mapped by the Blip's `spec.state`.
Those markers and the profile must be protected from untrusted writers by
appropriate admission/RBAC controls. Arbitrary user-controlled labels or
annotations are not trusted policy, even though the API returns them.

This API supplies identity context, **not authorization**. The proxy/policy
layer remains responsible for deciding whether the authenticated VM may perform
the requested operation.
