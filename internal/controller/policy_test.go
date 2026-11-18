package controller

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/yaml"

	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// loadVMOwnerPolicy compiles deploy/base/vm-owner-policy.yaml the way the
// API server's validating admission policy plugin does.
func loadVMOwnerPolicy(t *testing.T) validating.Validator {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/base/vm-owner-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var policy *admissionv1.ValidatingAdmissionPolicy
	notFound := map[string]admissionv1.ParameterNotFoundActionType{}
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case bytes.Contains(doc, []byte("kind: ValidatingAdmissionPolicyBinding")):
			b := &admissionv1.ValidatingAdmissionPolicyBinding{}
			if err = yaml.UnmarshalStrict(doc, b); err == nil {
				if b.Spec.PolicyName != "blip-vm-owner" || b.Spec.ParamRef == nil || b.Spec.ParamRef.Name != VMOwnersConfigMap {
					t.Fatalf("binding %v", b)
				}
				for _, r := range b.Spec.MatchResources.ResourceRules {
					notFound[r.Resources[0]] = *b.Spec.ParamRef.ParameterNotFoundAction
				}
			}
		case bytes.Contains(doc, []byte("kind: ValidatingAdmissionPolicy")):
			policy = &admissionv1.ValidatingAdmissionPolicy{}
			err = yaml.UnmarshalStrict(doc, policy)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Fail secure for blip writes; pod exec elsewhere stays usable.
	if policy == nil || policy.Name != "blip-vm-owner" ||
		notFound["blips"] != admissionv1.DenyAction || notFound["pods/exec"] != admissionv1.AllowAction {
		t.Fatalf("policy %v bindings %v", policy, notFound)
	}

	env, err := plugincel.NewCompositionEnv(plugincel.VariablesTypeName, environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true))
	if err != nil {
		t.Fatal(err)
	}
	compiler := plugincel.NewCompositedCompilerFromTemplate(env)
	opts := plugincel.OptionalVariableDeclarations{HasParams: true, HasAuthorizer: true, StrictCost: true}
	var vars []plugincel.NamedExpressionAccessor
	for _, v := range policy.Spec.Variables {
		vars = append(vars, &validating.Variable{Name: v.Name, Expression: v.Expression})
	}
	compiler.CompileAndStoreVariables(vars, opts, environment.StoredExpressions)
	var match, checks, messages []plugincel.ExpressionAccessor
	for i := range policy.Spec.MatchConditions {
		match = append(match, (*matchconditions.MatchCondition)(&policy.Spec.MatchConditions[i]))
	}
	for _, v := range policy.Spec.Validations {
		checks = append(checks, &validating.ValidationCondition{Expression: v.Expression, Message: v.Message, Reason: v.Reason})
		messages = append(messages, &validating.MessageExpressionCondition{MessageExpression: v.MessageExpression})
	}
	msgOpts := opts
	msgOpts.HasAuthorizer = false
	return validating.NewValidator(
		compiler.CompileCondition(checks, opts, environment.StoredExpressions),
		matchconditions.NewMatcher(compiler.CompileCondition(match, opts, environment.StoredExpressions), policy.Spec.FailurePolicy, "policy", "validate", policy.Name),
		compiler.CompileCondition(nil, opts, environment.StoredExpressions),
		compiler.CompileCondition(messages, msgOpts, environment.StoredExpressions),
		policy.Spec.FailurePolicy,
	)
}

type policyRequest struct {
	user      user.Info
	op        admission.Operation
	resource  string // blips, blipstates, pods/exec
	name      string
	object    map[string]any
	oldObject map[string]any
	connect   runtime.Object // CONNECT options; default: a blip session exec
}

func vmUser(sa, pod string) user.Info {
	return &user.DefaultInfo{
		Name:  "system:serviceaccount:" + ns + ":" + sa,
		Extra: map[string][]string{"authentication.kubernetes.io/pod-name": {pod}},
	}
}

func blipObj(name, owner string, mutate ...func(spec map[string]any)) map[string]any {
	meta := map[string]any{"name": name, "namespace": ns}
	if owner != "" {
		meta["labels"] = map[string]any{LabelOwner: owner}
	}
	spec := map[string]any{"pool": "default"}
	for _, m := range mutate {
		m(spec)
	}
	return map[string]any{"apiVersion": "blip.dev/v1alpha1", "kind": "Blip", "metadata": meta, "spec": spec}
}

func stateObj(name, owner, copyFrom string) map[string]any {
	o := blipObj(name, owner)
	o["kind"] = "BlipState"
	o["spec"] = map[string]any{}
	if copyFrom != "" {
		o["spec"] = map[string]any{"copyFrom": copyFrom}
	}
	return o
}

// sessionExec is the exec internal/session opens for a blip session.
func sessionExec() *corev1.PodExecOptions {
	return &corev1.PodExecOptions{Stdin: true, Stdout: true, Container: session.Container, Command: []string{"blip-runtime", "bridge", strconv.Itoa(wire.SessionPort)}}
}

func (p policyRequest) evaluate(t *testing.T, v validating.Validator, params map[string]string) (bool, string) {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "blip.dev", Version: "v1alpha1", Resource: p.resource}
	gvk := schema.GroupVersionKind{Group: "blip.dev", Version: "v1alpha1", Kind: "Blip"}
	sub := ""
	if res, s, ok := strings.Cut(p.resource, "/"); ok {
		gvr = schema.GroupVersionResource{Version: "v1", Resource: res}
		gvk = schema.GroupVersionKind{Version: "v1", Kind: "PodExecOptions"}
		sub = s
	}
	if p.resource == "blipstates" {
		gvk.Kind = "BlipState"
	}
	var obj, old runtime.Object
	if p.object != nil {
		obj = &unstructured.Unstructured{Object: p.object}
	}
	if p.oldObject != nil {
		old = &unstructured.Unstructured{Object: p.oldObject}
	}
	if p.op == admission.Connect {
		// The API server admits CONNECT with the versioned options of the
		// subresource as the object.
		obj = p.connect
		if obj == nil {
			obj = sessionExec()
		}
		gvk.Kind = map[string]string{"exec": "PodExecOptions", "attach": "PodAttachOptions", "portforward": "PodPortForwardOptions"}[sub]
	}
	attrs := admission.NewAttributesRecord(obj, old, gvk, ns, p.name, gvr, sub, p.op, nil, false, p.user)
	versioned := &admission.VersionedAttributes{Attributes: attrs, VersionedKind: gvk, VersionedObject: obj, VersionedOldObject: old}
	cm := &corev1.ConfigMap{Data: params}
	cm.Name, cm.Namespace = VMOwnersConfigMap, ns
	res := v.Validate(context.Background(), gvr, versioned, cm, nil, 10_000_000, nil)
	for _, d := range res.Decisions {
		if d.Evaluation == validating.EvalError {
			t.Fatalf("evaluation error: %s", d.Message)
		}
		if d.Action == validating.ActionDeny {
			return false, d.Message
		}
	}
	return true, ""
}

func TestVMOwnerPolicy(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	const o, x = "u-0123456789abcdef0123456789abcdef", "u-fedcba9876543210fedcba9876543210"
	params := map[string]string{
		"sa.vm":         "default gpu",
		"sa.other":      "",
		"default-mine":  o,
		"default-other": x,
		"default-admin": "-",
	}
	mine, other, vacant, admin := vmUser("vm", "default-mine"), vmUser("vm", "default-other"), vmUser("vm", "default-vacant"), vmUser("vm", "default-admin")
	podsOnly := vmUser("other", "default-mine")
	withState := func(s string) func(map[string]any) { return func(spec map[string]any) { spec["state"] = s } }
	withMount := func(s string) func(map[string]any) {
		return func(spec map[string]any) { spec["mounts"] = []any{map[string]any{"state": s, "path": "/data"}} }
	}
	withPool := func(p string) func(map[string]any) { return func(spec map[string]any) { spec["pool"] = p } }
	withSecret := func(spec map[string]any) { spec["imagePullSecrets"] = []any{map[string]any{"name": "creds"}} }
	shell := &corev1.PodExecOptions{Container: "vm", Command: []string{"sh"}}
	bridgeIn := func(c string) *corev1.PodExecOptions { o := sessionExec(); o.Container = c; return o }
	stateWithSecret := stateObj(o+".s", o, "")
	stateWithSecret["spec"] = map[string]any{"image": "reg/img", "imagePullSecrets": []any{map[string]any{"name": "creds"}}}

	for _, tc := range []struct {
		name  string
		req   policyRequest
		allow bool
		msg   string
	}{
		{"non-VM service account", policyRequest{user: vmUser("ci", "ci-pod"), op: admission.Create, resource: "blips", name: "anything", object: blipObj("anything", "")}, true, ""},
		{"user without pod token", policyRequest{user: &user.DefaultInfo{Name: "alice"}, op: admission.Delete, resource: "blips", name: x + ".a", oldObject: blipObj(x+".a", x)}, true, ""},
		{"other namespace service account", policyRequest{user: &user.DefaultInfo{Name: "system:serviceaccount:other:vm", Extra: map[string][]string{"authentication.kubernetes.io/pod-name": {"p"}}}, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "")}, true, ""},
		{"vacant VM denied", policyRequest{user: vacant, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o)}, false, "not claimed"},
		{"unrestricted owner", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "", withState("b"))}, true, ""},
		{"unrestricted owner exec", policyRequest{user: admin, op: admission.Connect, resource: "pods/exec", name: "default-other"}, true, ""},
		{"own blip", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withState(o+".root"), withMount(o+".data"))}, true, ""},
		{"own blip update", policyRequest{user: mine, op: admission.Update, resource: "blips", name: o + ".a", object: blipObj(o+".a", o), oldObject: blipObj(o+".a", o)}, true, ""},
		{"own blip status", policyRequest{user: mine, op: admission.Update, resource: "blips/status", name: o + ".a", object: blipObj(o+".a", o), oldObject: blipObj(o+".a", o)}, false, "may not change status"},
		{"own state status", policyRequest{user: mine, op: admission.Update, resource: "blipstates/status", name: o + ".s", object: stateObj(o+".s", o, ""), oldObject: stateObj(o+".s", o, "")}, false, "may not change status"},
		{"own state", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, o+".base")}, true, ""},
		{"missing label", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", "")}, false, "must label"},
		{"wrong label", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", x)}, false, "must label"},
		{"wrong prefix", policyRequest{user: mine, op: admission.Create, resource: "blips", name: x + ".a", object: blipObj(x+".a", o)}, false, "named " + o + ".*"},
		{"no prefix", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o, object: stateObj(o, o, "")}, false, "named"},
		{"relabel other's", policyRequest{user: mine, op: admission.Update, resource: "blips", name: x + ".a", object: blipObj(x+".a", o), oldObject: blipObj(x+".a", x)}, false, "labelled"},
		{"root is other's state", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withState(x+".root"))}, false, "use states"},
		{"mount of other's state", policyRequest{user: mine, op: admission.Update, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withMount(x+".data")), oldObject: blipObj(o+".a", o)}, false, "use states"},
		{"copy other's state", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, x+".root")}, false, "copy states"},
		{"delete own", policyRequest{user: mine, op: admission.Delete, resource: "blipstates", name: o + ".s", oldObject: stateObj(o+".s", o, "")}, true, ""},
		{"delete other's", policyRequest{user: mine, op: admission.Delete, resource: "blips", name: x + ".a", oldObject: blipObj(x+".a", x)}, false, "delete"},
		{"relabel own name", policyRequest{user: mine, op: admission.Update, resource: "blips", name: o + ".a", object: blipObj(o+".a", o), oldObject: blipObj(o+".a", x)}, false, "change objects labelled"},
		{"delete own name labelled other", policyRequest{user: mine, op: admission.Delete, resource: "blipstates", name: o + ".s", oldObject: stateObj(o+".s", x, "")}, false, "change objects labelled"},
		{"own pool", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool("gpu"))}, true, ""},
		{"other account's pool", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool("private"))}, false, "pools of service account vm"},
		{"pool prefix is not a pool", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool("gp"))}, false, "pools"},
		{"account without pools", policyRequest{user: podsOnly, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o)}, false, "pools"},
		{"unrestricted any pool", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "", withPool("private"))}, true, ""},
		{"blip pull secrets", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withSecret)}, false, "imagePullSecrets"},
		{"state pull secrets", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateWithSecret}, false, "imagePullSecrets"},
		{"unrestricted pull secrets", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "", withSecret)}, true, ""},
		{"exec own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "default-mine"}, true, ""},
		{"shell in own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "default-mine", connect: shell}, false, "blip sessions"},
		{"bridge in other container", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "default-mine", connect: bridgeIn("sidecar")}, false, "blip sessions"},
		{"bridge in default container", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "default-mine", connect: bridgeIn("")}, false, "blip sessions"},
		{"unrestricted shell", policyRequest{user: admin, op: admission.Connect, resource: "pods/exec", name: "default-other", connect: shell}, false, "blip sessions"},
		{"attach own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/attach", name: "default-mine", connect: &corev1.PodAttachOptions{Container: "vm", Stdin: true}}, false, "blip sessions"},
		{"unrestricted port-forward", policyRequest{user: admin, op: admission.Connect, resource: "pods/portforward", name: "default-other", connect: &corev1.PodPortForwardOptions{Ports: []int32{22}}}, false, "blip sessions"},
		{"attach other's pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/attach", name: "default-other", connect: &corev1.PodAttachOptions{Container: "vm"}}, false, "blip sessions"},
		{"exec other's pod", policyRequest{user: other, op: admission.Connect, resource: "pods/exec", name: "default-mine"}, false, "connect"},
		{"exec unrestricted pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "default-admin"}, false, "connect"},
		{"exec non-VM pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "gateway"}, false, "connect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allow, msg := tc.req.evaluate(t, v, params)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}

	// A table without data (or without the caller's service account)
	// leaves the caller unrestricted.
	if ok, msg := (policyRequest{user: vacant, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "")}).evaluate(t, v, nil); !ok {
		t.Fatalf("empty table denied: %s", msg)
	}
}
