package controller

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"slices"
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

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
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

// readPolicyDocs parses every policy and binding document in path.
func readPolicyDocs(t *testing.T, path string) ([]*admissionv1.ValidatingAdmissionPolicy, []*admissionv1.ValidatingAdmissionPolicyBinding) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policies []*admissionv1.ValidatingAdmissionPolicy
	var bindings []*admissionv1.ValidatingAdmissionPolicyBinding
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
			if err = yaml.UnmarshalStrict(doc, b); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, b)
		case bytes.Contains(doc, []byte("kind: ValidatingAdmissionPolicy")):
			p := &admissionv1.ValidatingAdmissionPolicy{}
			if err = yaml.UnmarshalStrict(doc, p); err != nil {
				t.Fatal(err)
			}
			policies = append(policies, p)
		}
	}
	return policies, bindings
}

// loadPolicy compiles one policy from a multi-document policy file the way the
// API server's validating admission policy plugin does.
func loadPolicy(t *testing.T, file, name string) validating.Validator {
	t.Helper()
	policies, bindings := readPolicyDocs(t, file)
	policy := findPolicy(t, policies, name)
	var found int
	for _, b := range bindings {
		if b.Spec.PolicyName != name {
			continue
		}
		found++
		if len(b.Spec.ValidationActions) != 1 || b.Spec.ValidationActions[0] != admissionv1.Deny {
			t.Fatalf("policy %v binding actions %v", name, b.Spec.ValidationActions)
		}
	}
	if found != 1 {
		t.Fatalf("policy %v has %d bindings", name, found)
	}
	return compilePolicy(t, policy, false)
}

func findPolicy(t *testing.T, policies []*admissionv1.ValidatingAdmissionPolicy, name string) *admissionv1.ValidatingAdmissionPolicy {
	t.Helper()
	for _, p := range policies {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("policy %q not found", name)
	return nil
}

// compilePolicy compiles one policy the way the API server's validating
// admission policy plugin does.
func compilePolicy(t *testing.T, policy *admissionv1.ValidatingAdmissionPolicy, hasParams bool) validating.Validator {
	t.Helper()
	env, err := plugincel.NewCompositionEnv(plugincel.VariablesTypeName, environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true))
	if err != nil {
		t.Fatal(err)
	}
	compiler := plugincel.NewCompositedCompilerFromTemplate(env)
	opts := plugincel.OptionalVariableDeclarations{StrictCost: true, HasParams: hasParams}
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

// loadTurnPolicy compiles both policies in deploy/base/turn-policy.yaml: the
// author identity check and the project ownership check.
func loadTurnPolicy(t *testing.T) (validating.Validator, validating.Validator) {
	t.Helper()
	policies, bindings := readPolicyDocs(t, "../../deploy/base/turn-policy.yaml")
	author := findPolicy(t, policies, "blip-turn-author")
	owner := findPolicy(t, policies, "blip-turn-owner")
	byPolicy := map[string]*admissionv1.ValidatingAdmissionPolicyBinding{}
	for _, b := range bindings {
		byPolicy[b.Spec.PolicyName] = b
	}
	for _, name := range []string{"blip-turn-author", "blip-turn-owner"} {
		b := byPolicy[name]
		if b == nil || len(b.Spec.ValidationActions) != 1 || b.Spec.ValidationActions[0] != admissionv1.Deny {
			t.Fatalf("binding for %s = %v", name, b)
		}
	}
	if ref := byPolicy["blip-turn-owner"].Spec.ParamRef; ref == nil ||
		ref.Name != VMOwnersConfigMap || ref.ParameterNotFoundAction == nil ||
		*ref.ParameterNotFoundAction != admissionv1.AllowAction {
		t.Fatalf("turn owner binding params = %v", byPolicy["blip-turn-owner"].Spec.ParamRef)
	}
	return compilePolicy(t, author, false), compilePolicy(t, owner, true)
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
		meta["labels"] = map[string]any{v1.LabelOwner: owner}
	}
	spec := map[string]any{"pool": "default", "state": name + ".root"}
	for _, m := range mutate {
		m(spec)
	}
	return map[string]any{"apiVersion": "blip.dev/v1alpha1", "kind": "Blip", "metadata": meta, "spec": spec}
}

func stateObj(name, owner, copyFrom string, mutate ...func(map[string]any)) map[string]any {
	o := blipObj(name, owner)
	o["kind"] = "BlipState"
	o["spec"] = map[string]any{}
	if copyFrom != "" {
		o["spec"] = map[string]any{"copyFrom": copyFrom}
	}
	for _, m := range mutate {
		m(o["spec"].(map[string]any))
	}
	return o
}

func threadObj(name, charter string) map[string]any {
	return map[string]any{
		"apiVersion": "blip.dev/v1alpha1",
		"kind":       "BlipThread",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec":       map[string]any{"pool": "default", "charter": charter},
	}
}

// sessionExec is the exec internal/session opens for a blip session.
func sessionExec() *corev1.PodExecOptions {
	return &corev1.PodExecOptions{Stdin: true, Stdout: true, Container: podapi.VMContainer, Command: []string{"blip-runtime", "bridge", strconv.Itoa(wire.SessionPort)}}
}

func (p policyRequest) evaluate(t *testing.T, v validating.Validator, params map[string]string) (bool, string) {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "blip.dev", Version: "v1alpha1", Resource: p.resource}
	gvk := schema.GroupVersionKind{Group: "blip.dev", Version: "v1alpha1", Kind: "Blip"}
	sub := ""
	if res, s, ok := strings.Cut(p.resource, "/"); ok {
		if res == "blipturns" {
			gvr = schema.GroupVersionResource{Group: "blip.dev", Version: "v1alpha1", Resource: res}
			gvk = schema.GroupVersionKind{Group: "blip.dev", Version: "v1alpha1", Kind: "BlipTurn"}
		} else {
			gvr = schema.GroupVersionResource{Version: "v1", Resource: res}
			gvk = schema.GroupVersionKind{Version: "v1", Kind: "PodExecOptions"}
		}
		sub = s
	}
	if p.resource == "blipstates" {
		gvk.Kind = "BlipState"
	}
	if strings.HasPrefix(p.resource, "blipturns") {
		gvk.Kind = "BlipTurn"
	}
	if p.resource == "blipthreads" {
		gvk.Kind = "BlipThread"
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
		gvk.Kind = map[string]string{"exec": "PodExecOptions", "attach": "PodAttachOptions", "portforward": "PodPortForwardOptions", "proxy": "PodProxyOptions"}[sub]
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

func TestVMOwnerPolicyRetiredBase(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	const owner = "u-0123456789abcdef0123456789abcdef"
	params := map[string]string{"sa.vm": "default", "default-mine": owner, "bases": "base-dev"}
	original := stateObj(owner+".root", owner, "base-dev")
	req := policyRequest{user: vmUser("vm", "default-mine"), op: admission.Create, resource: "blipstates", name: owner + ".root", object: original}
	if allow, msg := req.evaluate(t, v, params); !allow {
		t.Fatalf("copy shared base: %s", msg)
	}
	delete(params, "bases")
	if allow, _ := req.evaluate(t, v, params); allow {
		t.Fatal("new copy allowed after base was retired")
	}
	// copyFrom is immutable provisioning history. Retiring the source must not
	// prevent its independent copies from changing their durable configuration.
	req.op = admission.Update
	req.oldObject = original
	req.object = stateObj(owner+".root", owner, "base-dev", func(spec map[string]any) {
		spec["runtime"] = map[string]any{"workingDir": "/work"}
		spec["mounts"] = []any{map[string]any{"state": owner + ".data", "path": "/work", "writable": true}}
	})
	if allow, msg := req.evaluate(t, v, params); !allow {
		t.Fatalf("edit workspace after base retired: %s", msg)
	}
}

func TestVMOwnerPolicy(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	const o, x = "u-0123456789abcdef0123456789abcdef", "u-fedcba9876543210fedcba9876543210"
	params := map[string]string{
		"bases":         "base-dev base-tools",
		"sa.vm":         "default gpu",
		"sa.other":      "",
		"default-mine":  o,
		"default-other": x,
		"default-admin": "-",
	}
	mine, other, vacant, admin := vmUser("vm", "default-mine"), vmUser("vm", "default-other"), vmUser("vm", "default-vacant"), vmUser("vm", "default-admin")
	podsOnly := vmUser("other", "default-mine")
	withState := func(s string) func(map[string]any) { return func(spec map[string]any) { spec["state"] = s } }
	withMount := func(s string, writable bool) func(map[string]any) {
		return func(spec map[string]any) {
			spec["mounts"] = []any{map[string]any{"state": s, "path": "/data", "writable": writable}}
		}
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
		{"own blip", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withState(o+".root"))}, true, ""},
		{"own blip update", policyRequest{user: mine, op: admission.Update, resource: "blips", name: o + ".a", object: blipObj(o+".a", o), oldObject: blipObj(o+".a", o)}, true, ""},
		{"own blip status", policyRequest{user: mine, op: admission.Update, resource: "blips/status", name: o + ".a", object: blipObj(o+".a", o), oldObject: blipObj(o+".a", o)}, false, "may not change status"},
		{"own state status", policyRequest{user: mine, op: admission.Update, resource: "blipstates/status", name: o + ".s", object: stateObj(o+".s", o, ""), oldObject: stateObj(o+".s", o, "")}, false, "may not change status"},
		{"restricted creates thread", policyRequest{user: mine, op: admission.Create, resource: "blipthreads", name: "proj", object: threadObj("proj", "mine")}, false, "thread specs"},
		{"restricted updates thread", policyRequest{user: mine, op: admission.Update, resource: "blipthreads", name: "victim", object: threadObj("victim", "pwned"), oldObject: threadObj("victim", "original")}, false, "thread specs"},
		{"restricted deletes thread", policyRequest{user: mine, op: admission.Delete, resource: "blipthreads", name: "victim", oldObject: threadObj("victim", "original")}, false, "thread specs"},
		{"unrestricted updates thread", policyRequest{user: admin, op: admission.Update, resource: "blipthreads", name: "proj", object: threadObj("proj", "new"), oldObject: threadObj("proj", "old")}, true, ""},
		{"own state", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, o+".base")}, true, ""},
		{"missing label", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", "")}, false, "must label"},
		{"wrong label", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", x)}, false, "must label"},
		{"wrong prefix", policyRequest{user: mine, op: admission.Create, resource: "blips", name: x + ".a", object: blipObj(x+".a", o)}, false, "named " + o + ".*"},
		{"no prefix", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o, object: stateObj(o, o, "")}, false, "named"},
		{"relabel other's", policyRequest{user: mine, op: admission.Update, resource: "blips", name: x + ".a", object: blipObj(x+".a", o), oldObject: blipObj(x+".a", x)}, false, "labelled"},
		{"root is other's state", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withState(x+".root"))}, false, "use states"},
		{"mount own state", policyRequest{user: mine, op: admission.Update, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "", withMount(o+".data", true)), oldObject: stateObj(o+".s", o, "")}, true, ""},
		{"mount of other's state", policyRequest{user: mine, op: admission.Update, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "", withMount(x+".data", false)), oldObject: stateObj(o+".s", o, "")}, false, "may only mount"},
		{"mount shared base read-only", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "", withMount("base-tools", false))}, true, ""},
		{"mount shared base writable", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "", withMount("base-tools", true))}, false, "may only mount"},
		{"copy shared base", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "base-dev")}, true, ""},
		{"copy base name prefix", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "base")}, false, "copy states"},
		{"copy unlisted base", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, "base-private")}, false, "copy states"},
		{"use shared base as root", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withState("base-dev"))}, false, "use states"},
		{"copy other's state", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateObj(o+".s", o, x+".root")}, false, "copy states"},
		{"delete own", policyRequest{user: mine, op: admission.Delete, resource: "blipstates", name: o + ".s", oldObject: stateObj(o+".s", o, "")}, true, ""},
		{"delete other's", policyRequest{user: mine, op: admission.Delete, resource: "blips", name: x + ".a", oldObject: blipObj(x+".a", x)}, false, "delete"},
		{"relabel own name", policyRequest{user: mine, op: admission.Update, resource: "blips", name: o + ".a", object: blipObj(o+".a", o), oldObject: blipObj(o+".a", x)}, false, "change objects labelled"},
		{"delete own name labelled other", policyRequest{user: mine, op: admission.Delete, resource: "blipstates", name: o + ".s", oldObject: stateObj(o+".s", x, "")}, false, "change objects labelled"},
		{"own pool", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool("gpu"))}, true, ""},
		{"empty pool means default", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool(""))}, true, ""},
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
		{"proxy to own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/proxy", name: "default-mine", connect: &corev1.PodProxyOptions{Path: "/"}}, false, "blip sessions"},
		{"unrestricted proxy", policyRequest{user: admin, op: admission.Connect, resource: "pods/proxy", name: "default-other", connect: &corev1.PodProxyOptions{Path: "/"}}, false, "blip sessions"},
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

	// An existing table is authoritative for a claimed pod even without the
	// caller's service-account key, and an empty table denies creates rather
	// than allowing them. A missing table remains Allow for UPDATE/DELETE
	// (terminating namespaces) and Deny for CREATE through the binding below.
	noKey := map[string]string{"default-mine": o}
	create := policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o)}
	if ok, msg := create.evaluate(t, v, noKey); ok {
		t.Fatalf("create allowed without the caller's service-account key: %s", msg)
	}
	if ok, msg := (policyRequest{user: vacant, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "")}).evaluate(t, v, nil); ok {
		t.Fatalf("empty table allowed a create: %s", msg)
	}
}

// withThreadLabel sets (or clears, when thread is empty) the blip.dev/thread
// label on an object built by blipObj/stateObj.
func withThreadLabel(o map[string]any, thread string) map[string]any {
	meta := o["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
		meta["labels"] = labels
	}
	if thread == "" {
		delete(labels, v1.LabelThread)
		return o
	}
	labels[v1.LabelThread] = thread
	return o
}

// A restricted VM may attach its Blip only to a thread of its own project.
// The thread owner is the blip-vm-owners "thread.<name>" entry, so a forged
// blip.dev/thread label cannot steer blipchat turns into another project.
func TestVMOwnerPolicyThreadLabel(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	project := v1.ThreadOwner(ns, "proj")
	victim := v1.ThreadOwner(ns, "victim")
	params := map[string]string{
		"sa.vm":         "default",
		"default-mine":  project,
		"default-user":  "u-0123456789abcdef0123456789abcdef",
		"default-admin": "-",
		"thread.proj":   project,
		"thread.victim": victim,
	}
	mine, userVM, admin := vmUser("vm", "default-mine"), vmUser("vm", "default-user"), vmUser("vm", "default-admin")
	own := withThreadLabel(blipObj(project+".a", project), "proj")
	noThread := blipObj(project+".a", project)
	foreign := withThreadLabel(blipObj(project+".a", project), "victim")
	unknown := withThreadLabel(blipObj(project+".a", project), "missing")

	for _, tc := range []struct {
		name  string
		req   policyRequest
		allow bool
		msg   string
	}{
		{"own thread", policyRequest{user: mine, op: admission.Create, resource: "blips", name: project + ".a", object: own}, true, ""},
		{"no thread", policyRequest{user: mine, op: admission.Create, resource: "blips", name: project + ".a", object: noThread}, true, ""},
		{"foreign thread", policyRequest{user: mine, op: admission.Create, resource: "blips", name: project + ".a", object: foreign}, false, "thread"},
		{"unknown thread", policyRequest{user: mine, op: admission.Create, resource: "blips", name: project + ".a", object: unknown}, false, "thread"},
		{"user-owned VM foreign thread", policyRequest{user: userVM, op: admission.Create, resource: "blips", name: "u-0123456789abcdef0123456789abcdef.a",
			object: withThreadLabel(blipObj("u-0123456789abcdef0123456789abcdef.a", "u-0123456789abcdef0123456789abcdef"), "proj")}, false, "thread"},
		{"keep own thread", policyRequest{user: mine, op: admission.Update, resource: "blips", name: project + ".a", object: own, oldObject: own}, true, ""},
		{"add foreign thread", policyRequest{user: mine, op: admission.Update, resource: "blips", name: project + ".a", object: foreign, oldObject: noThread}, false, "thread"},
		{"change to foreign thread", policyRequest{user: mine, op: admission.Update, resource: "blips", name: project + ".a", object: foreign, oldObject: own}, false, "thread"},
		{"remove own thread", policyRequest{user: mine, op: admission.Update, resource: "blips", name: project + ".a", object: noThread, oldObject: own}, false, "thread"},
		{"unrestricted foreign thread", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: withThreadLabel(blipObj("a", ""), "victim")}, true, ""},
		{"non-VM foreign thread", policyRequest{user: &user.DefaultInfo{Name: "alice"}, op: admission.Create, resource: "blips", name: "a", object: withThreadLabel(blipObj("a", ""), "victim")}, true, ""},
		{"state thread label is not a blip", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: project + ".s",
			object: withThreadLabel(stateObj(project+".s", project, ""), "victim")}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allow, msg := tc.req.evaluate(t, v, params)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

func ownerReference(name string, mutate ...func(map[string]any)) map[string]any {
	ref := map[string]any{"apiVersion": "blip.dev/v1alpha1", "kind": "Blip", "name": name, "uid": "uid-parent"}
	for _, m := range mutate {
		m(ref)
	}
	return ref
}

func withOwnerReferences(o map[string]any, refs ...map[string]any) map[string]any {
	o["metadata"].(map[string]any)["ownerReferences"] = refs
	return o
}

func TestVMOwnerPolicyOwnerReferences(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	const o, x = "u-0123456789abcdef0123456789abcdef", "u-fedcba9876543210fedcba9876543210"
	params := map[string]string{"sa.vm": "default gpu", "default-mine": o, "default-admin": "-"}
	mine, admin := vmUser("vm", "default-mine"), vmUser("vm", "default-admin")
	set := func(key string, value any) func(map[string]any) {
		return func(ref map[string]any) { ref[key] = value }
	}

	for _, tc := range []struct {
		name  string
		req   policyRequest
		allow bool
		msg   string
	}{
		{"fork blip of own blip", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(o+".parent"))}, true, ""},
		{"state of own blip", policyRequest{user: mine, op: admission.Create, resource: "blipstates",
			name: o + ".s", object: withOwnerReferences(stateObj(o+".s", o, ""), ownerReference(o+".fork"))}, true, ""},
		{"no ownerReferences", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".a", object: blipObj(o+".a", o)}, true, ""},
		{"other owner's blip", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(x+".parent"))}, false, "ownerReferences"},
		{"wrong apiVersion", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(o+".parent", set("apiVersion", "v1")))}, false, "ownerReferences"},
		{"wrong kind", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(o+".parent", set("kind", "Pod")))}, false, "ownerReferences"},
		{"controller owner", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(o+".parent", set("controller", true)))}, false, "ownerReferences"},
		{"blocking deletion", policyRequest{user: mine, op: admission.Create, resource: "blipstates",
			name: o + ".s", object: withOwnerReferences(stateObj(o+".s", o, ""), ownerReference(o+".fork", set("blockOwnerDeletion", true)))}, false, "ownerReferences"},
		{"unrestricted foreign owner", policyRequest{user: admin, op: admission.Create, resource: "blips",
			name: "a", object: withOwnerReferences(blipObj("a", ""), ownerReference(x+".parent"))}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allow, msg := tc.req.evaluate(t, v, params)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

func turnObj(authorKind, authorName string) map[string]any {
	return turnFor("project", authorKind, authorName)
}

func turnFor(thread, authorKind, authorName string) map[string]any {
	return namedTurn("turn", thread, authorKind, authorName)
}

func namedTurn(name, thread, authorKind, authorName string) map[string]any {
	return map[string]any{
		"apiVersion": "blip.dev/v1alpha1",
		"kind":       "BlipTurn",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"thread": thread,
			"author": map[string]any{"kind": authorKind, "name": authorName},
		},
	}
}

// Only blipchat (the sequencer) may write turn status, so a stray status
// credential cannot forge or reorder a turn's sequence number.
func TestTurnStatusPolicy(t *testing.T) {
	v := loadPolicy(t, "../../deploy/base/turn-policy.yaml", "blip-turn-status")
	status := func(seq any) map[string]any {
		obj := turnObj("User", "alice")
		obj["status"] = map[string]any{"seq": seq}
		return obj
	}
	blipchat := &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blipchat"}
	other := &user.DefaultInfo{Name: "system:serviceaccount:hunt-p6-chat:blip-agent"}

	for _, tc := range []struct {
		name  string
		user  user.Info
		op    admission.Operation
		obj   map[string]any
		old   map[string]any
		allow bool
		msg   string
	}{
		{"blipchat writes turn status", blipchat, admission.Update, status(int64(1)), status(nil), true, ""},
		{"blipchat updates turn status again", blipchat, admission.Update, status(int64(2)), status(int64(1)), true, ""},
		{"producer cannot set seq", other, admission.Update, status(int64(4242)), status(nil), false, "only blipchat"},
		{"producer cannot change seq", other, admission.Update, status(int64(4242)), status(int64(1)), false, "only blipchat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{user: tc.user, op: tc.op, resource: "blipturns/status", name: "turn", object: tc.obj, oldObject: tc.old}
			allow, msg := req.evaluate(t, v, nil)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

func TestTurnAuthorPolicy(t *testing.T) {
	v, _ := loadTurnPolicy(t)
	const blipchat = "system:serviceaccount:blip-system:blipchat"
	other := func(sa string) user.Info {
		return &user.DefaultInfo{Name: "system:serviceaccount:hunt-p6-chat:" + sa}
	}

	ci := "system:serviceaccount:hunt-p6-chat:ci"
	for _, tc := range []struct {
		name  string
		user  user.Info
		op    admission.Operation
		obj   map[string]any
		old   map[string]any
		allow bool
		msg   string
	}{
		{"blipchat authors a user turn", &user.DefaultInfo{Name: blipchat}, admission.Create, turnObj("User", "ceo@example.com"), nil, true, ""},
		{"blipchat authors a system turn", &user.DefaultInfo{Name: blipchat}, admission.Create, turnObj("System", "blipchat"), nil, true, ""},
		{"blipchat may use a watcher name", &user.DefaultInfo{Name: blipchat}, admission.Create, namedTurn("blip-uid-fin", "project", "Blip", "blip-a"), nil, true, ""},
		{"foreign blipchat cannot impersonate a user", other("blipchat"), admission.Create, turnObj("User", "ceo@example.com"), nil, false, "must set author.kind=ServiceAccount"},
		{"foreign blipchat cannot impersonate a service account", other("blipchat"), admission.Create, turnObj("ServiceAccount", "system:serviceaccount:blip-system:blipchat"), nil, false, "must set author.kind=ServiceAccount"},
		{"lookalike blipchat cannot impersonate a user", &user.DefaultInfo{Name: blipchat + "2"}, admission.Create, turnObj("User", "ceo@example.com"), nil, false, "must set author.kind=ServiceAccount"},
		{"other service account names itself", other("ci"), admission.Create, turnObj("ServiceAccount", ci), nil, true, ""},
		{"other service account may use its own name", other("ci"), admission.Create, namedTurn("ci-turn", "project", "ServiceAccount", ci), nil, true, ""},
		{"other service account cannot impersonate a user", other("ci"), admission.Create, turnObj("User", "ceo@example.com"), nil, false, "must set author.kind=ServiceAccount"},
		{"other service account cannot impersonate another account", other("ci"), admission.Create, turnObj("ServiceAccount", blipchat), nil, false, "must set author.kind=ServiceAccount"},
		{"plain user cannot author a turn", &user.DefaultInfo{Name: "alice"}, admission.Create, turnObj("User", "alice"), nil, false, "must set author.kind=ServiceAccount"},
		{"service account cannot squat a report turn", other("ci"), admission.Create, namedTurn("blip-uid-r1", "project", "ServiceAccount", ci), nil, false, "reserved"},
		{"service account cannot squat a finish turn", other("ci"), admission.Create, namedTurn("blip-uid-fin", "project", "ServiceAccount", ci), nil, false, "reserved"},
		{"service account cannot squat a coordinator turn", other("ci"), admission.Create, namedTurn("coord-p-uid-1-0", "project", "ServiceAccount", ci), nil, false, "reserved"},
		{"pod-bound producer cannot delete a turn", vmUser("vm", "default-mine"), admission.Delete, nil, turnObj("ServiceAccount", ci), false, "immutable history"},
		{"pod-bound producer cannot relabel a turn", vmUser("vm", "default-mine"), admission.Update, turnObj("ServiceAccount", ci), turnObj("ServiceAccount", ci), false, "immutable history"},
		{"blipchat may delete a turn", &user.DefaultInfo{Name: blipchat}, admission.Delete, nil, turnObj("User", "ceo@example.com"), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{user: tc.user, op: tc.op, resource: "blipturns", name: "turn", object: tc.obj, oldObject: tc.old}
			allow, msg := req.evaluate(t, v, nil)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

// TestTurnOwnerPolicy guards the project binding for pod-bound turn
// producers: a VM may only write to the thread whose derived owner owns it.
func TestTurnOwnerPolicy(t *testing.T) {
	_, v := loadTurnPolicy(t)
	const blipchat = "system:serviceaccount:blip-system:blipchat"
	self := "system:serviceaccount:" + ns + ":vm"
	project := v1.ThreadOwner(ns, "proj")
	victim := v1.ThreadOwner(ns, "victim")
	params := map[string]string{
		"sa.vm":         "default",
		"vm-pod":        project,
		"admin-pod":     "-",
		"thread.proj":   project,
		"thread.victim": victim,
	}

	for _, tc := range []struct {
		name  string
		user  user.Info
		obj   map[string]any
		allow bool
		msg   string
	}{
		{"own project", vmUser("vm", "vm-pod"), turnFor("proj", "ServiceAccount", self), true, ""},
		{"other project", vmUser("vm", "vm-pod"), turnFor("victim", "ServiceAccount", self), false, "does not own thread"},
		{"unknown thread", vmUser("vm", "vm-pod"), turnFor("missing", "ServiceAccount", self), false, "no recorded owner"},
		{"unclaimed pod", vmUser("vm", "vacant"), turnFor("proj", "ServiceAccount", self), false, "may only author"},
		{"unrestricted VM", vmUser("vm", "admin-pod"), turnFor("victim", "ServiceAccount", self), true, ""},
		{"non-pod producer is left to the author policy", &user.DefaultInfo{Name: blipchat}, turnFor("victim", "User", "ceo@example.com"), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{user: tc.user, op: admission.Create, resource: "blipturns", name: "turn", object: tc.obj}
			allow, msg := req.evaluate(t, v, params)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

// The policy rules and every binding that covers them must agree. A resource
// present in the policy but missing from the binding is silently unrestricted,
// and a CONNECT subresource present in only one place is a hole.
func TestVMOwnerPolicyBindingCoverage(t *testing.T) {
	policies, bindings := readPolicyDocs(t, "../../deploy/base/vm-owner-policy.yaml")
	policy := findPolicy(t, policies, "blip-vm-owner")
	hasResource := func(rules []admissionv1.NamedRuleWithOperations, resource string, op admissionv1.OperationType) bool {
		for _, r := range rules {
			if !slices.Contains(r.Operations, op) {
				continue
			}
			if slices.Contains(r.Resources, resource) {
				return true
			}
		}
		return false
	}
	has := func(rules []admissionv1.NamedRuleWithOperations, resource string) bool {
		return hasResource(rules, resource, admissionv1.Create) ||
			hasResource(rules, resource, admissionv1.Update)
	}
	for _, resource := range []string{"blipthreads", "blipthreads/status"} {
		if !has(policy.Spec.MatchConstraints.ResourceRules, resource) {
			t.Errorf("policy does not cover %s", resource)
		}
	}
	if !hasResource(policy.Spec.MatchConstraints.ResourceRules, "pods/proxy", admissionv1.Connect) {
		t.Error("policy does not cover pods/proxy CONNECT")
	}
	for _, b := range bindings {
		if b.Spec.MatchResources == nil {
			continue
		}
		rules := b.Spec.MatchResources.ResourceRules
		if has(rules, "pods/exec") && !hasResource(rules, "pods/proxy", admissionv1.Connect) {
			t.Errorf("binding %s covers exec but not proxy", b.Name)
		}
		if (has(rules, "blips") || has(rules, "blipstates")) && !has(rules, "blipthreads") {
			t.Errorf("binding %s covers blips/states but not threads", b.Name)
		}
	}
}
