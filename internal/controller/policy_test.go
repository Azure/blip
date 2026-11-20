// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"slices"
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

	return compilePolicy(t, policy)
}

// compilePolicy compiles one policy the way the API server's validating
// admission policy plugin does.
func compilePolicy(t *testing.T, policy *admissionv1.ValidatingAdmissionPolicy) validating.Validator {
	t.Helper()
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

func loadChatPolicy(t *testing.T, name string) validating.Validator {
	t.Helper()
	policies, bindings := readPolicyDocs(t, "../../deploy/base/chat-agent-policy.yaml")
	policy := findPolicy(t, policies, name)
	var binding *admissionv1.ValidatingAdmissionPolicyBinding
	for _, b := range bindings {
		if b.Spec.PolicyName == name {
			binding = b
			break
		}
	}
	if binding == nil || binding.Spec.ParamRef == nil ||
		binding.Spec.ParamRef.Name != "blip-chat-policy" ||
		binding.Spec.ParamRef.Namespace != "blip-system" ||
		binding.Spec.ParamRef.ParameterNotFoundAction == nil ||
		*binding.Spec.ParamRef.ParameterNotFoundAction != admissionv1.DenyAction ||
		len(binding.Spec.ValidationActions) != 1 ||
		binding.Spec.ValidationActions[0] != admissionv1.Deny {
		t.Fatalf("binding %v", binding)
	}
	return compilePolicy(t, policy)
}

func readChatPolicyConfig(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/base/chat-agent-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(doc, []byte("kind: ConfigMap")) {
			continue
		}
		var cm corev1.ConfigMap
		if err := yaml.UnmarshalStrict(doc, &cm); err != nil {
			t.Fatal(err)
		}
		if cm.Name != "blip-chat-policy" || cm.Namespace != "blip-system" {
			t.Fatalf("policy ConfigMap %s/%s", cm.Namespace, cm.Name)
		}
		return cm.Data
	}
	t.Fatal("policy ConfigMap not found")
	return nil
}

type policyRequest struct {
	user       user.Info
	op         admission.Operation
	resource   string // blips, blipstates, pods/exec
	name       string
	object     map[string]any
	oldObject  map[string]any
	connect    runtime.Object // CONNECT options; default: an exec shell
	paramsName string
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
			obj = &corev1.PodExecOptions{Stdin: true, Stdout: true, Container: "vm", Command: []string{"sh"}}
		}
		gvk.Kind = map[string]string{"exec": "PodExecOptions", "attach": "PodAttachOptions", "portforward": "PodPortForwardOptions", "proxy": "PodProxyOptions"}[sub]
	}
	attrs := admission.NewAttributesRecord(obj, old, gvk, ns, p.name, gvr, sub, p.op, nil, false, p.user)
	versioned := &admission.VersionedAttributes{Attributes: attrs, VersionedKind: gvk, VersionedObject: obj, VersionedOldObject: old}
	cm := &corev1.ConfigMap{Data: params}
	cm.Name, cm.Namespace = VMOwnersConfigMap, ns
	if p.paramsName != "" {
		cm.Name = p.paramsName
	}
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
		"bases":                "base-dev base-tools",
		"sa.vm":                "default gpu",
		"sa.other":             "",
		"default-mine":         o,
		"default-other":        x,
		"default-admin":        "-",
		"default-chat":         chatEntryPrefix + o,
		"default-chat-unowned": chatEntryPrefix + chatUnowned,
	}
	mine, other, vacant, admin := vmUser("vm", "default-mine"), vmUser("vm", "default-other"), vmUser("vm", "default-vacant"), vmUser("vm", "default-admin")
	chat, chatUnowned := vmUser("vm", "default-chat"), vmUser("vm", "default-chat-unowned")
	podsOnly := vmUser("other", "default-mine")
	withState := func(s string) func(map[string]any) { return func(spec map[string]any) { spec["state"] = s } }
	withMount := func(s string, writable bool) func(map[string]any) {
		return func(spec map[string]any) {
			spec["mounts"] = []any{map[string]any{"state": s, "path": "/data", "writable": writable}}
		}
	}
	withPool := func(p string) func(map[string]any) { return func(spec map[string]any) { spec["pool"] = p } }
	withSecret := func(spec map[string]any) { spec["imagePullSecrets"] = []any{map[string]any{"name": "creds"}} }
	stateWithSecret := stateObj(o+".s", o, "")
	stateWithSecret["spec"] = map[string]any{"image": "reg/img", "imagePullSecrets": []any{map[string]any{"name": "creds"}}}
	// Chat VMs are claimed, so they pass the owner checks; the chat entry
	// instead denies every write, including writes of their own objects.
	const chatDenied = "chat agents may not modify blips or blipstates; use the agent tools"
	chatBlip := blipObj(o+".a", o)
	chatState := stateObj(o+".s", o, "")

	for _, tc := range []struct {
		name  string
		req   policyRequest
		allow bool
		msg   string
	}{
		{"same-namespace pod without an owner entry", policyRequest{user: vmUser("ci", "ci-pod"), op: admission.Create, resource: "blips", name: "anything", object: blipObj("anything", "")}, false, "not claimed"},
		{"user without pod token", policyRequest{user: &user.DefaultInfo{Name: "alice"}, op: admission.Delete, resource: "blips", name: x + ".a", oldObject: blipObj(x+".a", x)}, true, ""},
		{"controller without a pod token", policyRequest{user: &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blip-controller"}, op: admission.Create, resource: "blips", name: "anything", object: blipObj("anything", "")}, true, ""},
		{"other namespace service account", policyRequest{user: &user.DefaultInfo{Name: "system:serviceaccount:other:vm", Extra: map[string][]string{"authentication.kubernetes.io/pod-name": {"p"}}}, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "")}, true, ""},
		{"vacant VM denied", policyRequest{user: vacant, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o)}, false, "not claimed"},
		{"unrestricted owner", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "", withState("b"))}, true, ""},
		{"non-VM user exec", policyRequest{user: &user.DefaultInfo{Name: "alice"}, op: admission.Connect, resource: "pods/exec", name: "default-other"}, true, ""},
		{"unrestricted owner exec", policyRequest{user: admin, op: admission.Connect, resource: "pods/exec", name: "default-other"}, false, "may not connect"},
		{"own blip", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withState(o+".root"))}, true, ""},
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
		{"chat creates own blip", policyRequest{user: chat, op: admission.Create, resource: "blips", name: o + ".a", object: chatBlip}, false, chatDenied},
		{"chat updates own blip", policyRequest{user: chat, op: admission.Update, resource: "blips", name: o + ".a", object: chatBlip, oldObject: chatBlip}, false, chatDenied},
		{"chat deletes own blip", policyRequest{user: chat, op: admission.Delete, resource: "blips", name: o + ".a", oldObject: chatBlip}, false, chatDenied},
		{"chat blip status", policyRequest{user: chat, op: admission.Update, resource: "blips/status", name: o + ".a", object: chatBlip, oldObject: chatBlip}, false, chatDenied},
		{"chat creates own state", policyRequest{user: chat, op: admission.Create, resource: "blipstates", name: o + ".s", object: chatState}, false, chatDenied},
		{"chat updates own state", policyRequest{user: chat, op: admission.Update, resource: "blipstates", name: o + ".s", object: chatState, oldObject: chatState}, false, chatDenied},
		{"chat deletes own state", policyRequest{user: chat, op: admission.Delete, resource: "blipstates", name: o + ".s", oldObject: chatState}, false, chatDenied},
		{"chat state status", policyRequest{user: chat, op: admission.Update, resource: "blipstates/status", name: o + ".s", object: chatState, oldObject: chatState}, false, chatDenied},
		{"unowned chat creates blip", policyRequest{user: chatUnowned, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "")}, false, chatDenied},
		{"empty pool means default", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool(""))}, true, ""},
		{"other account's pool", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool("private"))}, false, "pools of service account vm"},
		{"pool prefix is not a pool", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withPool("gp"))}, false, "pools"},
		{"account without pools", policyRequest{user: podsOnly, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o)}, false, "pools"},
		{"unrestricted any pool", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "", withPool("private"))}, true, ""},
		{"blip pull secrets", policyRequest{user: mine, op: admission.Create, resource: "blips", name: o + ".a", object: blipObj(o+".a", o, withSecret)}, false, "imagePullSecrets"},
		{"state pull secrets", policyRequest{user: mine, op: admission.Create, resource: "blipstates", name: o + ".s", object: stateWithSecret}, false, "imagePullSecrets"},
		{"unrestricted pull secrets", policyRequest{user: admin, op: admission.Create, resource: "blips", name: "a", object: blipObj("a", "", withSecret)}, true, ""},
		{"exec own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "default-mine"}, false, "may not connect"},
		{"exec other's pod", policyRequest{user: other, op: admission.Connect, resource: "pods/exec", name: "default-mine"}, false, "may not connect"},
		{"exec non-VM pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/exec", name: "gateway"}, false, "may not connect"},
		{"attach own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/attach", name: "default-mine", connect: &corev1.PodAttachOptions{Container: "vm", Stdin: true}}, false, "may not connect"},
		{"port-forward own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/portforward", name: "default-mine", connect: &corev1.PodPortForwardOptions{Ports: []int32{22}}}, false, "may not connect"},
		{"proxy to own pod", policyRequest{user: mine, op: admission.Connect, resource: "pods/proxy", name: "default-mine", connect: &corev1.PodProxyOptions{Path: "/"}}, false, "may not connect"},
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

	// A non-empty table that lacks the caller's service-account and pod keys
	// must fail closed rather than skipping every owner check.
	partial := map[string]string{"bases": "base", "sa.other": ""}
	if ok, msg := (policyRequest{user: vmUser("vm", "vacant-pod"), op: admission.Create, resource: "blips",
		name: "a", object: blipObj("a", "")}).evaluate(t, v, partial); ok {
		t.Fatalf("partial table allowed a pod-bound create: %s", msg)
	}
	noPod := map[string]string{"sa.vm": "default", "sa.other": ""}
	if ok, msg := (policyRequest{user: vmUser("vm", "vacant-pod"), op: admission.Create, resource: "blips",
		name: o + ".a", object: blipObj(o+".a", o)}).evaluate(t, v, noPod); ok {
		t.Fatalf("table without the caller's pod entry allowed a create: %s", msg)
	}
	// A valid claimed pod still works, including its pools.
	claimed := map[string]string{"sa.vm": "default", "default-mine": o}
	if ok, msg := (policyRequest{user: mine, op: admission.Create, resource: "blips",
		name: o + ".a", object: blipObj(o+".a", o)}).evaluate(t, v, claimed); !ok {
		t.Fatalf("valid claimed pod was denied: %s", msg)
	}
}

// withLabels adds labels to an object built by blipObj/stateObj.
func withLabels(o map[string]any, labels map[string]string) map[string]any {
	meta := o["metadata"].(map[string]any)
	existing, _ := meta["labels"].(map[string]any)
	if existing == nil {
		existing = map[string]any{}
		meta["labels"] = existing
	}
	for k, v := range labels {
		existing[k] = v
	}
	return o
}

// withFinalizers sets (or clears, when empty) metadata.finalizers.
func withFinalizers(o map[string]any, finalizers ...string) map[string]any {
	meta := o["metadata"].(map[string]any)
	if len(finalizers) == 0 {
		delete(meta, "finalizers")
		return o
	}
	fs := make([]any, len(finalizers))
	for i, f := range finalizers {
		fs[i] = f
	}
	meta["finalizers"] = fs
	return o
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
	// A child forked from another owner's Blip inherits its parent reference.
	// Unrelated updates must not re-validate that unchanged reference against
	// the caller's prefix.
	inheritedOld := withOwnerReferences(blipObj(o+".child", o), ownerReference(x+".parent"))
	inheritedNew := withOwnerReferences(withLabels(blipObj(o+".child", o), map[string]string{"probe": "1"}), ownerReference(x+".parent"))
	ownAndForeign := withOwnerReferences(blipObj(o+".child", o),
		ownerReference(o+".parent"), ownerReference(x+".parent"))
	foreignRenamed := withOwnerReferences(blipObj(o+".child", o), ownerReference(x+".other"))

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
		{"state of own state", policyRequest{user: mine, op: admission.Create, resource: "blipstates",
			name: o + ".child", object: withOwnerReferences(stateObj(o+".child", o, ""), ownerReference(o+".root", set("kind", "BlipState")))}, true, ""},
		{"state of foreign state", policyRequest{user: mine, op: admission.Create, resource: "blipstates",
			name: o + ".child", object: withOwnerReferences(stateObj(o+".child", o, ""), ownerReference(x+".root", set("kind", "BlipState")))}, false, "ownerReferences"},
		{"controller-owned state of own state", policyRequest{user: mine, op: admission.Create, resource: "blipstates",
			name: o + ".child", object: withOwnerReferences(stateObj(o+".child", o, ""), ownerReference(o+".root", set("kind", "BlipState"), set("controller", true)))}, false, "ownerReferences"},
		{"blocking-deletion state of own state", policyRequest{user: mine, op: admission.Create, resource: "blipstates",
			name: o + ".child", object: withOwnerReferences(stateObj(o+".child", o, ""), ownerReference(o+".root", set("kind", "BlipState"), set("blockOwnerDeletion", true)))}, false, "ownerReferences"},
		{"blip owned by a state", policyRequest{user: mine, op: admission.Create, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(o+".root", set("kind", "BlipState")))}, false, "ownerReferences"},
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
		{"inherited foreign owner unchanged", policyRequest{user: mine, op: admission.Update, resource: "blips",
			name: o + ".child", object: inheritedNew, oldObject: inheritedOld}, true, ""},
		{"add foreign owner reference", policyRequest{user: mine, op: admission.Update, resource: "blips",
			name: o + ".child", object: ownAndForeign,
			oldObject: withOwnerReferences(blipObj(o+".child", o), ownerReference(o+".parent"))}, false, "ownerReferences"},
		{"change inherited foreign owner reference", policyRequest{user: mine, op: admission.Update, resource: "blips",
			name: o + ".child", object: foreignRenamed, oldObject: inheritedOld}, false, "ownerReferences"},
		{"change inherited foreign owner uid", policyRequest{user: mine, op: admission.Update, resource: "blips",
			name: o + ".child", object: withOwnerReferences(blipObj(o+".child", o), ownerReference(x+".parent", set("uid", "uid-replaced"))),
			oldObject: inheritedOld}, false, "ownerReferences"},
		{"own prefixed owner reference on update", policyRequest{user: mine, op: admission.Update, resource: "blips",
			name: o + ".fork", object: withOwnerReferences(blipObj(o+".fork", o), ownerReference(o+".parent")),
			oldObject: blipObj(o+".fork", o)}, true, ""},
		{"remove inherited foreign owner reference", policyRequest{user: mine, op: admission.Update, resource: "blips",
			name: o + ".child", object: blipObj(o+".child", o), oldObject: inheritedOld}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allow, msg := tc.req.evaluate(t, v, params)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

// TestVMOwnerPolicyInheritedOwnerReference follows the e2e flow that exposed
// the bug: an unrestricted Blip forks a child, an administrator labels the
// child for a project, and the child's own VM then patches an unrelated label.
// The child keeps the ownerReference its privileged creator set; re-validating
// that unchanged reference against the project prefix denied every self-patch.
func TestVMOwnerPolicyInheritedOwnerReference(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	const project, parent = "u-0123456789abcdef0123456789abcdef", "w6-18-top"
	child := project + ".child"
	params := map[string]string{
		"sa.vm":         "default",
		"default-top":   "-",
		"default-child": project,
	}
	topVM, childVM := vmUser("vm", "default-top"), vmUser("vm", "default-child")
	ref := ownerReference(parent)

	// The unrestricted parent may fork a child owned by itself.
	created := withOwnerReferences(blipObj(child, ""), ref)
	create := policyRequest{user: topVM, op: admission.Create, resource: "blips", name: child, object: created}
	if allow, msg := create.evaluate(t, v, params); !allow {
		t.Fatalf("unrestricted parent fork: %s", msg)
	}

	// An administrator labels the child as project-owned. Its own VM may now
	// patch the child, but the inherited reference must not be re-validated.
	old := withOwnerReferences(blipObj(child, project), ref)
	patched := withOwnerReferences(withLabels(blipObj(child, project), map[string]string{"probe": "1"}), ref)
	update := policyRequest{user: childVM, op: admission.Update, resource: "blips", name: child, object: patched, oldObject: old}
	if allow, msg := update.evaluate(t, v, params); !allow {
		t.Fatalf("self-patch with inherited ownerReference: %s", msg)
	}

	// The exemption is for unchanged references only: adding another foreign
	// reference, or replacing the inherited one, is still a foreign write.
	update.object = withOwnerReferences(withLabels(blipObj(child, project), map[string]string{"probe": "1"}),
		ref, ownerReference("other-project.parent"))
	if allow, msg := update.evaluate(t, v, params); allow {
		t.Fatalf("adding a foreign ownerReference was allowed: %s", msg)
	}
	update.object = withOwnerReferences(withLabels(blipObj(child, project), map[string]string{"probe": "1"}),
		ownerReference("other-project.parent"))
	if allow, msg := update.evaluate(t, v, params); allow {
		t.Fatalf("changing the inherited ownerReference was allowed: %s", msg)
	}

	// A reference the caller may set itself remains allowed.
	update.object = withOwnerReferences(withLabels(blipObj(child, project), map[string]string{"probe": "1"}),
		ownerReference(project+".parent"))
	if allow, msg := update.evaluate(t, v, params); !allow {
		t.Fatalf("own-prefixed ownerReference: %s", msg)
	}
}

// A restricted VM may not add a finalizer to its Blip or state. Retention and
// namespace cleanup only call Delete, so a foreign finalizer would survive the
// controller removing blip.dev/finalizer and leave the object Terminating
// forever. Unchanged inherited finalizers and removals stay allowed so normal
// patches and the controller's own cleanup keep working.
func TestVMOwnerPolicyFinalizers(t *testing.T) {
	v := loadVMOwnerPolicy(t)
	const owner = "u-0123456789abcdef0123456789abcdef"
	params := map[string]string{"sa.vm": "default", "default-mine": owner, "default-admin": "-"}
	mine, admin := vmUser("vm", "default-mine"), vmUser("vm", "default-admin")
	controller := &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blip-controller"}
	blipchat := &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blipchat"}
	blip := func(fs ...string) map[string]any {
		return withFinalizers(blipObj(owner+".a", owner), fs...)
	}
	state := func(fs ...string) map[string]any {
		return withFinalizers(stateObj(owner+".s", owner, ""), fs...)
	}

	for _, tc := range []struct {
		name  string
		user  user.Info
		op    admission.Operation
		res   string
		obj   map[string]any
		old   map[string]any
		allow bool
		msg   string
	}{
		{"restricted create with finalizer", mine, admission.Create, "blips", blip("w7-24.hold"), nil, false, "finalizer"},
		{"restricted create without finalizer", mine, admission.Create, "blips", blip(), nil, true, ""},
		{"restricted update adds finalizer", mine, admission.Update, "blips", blip("w7-24.hold"), blip(), false, "finalizer"},
		{"restricted update adds a second finalizer", mine, admission.Update, "blips",
			blip(v1.Finalizer, "w7-24.hold"), blip(v1.Finalizer), false, "finalizer"},
		{"restricted update keeps inherited finalizers", mine, admission.Update, "blips",
			blip(v1.Finalizer, "w7-24.hold"), blip(v1.Finalizer, "w7-24.hold"), true, ""},
		{"restricted update removes a finalizer", mine, admission.Update, "blips",
			blip(v1.Finalizer), blip(v1.Finalizer, "w7-24.hold"), true, ""},
		{"restricted update replaces a finalizer", mine, admission.Update, "blips",
			blip("w7-24.other"), blip("w7-24.hold"), false, "finalizer"},
		{"restricted state create with finalizer", mine, admission.Create, "blipstates", state("w7-24.hold"), nil, false, "finalizer"},
		{"restricted state update adds finalizer", mine, admission.Update, "blipstates", state("w7-24.hold"), state(), false, "finalizer"},
		{"restricted state update keeps finalizer", mine, admission.Update, "blipstates",
			state(v1.Finalizer), state(v1.Finalizer), true, ""},
		{"controller adds its finalizer", controller, admission.Update, "blips", blip(v1.Finalizer), blip(), true, ""},
		{"controller removes its finalizer", controller, admission.Update, "blips", blip(), blip(v1.Finalizer), true, ""},
		{"blipchat adds a finalizer", blipchat, admission.Update, "blips", blip("w7-24.hold"), blip(), true, ""},
		{"unrestricted VM adds a finalizer", admin, admission.Update, "blips", withFinalizers(blipObj("a", ""), "w7-24.hold"), blipObj("a", ""), true, ""},
		{"plain admin adds a finalizer", &user.DefaultInfo{Name: "alice"}, admission.Update, "blips", blip("w7-24.hold"), blip(), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := owner + ".a"
			if tc.res == "blipstates" {
				name = owner + ".s"
			}
			req := policyRequest{user: tc.user, op: tc.op, resource: tc.res, name: name, object: tc.obj, oldObject: tc.old}
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
	}
}

func chatObject(kind, name string, labels, annotations map[string]string) map[string]any {
	meta := map[string]any{"name": name, "namespace": ns}
	if len(labels) > 0 {
		m := make(map[string]any, len(labels))
		for k, v := range labels {
			m[k] = v
		}
		meta["labels"] = m
	}
	if len(annotations) > 0 {
		m := make(map[string]any, len(annotations))
		for k, v := range annotations {
			m[k] = v
		}
		meta["annotations"] = m
	}
	spec := map[string]any{}
	if kind == "Blip" {
		spec = map[string]any{"pool": "default", "state": name + ".root"}
	}
	return map[string]any{
		"apiVersion": "blip.dev/v1alpha1",
		"kind":       kind,
		"metadata":   meta,
		"spec":       spec,
	}
}

func chatStateObj(name, profile, parent, parentProfile, root, depth, parentDepth string) map[string]any {
	labels := map[string]string{v1.LabelChatSession: "true", v1.LabelOwner: root}
	annotations := map[string]string{v1.AnnotationChatProfile: profile}
	for k, v := range map[string]string{
		v1.AnnotationChatParent:        parent,
		v1.AnnotationChatParentProfile: parentProfile,
		v1.AnnotationChatRoot:          root,
		v1.AnnotationChatDepth:         depth,
		v1.AnnotationChatParentDepth:   parentDepth,
	} {
		if v != "" {
			annotations[k] = v
		}
	}
	return chatObject("BlipState", name, labels, annotations)
}

func TestChatSessionPolicy(t *testing.T) {
	v := loadChatPolicy(t, "blip-chat-session")
	params := readChatPolicyConfig(t)
	blipchat := &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blipchat"}
	controller := &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blip-controller"}
	gc := &user.DefaultInfo{Name: "system:serviceaccount:kube-system:generic-garbage-collector"}
	namespace := &user.DefaultInfo{Name: "system:serviceaccount:kube-system:namespace-controller"}
	chatVM := vmUser("blip-agent", "chat-pod")
	admin := &user.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}}
	labels := map[string]string{v1.LabelChatSession: "true", v1.LabelOwner: "chat-abc"}
	annotations := map[string]string{v1.AnnotationChatProfile: "default"}
	obj := chatObject("BlipState", "chat-abc", labels, annotations)
	blip := chatObject("Blip", "chat-abc-g1", labels, annotations)
	plain := chatObject("BlipState", "plain", map[string]string{v1.LabelOwner: "alice"}, nil)

	for _, tc := range []struct {
		name   string
		user   user.Info
		op     admission.Operation
		res    string
		object map[string]any
		old    map[string]any
		allow  bool
	}{
		{"blipchat creates a session", blipchat, admission.Create, "blipstates", obj, nil, true},
		{"blipchat updates a session", blipchat, admission.Update, "blipstates", obj, obj, true},
		{"controller updates a session", controller, admission.Update, "blipstates", obj, obj, true},
		{"garbage collector deletes a session", gc, admission.Delete, "blipstates", nil, obj, true},
		{"namespace controller deletes a session", namespace, admission.Delete, "blipstates", nil, obj, true},
		{"administrator updates a session", admin, admission.Update, "blipstates", obj, obj, true},
		{"chat VM creates a session", chatVM, admission.Create, "blipstates", obj, nil, false},
		{"chat VM updates a Blip", chatVM, admission.Update, "blips", blip, blip, false},
		{"chat VM deletes a session", chatVM, admission.Delete, "blipstates", nil, obj, false},
		{"chat VM removes the session label", chatVM, admission.Update, "blipstates",
			chatObject("BlipState", "chat-abc", map[string]string{v1.LabelOwner: "chat-abc"}, annotations), obj, false},
		{"non-chat object is not matched", chatVM, admission.Create, "blipstates", plain, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{user: tc.user, op: tc.op, resource: tc.res, name: "chat-abc", object: tc.object, oldObject: tc.old, paramsName: "blip-chat-policy"}
			allow, msg := req.evaluate(t, v, params)
			if allow != tc.allow {
				t.Fatalf("allow %v (%q), want %v", allow, msg, tc.allow)
			}
			if !allow && !strings.Contains(msg, "may not modify chat sessions") {
				t.Fatalf("unexpected denial %q", msg)
			}
		})
	}
}

func TestChatSpawnPolicy(t *testing.T) {
	v := loadChatPolicy(t, "blip-chat-spawn")
	params := readChatPolicyConfig(t)
	blipchat := &user.DefaultInfo{Name: "system:serviceaccount:blip-system:blipchat"}
	admin := &user.DefaultInfo{Name: "alice", Groups: []string{"system:masters"}}
	// A root chat has no parent and may omit depth; blipchat writes "0". A
	// child must carry the parent's reviewed profile and depth.
	root := func(profile, depth string) map[string]any {
		return chatStateObj("chat-root", profile, "", "", "chat-root", depth, "")
	}
	child := func(profile, parentProfile, depth, parentDepth string) map[string]any {
		return chatStateObj("chat-child", profile, "chat-root", parentProfile, "chat-root", depth, parentDepth)
	}

	custom := make(map[string]string, len(params))
	for k, v := range params {
		custom[k] = v
	}
	custom["root"] = "default"
	custom["allow.default"] = "*"
	limitedRoot := make(map[string]string, len(params))
	for k, v := range params {
		limitedRoot[k] = v
	}
	limitedRoot["root"] = "default"
	noRoot := make(map[string]string, len(params))
	for k, v := range params {
		noRoot[k] = v
	}
	delete(noRoot, "root")
	noMaxDepth := make(map[string]string, len(params))
	for k, v := range params {
		noMaxDepth[k] = v
	}
	delete(noMaxDepth, "maxDepth")
	noAllow := make(map[string]string, len(params))
	for k, v := range params {
		noAllow[k] = v
	}
	delete(noAllow, "allow.worker")

	for _, tc := range []struct {
		name   string
		user   user.Info
		params map[string]string
		object map[string]any
		allow  bool
		msg    string
	}{
		{"root default", blipchat, params, root("default", "0"), true, ""},
		{"root worker", blipchat, params, root("worker", "0"), true, ""},
		{"root may omit depth", blipchat, params, root("default", ""), true, ""},
		{"root depth one", blipchat, params, root("default", "1"), false, "depth"},
		{"root bad depth", blipchat, params, root("default", "x"), false, "depth"},
		{"root not in list", blipchat, limitedRoot, root("worker", "0"), false, "root"},
		{"root policy key missing", blipchat, noRoot, root("default", "0"), false, "root"},
		{"maxDepth key missing", blipchat, noMaxDepth, root("default", "0"), false, "maxDepth"},
		{"child default to worker", blipchat, params, child("worker", "default", "1", "0"), true, ""},
		{"child default to reviewer", blipchat, params, child("reviewer", "default", "1", "0"), true, ""},
		{"child default to default", blipchat, params, child("default", "default", "1", "0"), false, "child"},
		{"child lead to worker", blipchat, params, child("worker", "lead", "1", "0"), true, ""},
		{"child worker has no allow", blipchat, params, child("worker", "worker", "1", "0"), false, "child"},
		{"child allow key missing", blipchat, noAllow, child("worker", "worker", "1", "0"), false, "child"},
		{"child missing parent profile", blipchat, params, child("worker", "", "1", "0"), false, "child"},
		{"child missing parent depth", blipchat, params, child("worker", "default", "1", ""), false, "depth"},
		{"child depth skips a level", blipchat, params, child("worker", "default", "2", "0"), false, "depth"},
		{"child depth two allowed", blipchat, params, child("worker", "default", "2", "1"), true, ""},
		{"child depth exceeds max", blipchat, params, child("worker", "default", "3", "2"), false, "maxDepth"},
		{"wildcard allow", blipchat, custom, child("default", "default", "1", "0"), true, ""},
		{"administrator bypasses policy", admin, limitedRoot, child("worker", "", "9", ""), true, ""},
		{"hidden fork copy is not a spawn", blipchat, params, chatObject("BlipState", "chat-mount", map[string]string{v1.LabelChatSession: "true", v1.LabelOwner: "chat-root"}, nil), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := policyRequest{user: tc.user, op: admission.Create, resource: "blipstates", name: "chat-new", object: tc.object, paramsName: "blip-chat-policy"}
			allow, msg := req.evaluate(t, v, tc.params)
			if allow != tc.allow || !strings.Contains(msg, tc.msg) {
				t.Fatalf("allow %v (%q), want %v (%q)", allow, msg, tc.allow, tc.msg)
			}
		})
	}
}

func TestChatPolicyCoverage(t *testing.T) {
	policies, bindings := readPolicyDocs(t, "../../deploy/base/chat-agent-policy.yaml")
	for _, name := range []string{"blip-chat-session", "blip-chat-spawn"} {
		policy := findPolicy(t, policies, name)
		if policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admissionv1.Fail {
			t.Errorf("%s does not fail closed", name)
		}
		var binding *admissionv1.ValidatingAdmissionPolicyBinding
		for _, b := range bindings {
			if b.Spec.PolicyName == name {
				binding = b
				break
			}
		}
		if binding == nil || binding.Spec.ParamRef == nil || binding.Spec.ParamRef.Name != "blip-chat-policy" ||
			binding.Spec.ParamRef.Namespace != "blip-system" ||
			binding.Spec.ParamRef.ParameterNotFoundAction == nil ||
			*binding.Spec.ParamRef.ParameterNotFoundAction != admissionv1.DenyAction ||
			len(binding.Spec.ValidationActions) != 1 || binding.Spec.ValidationActions[0] != admissionv1.Deny {
			t.Errorf("%s binding %v", name, binding)
		}
	}
	session := findPolicy(t, policies, "blip-chat-session")
	if !slices.Contains(session.Spec.MatchConstraints.ResourceRules[0].Resources, "blips") ||
		!slices.Contains(session.Spec.MatchConstraints.ResourceRules[0].Resources, "blipstates") {
		t.Errorf("session policy does not cover blips and blipstates")
	}
	spawn := findPolicy(t, policies, "blip-chat-spawn")
	if !slices.Equal(spawn.Spec.MatchConstraints.ResourceRules[0].Resources, []string{"blipstates"}) ||
		!slices.Equal(spawn.Spec.MatchConstraints.ResourceRules[0].Operations, []admissionv1.OperationType{admissionv1.Create}) {
		t.Errorf("spawn policy rules %v", spawn.Spec.MatchConstraints.ResourceRules)
	}
}
