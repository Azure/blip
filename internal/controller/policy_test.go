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
	cm.Name, cm.Namespace = p.paramsName, ns
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
