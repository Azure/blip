// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// TestStateAnonymousUnauthorizedFailsTerminally covers a private or missing
// repository that answers an anonymous pull with 401. No secret is supplied
// and imagePullSecrets is immutable, so retrying cannot succeed: the state
// must fail terminally with the registry detail instead of leaving `pull`
// waiting on Pending forever.
func TestStateAnonymousUnauthorizedFailsTerminally(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"details":"authentication required"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	e := newEnv(t)
	e.addNodes("n1")
	e.state.Registry = RemoteRegistry{Reader: e.c}
	e.newState("s", func(st *v1.BlipState) {
		st.Spec.Image = u.Host + "/library/private:latest"
		st.Spec.Replicas = 1
	})
	e.run(e.state, ns, "s")
	st := e.getState("s")
	if st.Status.Phase != v1.StateFailed || st.Status.Pending != nil || st.Status.UnplaceableSince != nil {
		t.Fatalf("anonymous 401 not terminal: %+v", st.Status)
	}
	if !strings.Contains(st.Status.Message, "registry rejected image pull credentials") ||
		!strings.Contains(st.Status.Message, "authentication required") {
		t.Fatalf("message %q does not explain the anonymous auth rejection", st.Status.Message)
	}
}
