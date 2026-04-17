package actions

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"
)

// githubAPIBase is the base URL for GitHub API calls. It defaults to the
// public GitHub API but can be overridden via the GITHUB_API_URL environment
// variable for testing (e.g. pointing at a fake API server).
var githubAPIBase = "https://api.github.com"

// githubHTTPClient is used for GitHub API calls. When the API URL is
// overridden it may point at an in-cluster HTTP server with a self-signed
// certificate, so we skip TLS verification in that case.
var githubHTTPClient *http.Client

func init() {
	if u := os.Getenv("GITHUB_API_URL"); u != "" {
		githubAPIBase = u
		githubHTTPClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	} else {
		githubHTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
}
