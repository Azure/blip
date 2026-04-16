package actions

import (
	"net/http"
	"time"
)

// githubHTTPClient is used for GitHub API calls.
var githubHTTPClient = &http.Client{Timeout: 30 * time.Second}
