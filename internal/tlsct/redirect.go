package tlsct

import "net/http"

// RejectRedirect returns the original response without sending a request to
// the redirect target. Fetch callers must reject its status as a protocol error.
func RejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// IsRedirectStatus identifies all HTTP redirection status codes.
func IsRedirectStatus(status int) bool { return status >= 300 && status < 400 }
