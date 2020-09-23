package jwt

import (
	"net/http"
	"strings"
)

func addRedirectLocationHeader(w http.ResponseWriter, r *http.Request, authURLPath string, authRedirectQueryDisabled bool, redirectParameter string) {
	if strings.Contains(r.RequestURI, redirectParameter) {
		return
	}
	if authRedirectQueryDisabled {
		w.Header().Set("Location", authURLPath)
		return
	}
	sep := "?"
	redirectURL := r.RequestURI
	if strings.HasPrefix(redirectURL, "/") {
		redirectURL = r.Host + redirectURL
		if r.TLS == nil {
			redirectURL = "http://" + redirectURL
		} else {
			redirectURL = "https://" + redirectURL
		}
	}
	if strings.Contains(r.RequestURI, "?") {
		sep = "&"
	}
	w.Header().Set("Location", authURLPath+sep+redirectParameter+"="+redirectURL)
}
