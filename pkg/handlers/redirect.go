// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	//"go.uber.org/zap"

	"net/http"
	"net/url"
	"strings"
)

// HandleHeaderRedirect redirect the requests to configured auth URL by setting Location header and sending 302.
func HandleHeaderRedirect(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) {
	authURLPath, sep, redirectParameter, redirectURL, redirect := redirectParameters(w, r, opts)
	if !redirect {
		return
	}
	escaped := url.QueryEscape(redirectURL)
	finalURL := authURLPath
	if redirectParameter != "" {
		finalURL = finalURL + sep + redirectParameter + "=" + escaped
	}
	if loginHint := opts["login_hint"]; loginHint != "" {
		loginHint := loginHint.(string)
		escapedLoginHint := url.QueryEscape(loginHint)
		if strings.Contains(finalURL, "?") {
			sep = "&"
		}
		finalURL = finalURL + sep + "login_hint" + "=" + escapedLoginHint
	}

	w.Header().Set("Location", finalURL)
	if opts != nil {
		if v, exists := opts["auth_redirect_status_code"]; exists {
			code := v.(int)
			w.WriteHeader(code)
			w.Write([]byte(http.StatusText(code)))
			return
		}
	}
	w.WriteHeader(302)
	w.Write([]byte(`User Unauthorized`))
}

func redirectParameters(_ http.ResponseWriter, r *http.Request, opts map[string]interface{}) (authURLPath, sep, redirectParameter, redirectURL string, redirect bool) {
	redirect = true
	authURLPath = opts["auth_url_path"].(string)
	authRedirectQueryDisabled := opts["auth_redirect_query_disabled"].(bool)
	redirectParameter = opts["redirect_param"].(string)

	//log := opts["logger"].(*zap.Logger)

	if strings.Contains(r.RequestURI, redirectParameter) {
		return "", "", "", "", false
	}
	if authRedirectQueryDisabled {
		return authURLPath, "", "", "", true
	}
	sep = "?"
	redirectURL = r.RequestURI
	if strings.HasPrefix(redirectURL, "/") {
		redirHost := r.Header.Get("X-Forwarded-Host")
		if redirHost == "" {
			redirHost = r.Host
		}
		redirProto := r.Header.Get("X-Forwarded-Proto")
		if redirProto == "" {
			if r.TLS == nil {
				redirProto = "http"
			} else {
				redirProto = "https"
			}
		}
		redirPort := r.Header.Get("X-Forwarded-Port")

		redirectBaseURL := redirProto + "://" + redirHost
		if redirPort != "" {
			switch redirPort {
			case "443":
				if redirProto != "https" {
					redirectBaseURL += ":" + redirPort
				}
			case "80":
				if redirProto != "http" {
					redirectBaseURL += ":" + redirPort
				}
			default:
				redirectBaseURL += ":" + redirPort
			}
		}
		redirectURL = redirectBaseURL + r.RequestURI
	}

	if strings.Contains(authURLPath, "?") {
		sep = "&"
	}

	return
}
