// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	//"go.uber.org/zap"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

var jsRedirTmpl = template.Must(template.New("js_redir").Parse(`
<html>
	<body>
	    <p>User Unauthorized. Redirecting to login.</p>
		<script>
		var auth_url_path = "{{.AuthURLPath}}";
		var sep = "{{.Sep}}";
		var redir_param = "{{.RedirParam}}";
		var redir_url = "{{.RedirURL}}";
		if (window.location.hash) {
			redir_url = redir_url + "#" + window.location.hash.substr(1);
		}
		var final_url = auth_url_path + sep + redir_param + "=" + encodeURIComponent(redir_url);
		window.location = final_url;
		</script>
	</body>
</html>
`))

// HandleRedir redirct the requests to configured auth URL.
func HandleRedir(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) {
	authURLPath := opts["auth_url_path"].(string)
	authRedirectQueryDisabled := opts["auth_redirect_query_disabled"].(bool)
	redirectParameter := opts["redirect_param"].(string)
	useJSRedir := opts["use_js_redir"].(bool)
	//log := opts["logger"].(*zap.Logger)

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

	if useJSRedir {
		w.WriteHeader(403)
		jsRedirTmpl.Execute(w, map[string]string{
			"AuthURLPath": authURLPath,
			"Sep":         sep,
			"RedirParam":  redirectParameter,
			"RedirURL":    redirectURL,
		})

		return
	}
	escaped := url.QueryEscape(redirectURL)
	w.Header().Set("Location", authURLPath+sep+redirectParameter+"="+escaped)
	w.WriteHeader(302)
	w.Write([]byte(`User Unauthorized`))
}
