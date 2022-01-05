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
	"html/template"
	"net/http"
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
		var final_url = auth_url_path;
		if (redir_param) {
			final_url = auth_url_path + sep + redir_param + "=" + encodeURIComponent(redir_url);
		}
		window.location = final_url;
		</script>
	</body>
</html>
`))

// HandleJSRedirect redirects the requests to configured auth URL by responding an HTML
// with javascript doing the real redirection.
func HandleJSRedirect(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) {
	authURLPath, sep, redirectParameter, redirectURL, _, redirect := redirectParameters(w, r, opts)
	if !redirect {
		return
	}

	w.WriteHeader(403)
	jsRedirTmpl.Execute(w, map[string]string{
		"AuthURLPath": authURLPath,
		"Sep":         sep,
		"RedirParam":  redirectParameter,
		"RedirURL":    redirectURL,
	})
}
