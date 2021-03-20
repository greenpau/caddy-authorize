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

// HandleRedirect redirct the requests to configured auth URL by responding an HTML
// with javascript doing the real redireciton.
func HandleJSRedirect(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) {
	authURLPath, sep, redirectParameter, redirectURL, redirect := redirectParameters(w, r, opts)
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
