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

package validator

import (
	// "errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtacl "github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
)

func TestAuthorizeWithMultipleAccessList(t *testing.T) {
	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"

	// Create access list with default deny that allows read:books only
	defaultDenyACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "scopes",
			Values: []string{"read:books"},
		},
	}

	// Create access list with default allow that denies write:books
	defaultAllowACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "deny",
			Claim:  "scopes",
			Values: []string{"write:books"},
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "scopes",
			Values: []string{"any"},
		},
	}

	// Create access list with default deny that allows 127.0.0.1 only
	audienceDefaultDenyACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "audience",
			Values: []string{"https://127.0.0.1:2019/"},
		},
	}

	// Create access list with default allow that denies localhost
	audienceDefaultAllowACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "deny",
			Claim:  "audience",
			Values: []string{"https://localhost/"},
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "audience",
			Values: []string{"any"},
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action:  "deny",
			Claim:   "scopes",
			Values:  []string{"write:books"},
			Methods: []string{"GET"},
			Path:    "/app/page1/blocked",
		},
		&jwtacl.AccessListEntry{
			Action:  "deny",
			Claim:   "scopes",
			Values:  []string{"write:books"},
			Methods: []string{"GET"},
			Path:    "/app/page2/blocked",
		},
		&jwtacl.AccessListEntry{
			Action:  "allow",
			Claim:   "scopes",
			Values:  []string{"write:books"},
			Methods: []string{"GET"},
			Path:    "/app/page3/allowed",
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "scopes",
			Values: []string{"read:books"},
		},
	}

	// Create access list with default deny and mixed claims
	mixedACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "scopes",
			Values: []string{"write:books"},
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "audience",
			Values: []string{"https://127.0.0.1:2019/"},
		},
	}

	// Create viewer persona
	viewer := `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "aud": ["https://127.0.0.1:2019/", "https://google.com/"],
        "sub": "smithj@outlook.com",
        "scope": ["read:books"]
    }`

	editor := `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "aud": "https://localhost/",
        "sub": "jane.smith@outlook.com",
        "scope": ["write:books"]
    }`

	testcases := []struct {
		name      string
		claims    string
		acl       []*jwtacl.AccessListEntry
		method    string
		path      string
		allowAll  bool
		shouldErr bool
		err       error
	}{
		// Access list with default deny that allows viewer only
		{
			name:   "user with viewer scope claim and default deny acl",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and default deny acl",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer scope claim and default allow acl",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and default allow acl",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Access list with default deny that allows 127.0.0.1 only
		{
			name:   "user with viewer scope claim and audience deny acl",
			claims: viewer, acl: audienceDefaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and audience deny acl",
			claims: editor, acl: audienceDefaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Access list with default allow that denies localhost
		{
			name:   "user with viewer scope claim and audience allow acl",
			claims: viewer, acl: audienceDefaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and audience allow acl",
			claims: editor, acl: audienceDefaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Custom ACL
		{
			name:   "user with viewer scope claim and custom acl going to /app/page1/blocked via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer scope claim and custom acl going to /app/page2/blocked via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer scope claim and custom acl going to /app/page3/allowed via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page1/blocked via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page2/blocked via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page3/allowed via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
		// Mixed ACL
		{
			name:   "user with viewer scope and audience claims and custom acl",
			claims: viewer, acl: mixedACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer scope and audience claims and custom acl",
			claims: viewer, acl: mixedACL, method: "GET", path: "/app/page1/blocked", allowAll: true,
			shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor scope and localhost audience claims and mixed acl",
			claims: editor, acl: mixedACL, method: "GET", path: "/app/editor", shouldErr: false,
		},
		{
			name:   "user with editor scope and localhost audience claims and mixed acl",
			claims: editor, acl: mixedACL, method: "GET", path: "/app/editor", allowAll: true,
			shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tokenConfig, err := kms.NewTokenConfig("HS512", secret)
			if err != nil {
				t.Fatal(err)
			}
			keyManager, err := kms.NewKeyManager(tokenConfig)
			if err != nil {
				t.Fatal(err)
			}
			validator := NewTokenValidator()
			if err := validator.AddKeyManagers([]*kms.KeyManager{keyManager}); err != nil {
				t.Fatal(err)
			}
			if err := validator.AddAccessList(tc.acl); err != nil {
				t.Fatal(err)
			}

			userClaims, err := claims.NewUserClaimsFromJSON(tc.claims)
			if err != nil {
				t.Fatal(err)
			}
			token, err := keyManager.SignToken("HS512", userClaims)
			if err != nil {
				t.Fatal(err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				opts := options.NewTokenValidatorOptions()
				opts.ValidateBearerHeader = true
				if tc.allowAll {
					opts.ValidateAllowMatchAll = true
				}
				for _, entry := range tc.acl {
					if len(entry.Methods) > 0 || entry.Path != "" {
						opts.ValidateMethodPath = true
						break
					}
				}
				if opts.ValidateMethodPath {
					opts.Metadata = make(map[string]interface{})
					opts.Metadata["method"] = r.Method
					opts.Metadata["path"] = r.URL.Path
				}
				for _, entry := range tc.acl {
					t.Logf("ACL: %+v", entry)
				}
				t.Logf("claims: %+v", tc.claims)
				t.Logf("path: %s", r.URL.Path)
				t.Logf("method: %s", r.Method)

				user, err := validator.Authorize(r, opts)
				tests.EvalErr(t, err, user, tc.shouldErr, tc.err)
			}

			req, err := http.NewRequest(tc.method, tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			w := httptest.NewRecorder()
			handler(w, req)

			w.Result()
		})
	}
}

func TestAuthorizeWithAccessList(t *testing.T) {
	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"

	// Create access list with default deny that allows viewer only
	defaultDenyACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"viewer"},
		},
	}

	// Create access list with default allow that denies editor
	defaultAllowACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "deny",
			Claim:  "roles",
			Values: []string{"editor"},
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"any"},
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action:  "deny",
			Claim:   "roles",
			Values:  []string{"editor"},
			Methods: []string{"GET"},
			Path:    "/app/page1/blocked",
		},
		&jwtacl.AccessListEntry{
			Action:  "deny",
			Claim:   "roles",
			Values:  []string{"editor"},
			Methods: []string{"GET"},
			Path:    "/app/page2/blocked",
		},
		&jwtacl.AccessListEntry{
			Action:  "allow",
			Claim:   "roles",
			Values:  []string{"editor"},
			Methods: []string{"GET"},
			Path:    "/app/page3/allowed",
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"viewer"},
		},
	}

	// Create viewer persona
	viewer := `{
            "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
            "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
            "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
            "name":   "Smith, John",
            "email":  "smithj@outlook.com",
            "origin": "localhost",
            "sub":    "smithj@outlook.com",
            "roles": ["viewer"]
        }`

	editor := `{
            "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
            "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
            "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
            "name":   "Smith, Jane",
            "email":  "jane.smith@outlook.com",
            "origin": "localhost",
            "sub":    "jane.smith@outlook.com",
            "roles": ["editor"]
        }`

	testcases := []struct {
		name      string
		claims    string
		acl       []*jwtacl.AccessListEntry
		method    string
		path      string
		shouldErr bool
		err       error
	}{
		// Access list with default deny that allows viewer only
		{
			name:   "user with viewer role claim and default deny acl going to app/viewer via get",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/editor via get",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/editor", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/admin via get",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/admin", shouldErr: false,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/viewer via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/editor via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/editor", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/admin via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/admin", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer role claim and default allow acl going to app/viewer via get",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/editor via get",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/editor", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/admin via get",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/admin", shouldErr: false,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/viewer via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/editor via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/editor", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/admin via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/admin", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Custom ACL
		{
			name:   "user with editor role claim and custom acl going to /app/page1/blocked via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page2/blocked via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page3/allowed via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page1/blocked via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page2/blocked via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page3/allowed via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tokenConfig, err := kms.NewTokenConfig("HS512", secret)
			if err != nil {
				t.Fatal(err)
			}
			keyManager, err := kms.NewKeyManager(tokenConfig)
			if err != nil {
				t.Fatal(err)
			}
			validator := NewTokenValidator()
			if err := validator.AddKeyManagers([]*kms.KeyManager{keyManager}); err != nil {
				t.Fatal(err)
			}
			if err := validator.AddAccessList(tc.acl); err != nil {
				t.Fatal(err)
			}

			userClaims, err := claims.NewUserClaimsFromJSON(tc.claims)
			if err != nil {
				t.Fatal(err)
			}

			token, err := keyManager.SignToken("HS512", userClaims)
			if err != nil {
				t.Fatal(err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				opts := options.NewTokenValidatorOptions()
				for _, entry := range tc.acl {
					if len(entry.Methods) > 0 || entry.Path != "" {
						opts.ValidateMethodPath = true
						break
					}
				}
				if opts.ValidateMethodPath {
					opts.Metadata = make(map[string]interface{})
					opts.Metadata["method"] = r.Method
					opts.Metadata["path"] = r.URL.Path
				}
				t.Logf("role: %s", userClaims.Roles)
				t.Logf("path: %s", r.URL.Path)
				t.Logf("method: %s", r.Method)
				user, err := validator.Authorize(r, opts)

				tests.EvalErr(t, err, user, tc.shouldErr, tc.err)
			}

			req, err := http.NewRequest(tc.method, tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("access_token=%s", token))
			w := httptest.NewRecorder()
			handler(w, req)

			w.Result()
		})
	}
}
