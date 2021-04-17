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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/testutils"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"
)

var (

	// Create access list with default deny that allows read:books only
	defaultDenyACL = []*acl.RuleConfiguration{
		{
			Comment: "allow read:books scope",
			Conditions: []string{
				"match scopes read:books",
			},
			Action: `allow log`,
		},
	}

	// Create access list with default allow that denies write:books
	defaultAllowACL = []*acl.RuleConfiguration{
		{
			Comment: "deny write:books scope",
			Conditions: []string{
				"match scopes write:books",
			},
			Action: `deny`,
		},
		{
			Comment: "allow all scopes",
			Conditions: []string{
				"always match scopes any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny that allows 127.0.0.1 only
	audienceDefaultDenyACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match aud https://127.0.0.1:2019/",
			},
			Action: `allow`,
		},
	}

	// Create access list with default allow that denies localhost
	audienceDefaultAllowACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match aud https://localhost/",
			},
			Action: `deny`,
		},
		{
			Comment: "allow all audiences",
			Conditions: []string{
				"always match audience any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match scope write:books",
				"match method GET",
				"match path /app/page1/blocked",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"match scope write:books",
				"match method GET",
				"match path /app/page2/blocked",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"match scope write:books",
				"match method GET",
				"match path /app/page3/allowed",
			},
			Action: `allow`,
		},
		{
			Conditions: []string{
				"match scope read:books",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny and mixed claims
	mixedACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match scope write:books",
			},
			Action: `allow`,
		},
		{
			Conditions: []string{
				"match audience https://127.0.0.1:2019/",
			},
			Action: `allow`,
		},
	}

	// Create viewer persona
	viewer = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "aud": ["https://127.0.0.1:2019/", "https://google.com/"],
        "sub": "smithj@outlook.com",
        "scope": ["read:books"]
    }`

	editor = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "aud": "https://localhost/",
        "sub": "jane.smith@outlook.com",
        "scope": ["write:books"]
    }`

	// Create access list with default deny that allows viewer only
	defaultRolesDenyACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role viewer",
			},
			Action: `allow`,
		},
	}

	// Create access list with default allow that denies editor
	defaultRolesAllowACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role editor",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"always match role any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customRolesACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role editor",
				"match method GET",
				"match path /app/page1/blocked",
			},
			Action: `deny log`,
		},
		{
			Conditions: []string{
				"match role editor",
				"match method GET",
				"match path /app/page2/blocked",
			},
			Action: `deny log`,
		},
		{
			Conditions: []string{
				"match role editor",
				"match method GET",
				"match path /app/page3/allowed",
			},
			Action: `allow log`,
		},
		{
			Conditions: []string{
				"match role viewer",
			},
			Action: `allow log`,
		},
	}

	// Create viewer persona
	viewer2 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, John",
        "email":  "smithj@outlook.com",
        "origin": "localhost",
        "sub":    "smithj@outlook.com",
        "roles": ["viewer"],
        "addr": "10.10.10.10"
    }`

	editor2 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, Jane",
        "email":  "jane.smith@outlook.com",
        "origin": "localhost",
        "sub":    "jane.smith@outlook.com",
        "roles": ["editor"]
    }`

	viewer3 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, John",
        "email":  "smithj@outlook.com",
        "origin": "localhost",
        "sub":    "smithj@outlook.com",
        "roles": ["viewer"],
		"acl":{
			"paths": {
				"/**/allowed": {}
			}
		}
    }`
)

func TestAuthorize(t *testing.T) {
	testcases := []struct {
		name                        string
		claims                      string
		config                      []*acl.RuleConfiguration
		method                      string
		path                        string
		enableBearer                bool
		validateAccessListPathClaim bool
		want                        map[string]interface{}
		shouldErr                   bool
		err                         error
	}{
		// Access list with default deny that allows viewer only
		{
			name:   "user with viewer scope claim and default deny acl",
			claims: viewer, config: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and default deny acl",
			claims: editor, config: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer scope claim and default allow acl",
			claims: viewer, config: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and default allow acl",
			claims: editor, config: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
		},
		// Access list with default deny that allows 127.0.0.1 only
		{
			name:   "user with viewer scope claim and audience deny acl",
			claims: viewer, config: audienceDefaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and audience deny acl",
			claims: editor, config: audienceDefaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
		},
		// Access list with default allow that denies localhost
		{
			name:   "user with viewer scope claim and audience allow acl",
			claims: viewer, config: audienceDefaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and audience allow acl",
			claims: editor, config: audienceDefaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
		},
		// Custom ACL
		{
			name:   "user with viewer scope claim and custom acl going to /app/page1/blocked via get",
			claims: viewer, config: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer scope claim and custom acl going to /app/page2/blocked via get",
			claims: viewer, config: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer scope claim and custom acl going to /app/page3/allowed via get",
			claims: viewer, config: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page1/blocked via get",
			claims: editor, config: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page2/blocked via get",
			claims: editor, config: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page3/allowed via get",
			claims: editor, config: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
		// Mixed ACL
		{
			name:   "user with viewer scope and audience claims and custom acl",
			claims: viewer, config: mixedACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
		},
		{
			name:   "user with editor scope and localhost audience claims and mixed acl",
			claims: editor, config: mixedACL, method: "GET", path: "/app/editor", shouldErr: false,
		},
		// Role-based ACLs.
		{
			name:   "user with viewer role claim and default deny acl going to app/viewer via get",
			claims: viewer2, config: defaultRolesDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/editor via get",
			claims: viewer2, config: defaultRolesDenyACL, method: "GET", path: "/app/editor", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/admin via get",
			claims: viewer2, config: defaultRolesDenyACL, method: "GET", path: "/app/admin", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/viewer via get",
			claims: editor2, config: defaultRolesDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/editor via get",
			claims: editor2, config: defaultRolesDenyACL, method: "GET", path: "/app/editor", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/admin via get",
			claims: editor2, config: defaultRolesDenyACL, method: "GET", path: "/app/admin", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer role claim and default allow acl going to app/viewer via get",
			claims: viewer2, config: defaultRolesAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/editor via get",
			claims: viewer2, config: defaultRolesAllowACL, method: "GET", path: "/app/editor", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/admin via get",
			claims: viewer2, config: defaultRolesAllowACL, method: "GET", path: "/app/admin", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/viewer via get",
			claims: editor2, config: defaultRolesAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/editor via get",
			claims: editor2, config: defaultRolesAllowACL, method: "GET", path: "/app/editor", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/admin via get",
			claims: editor2, config: defaultRolesAllowACL, method: "GET", path: "/app/admin", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		// Custom ACL
		{
			name:   "user with editor role claim and custom acl going to /app/page1/blocked via get",
			claims: editor2, config: customRolesACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page2/blocked via get",
			claims: editor2, config: customRolesACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer: true,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page3/allowed via get",
			claims: editor2, config: customRolesACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page1/blocked via get",
			claims: viewer2, config: customRolesACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page2/blocked via get",
			claims: viewer2, config: customRolesACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
			enableBearer: true,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page3/allowed via get",
			claims: viewer2, config: customRolesACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			enableBearer: true,
		},
		// Token based ACL
		{
			name:   "user with viewer role claim and token-based acl going to /app/page3/allowed via get",
			claims: viewer3, config: defaultRolesDenyACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			validateAccessListPathClaim: true,
		}, {
			name:                        "user with viewer role claim and token-based acl going to /app/page2/blocked via get",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page2/blocked",
			validateAccessListPathClaim: true,
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			logger := utils.NewLogger()
			keyManagers := testutils.NewTestKeyManagers("HS512", testutils.GetSharedKey())
			keyManager := keyManagers[0]
			validator := NewTokenValidator()
			if err := validator.AddKeyManagers(ctx, keyManagers); err != nil {
				t.Fatal(err)
			}
			accessList := acl.NewAccessList()
			accessList.SetLogger(logger)
			if err := accessList.AddRules(ctx, tc.config); err != nil {
				t.Fatal(err)
			}
			if err := validator.AddAccessList(ctx, accessList); err != nil {
				t.Fatal(err)
			}

			if tc.want == nil {
				tc.want = make(map[string]interface{})
			}

			userClaims, err := claims.NewUserClaimsFromJSON(tc.claims)
			if err != nil {
				t.Fatal(err)
			}
			tc.want["claims"] = userClaims
			if tc.enableBearer {
				tc.want["token_name"] = "bearer"
			} else {
				tc.want["token_name"] = "access_token"
			}
			token, err := keyManager.SignToken("HS512", userClaims)
			if err != nil {
				t.Fatal(err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				ctx := context.Background()
				opts := options.NewTokenValidatorOptions()
				opts.ValidateMethodPath = true
				if tc.enableBearer {
					opts.ValidateBearerHeader = true
				}
				if tc.validateAccessListPathClaim {
					opts.ValidateAccessListPathClaim = true
				}
				var msgs []string
				msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
				for _, entry := range tc.config {
					msgs = append(msgs, fmt.Sprintf("ACL: %+v", entry))
				}
				msgs = append(msgs, fmt.Sprintf("claims: %+v", tc.claims))
				msgs = append(msgs, fmt.Sprintf("path: %s", r.URL.Path))
				msgs = append(msgs, fmt.Sprintf("method: %s", r.Method))
				userClaims, tokenName, err := validator.Authorize(ctx, r, opts)
				if tests.EvalErrWithLog(t, err, tc.config, tc.shouldErr, tc.err, msgs) {
					return
				}
				got := make(map[string]interface{})
				got["token_name"] = tokenName
				got["claims"] = userClaims
				tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
			}

			req, err := http.NewRequest(tc.method, tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.enableBearer {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			} else {
				req.Header.Set("Authorization", fmt.Sprintf("access_token=%s", token))
			}
			w := httptest.NewRecorder()
			handler(w, req)

			w.Result()
		})
	}
}

func TestAddKeyManagers(t *testing.T) {
	testcases := []struct {
		name         string
		tokenConfigs []string
		want         map[string]interface{}
		shouldErr    bool
		err          error
	}{
		{
			name:      "add empty key managers",
			shouldErr: true,
			err:       errors.ErrValidatorKeystoreNoKeyManagers,
		},
		{
			name: "add key managers with custom token config",
			tokenConfigs: []string{
				`{"token_secret": "foobarfoo", "token_name": "jsmith"}`,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			ctx := context.Background()
			keyManagers := []*kms.KeyManager{}
			// keyManagers := testutils.NewTestKeyManagers("HS512", testutils.GetSharedKey())
			for _, cfg := range tc.tokenConfigs {
				km := testutils.NewTestKeyManager(cfg)
				keyManagers = append(keyManagers, km)
			}
			// keyManager := keyManagers[0]
			validator := NewTokenValidator()

			err = validator.AddKeyManagers(ctx, keyManagers)
			if tests.EvalErr(t, err, "key manager", tc.shouldErr, tc.err) {
				return
			}
		})
	}
}

func TestSetAllowedTokenNames(t *testing.T) {
	testcases := []struct {
		name       string
		tokenNames []string
		want       map[string]interface{}
		shouldErr  bool
		err        error
	}{
		{
			name:      "empty token names slice",
			shouldErr: true,
			err:       errors.ErrTokenNamesNotFound,
		},
		{
			name:       "token names slice with duplicate values",
			tokenNames: []string{"foo", "foo"},
			shouldErr:  true,
			err:        errors.ErrDuplicateTokenName.WithArgs("foo"),
		},
		{
			name:       "token names slice with empty values",
			tokenNames: []string{"foo", ""},
			shouldErr:  true,
			err:        errors.ErrEmptyTokenName,
		},
		{
			name:      "empty token names slice",
			shouldErr: true,
			err:       errors.ErrTokenNamesNotFound,
		},
		{
			name:       "valid token names",
			tokenNames: []string{"foo", "bar"},
			want: map[string]interface{}{
				"header": map[string]interface{}{
					"foo": true,
					"bar": true,
				},
				"cookie": map[string]interface{}{
					"foo": true,
					"bar": true,
				},
				"query": map[string]interface{}{
					"foo": true,
					"bar": true,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewTokenValidator()
			err := validator.SetAllowedTokenNames(tc.tokenNames)
			if tests.EvalErr(t, err, "token names", tc.shouldErr, tc.err) {
				return
			}
			got := make(map[string]interface{})
			got["header"] = validator.authHeaders
			got["cookie"] = validator.authCookies
			got["query"] = validator.authHeaders
			tests.EvalObjects(t, "token names", tc.want, got)
		})
	}
}

func TestSetSourcePriority(t *testing.T) {
	testcases := []struct {
		name      string
		sources   []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:      "empty allowed token sources slice",
			shouldErr: true,
			err:       errors.ErrInvalidSourcePriority,
		},
		{
			name:      "allowed token sources slice exceeds three values",
			shouldErr: true,
			sources:   []string{"foo", "foo", "foo", "foo"},
			err:       errors.ErrInvalidSourcePriority,
		},
		{
			name:      "allowed token sources slice has invalid source",
			sources:   []string{"header", "cookie", "foo"},
			shouldErr: true,
			err:       errors.ErrInvalidSourceName.WithArgs("foo"),
		},
		{
			name:      "allowed token sources slice has duplicate source",
			sources:   []string{"header", "query", "query"},
			shouldErr: true,
			err:       errors.ErrDuplicateSourceName.WithArgs("query"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewTokenValidator()
			err := validator.SetSourcePriority(tc.sources)
			if tests.EvalErr(t, err, "token sources", tc.shouldErr, tc.err) {
				return
			}
			got := make(map[string]interface{})
			got["sources"] = validator.tokenSources
			tests.EvalObjects(t, "token sources", tc.want, got)
		})
	}
}

func TestValidateToken(t *testing.T) {
	testcases := []struct {
		name                  string
		user                  string
		accessList            []*acl.RuleConfiguration
		tokenConfigs          []string
		want                  map[string]interface{}
		shouldErr             bool
		disableACL            bool
		badToken              bool
		validateSourceAddress bool
		err                   error
	}{
		{
			name:       "access list not set",
			user:       viewer,
			accessList: defaultAllowACL,
			disableACL: true,
			shouldErr:  true,
			err:        errors.ErrNoAccessList,
		},
		{
			name:       "bad token",
			user:       viewer,
			accessList: defaultAllowACL,
			badToken:   true,
			shouldErr:  true,
			err:        errors.ErrValidatorInvalidToken.WithArgs(errors.ErrKeystoreAddKeyNil),
		},
		{
			name:                  "token without ip address",
			user:                  viewer,
			accessList:            defaultAllowACL,
			validateSourceAddress: true,
			shouldErr:             true,
			err:                   errors.ErrSourceAddressNotFound,
		},
		{
			name:                  "token ip address and client ip address not match",
			user:                  viewer2,
			accessList:            defaultRolesAllowACL,
			validateSourceAddress: true,
			shouldErr:             true,
			err:                   errors.ErrSourceAddressMismatch.WithArgs("10.10.10.10", "20.20.20.20"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var opts *options.TokenValidatorOptions
			ctx := context.Background()
			logger := utils.NewLogger()
			keyManagers := testutils.NewTestKeyManagers("HS512", testutils.GetSharedKey())
			keyManager := keyManagers[0]
			validator := NewTokenValidator()
			if tc.validateSourceAddress {
				opts = options.NewTokenValidatorOptions()
				opts.ValidateSourceAddress = true
				opts.Metadata = make(map[string]interface{})
				opts.Metadata["address"] = "20.20.20.20"
			}
			if err := validator.AddKeyManagers(ctx, keyManagers); err != nil {
				t.Fatal(err)
			}
			var accessList *acl.AccessList
			if !tc.disableACL {
				accessList = acl.NewAccessList()
				accessList.SetLogger(logger)
				if err := accessList.AddRules(ctx, tc.accessList); err != nil {
					t.Fatal(err)
				}
				if err := validator.AddAccessList(ctx, accessList); err != nil {
					t.Fatal(err)
				}
			}

			if tc.want == nil {
				tc.want = make(map[string]interface{})
			}
			userClaims, err := claims.NewUserClaimsFromJSON(tc.user)
			if err != nil {
				t.Fatal(err)
			}
			token, err := keyManager.SignToken("HS512", userClaims)
			if err != nil {
				t.Fatal(err)
			}
			if tc.badToken {
				token = ""
			}
			_, err = validator.ValidateToken(ctx, nil, token, opts)
			if tests.EvalErr(t, err, "validator", tc.shouldErr, tc.err) {
				return
			}
		})
	}
}
