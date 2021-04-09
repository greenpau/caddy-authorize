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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	//"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	// "github.com/greenpau/caddy-auth-jwt/pkg/kms"
	// "github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/testutils"
)

func TestAuthorizationSources(t *testing.T) {
	var testcases = []struct {
		name                string
		allowedTokenNames   []string
		allowedTokenSources []string
		// The name of the token.
		tokens    []*testutils.InjectedTestToken
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "default token sources and names with auth header claim injection",
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "access_token",
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
			},
			want: map[string]interface{}{
				"name": "foo",
			},
			shouldErr: false,
		},
		{
			name: "default token sources and names with cookie claim injection",
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "jwt_access_token",
					Location: tokenSourceCookie,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
			},
			want: map[string]interface{}{
				"name": "foo",
			},
			shouldErr: false,
		},
		{
			name: "default token sources and names with query parameter claim injection",
			tokens: []*testutils.InjectedTestToken{
				{
					Location: tokenSourceQuery,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
			},
			want: map[string]interface{}{
				"name": "foo",
			},
			shouldErr: false,
		},
		{
			name: "default token source priorities, same token name, different tokens injected in query parameter and auth header",
			tokens: []*testutils.InjectedTestToken{
				{
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
				{
					Location: tokenSourceQuery,
					Claims: &claims.UserClaims{
						Name: "bar",
					},
				},
			},
			want: map[string]interface{}{
				"name": "foo",
			},
			shouldErr: false,
		},
		{
			name:                "custom token source priorities, same token name, different tokens injected in query parameter and auth header",
			allowedTokenSources: []string{tokenSourceQuery, tokenSourceCookie, tokenSourceHeader},
			tokens: []*testutils.InjectedTestToken{
				{
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
				{
					Location: tokenSourceQuery,
					Claims: &claims.UserClaims{
						Name: "bar",
					},
				},
			},
			want: map[string]interface{}{
				"name": "bar",
			},
			shouldErr: false,
		},
		{
			name:              "default token source priorities, different token name, different tokens injected in query parameter and auth header",
			allowedTokenNames: []string{"jwt_access_token"},
			tokens: []*testutils.InjectedTestToken{
				{
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
				{
					Name:     "jwt_access_token",
					Location: tokenSourceQuery,
					Claims: &claims.UserClaims{
						Name: "bar",
					},
				},
			},
			want: map[string]interface{}{
				"name": "bar",
			},
			shouldErr: false,
		},
		{
			name: "default token sources and names with custom token name injection",
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "foobar",
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
			},
			shouldErr: true,
			err:       errors.ErrNoTokenFound,
		},
		{
			name:              "custom token names with standard token name injection",
			allowedTokenNames: []string{"foobar"},
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "access_token",
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
			},
			shouldErr: true,
			err:       errors.ErrNoTokenFound,
		},
		{
			name:                "cookie token source with auth header token injection",
			allowedTokenSources: []string{tokenSourceCookie},
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "access_token",
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
			},
			shouldErr: true,
			err:       errors.ErrNoTokenFound,
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {

			keyManagers := testutils.NewTestKeyManagers("HS512", secret)
			keyManager := keyManagers

			validator, keyManager := testutils.NewTestValidator("HS512", secret)
			accessList := testutils.NewTestGuestAccessList()
			if err := validator.AddAccessList(accessList); err != nil {
				t.Fatal(err)
			}

			if len(allowedTokenSources) > 0 {
				if err := validator.SetSourcePriority(allowedTokenSources); err != nil {
					t.Fatal(err)
				}
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				userClaims, tokenName, err := validator.Authorize(r, nil)
				if tests.EvalErr(t, err, u, tc.shouldErr, tc.err) {
					return
				}
				got := make(map[string]interface{})
				got["token_name"] = tokenName
				tests.EvalObjects(t, "response", tc.want, got)
			}

			req, err := http.NewRequest("GET", "/protected/path", nil)
			if err != nil {
				t.Fatal(err)
			}

			for _, token := range tc.tokens {
				tokenName = token.name
				if tokenName == "" {
					tokenName = "access_token"
				}
				if err := testutils.PopulateDefaultClaims(token.claims); err != nil {
					t.Fatalf("malformed test: token claim: %v", err)
				}
				signedToken, err := keyManager.SignToken("HS512", token.claims)
				if err != nil {
					t.Fatal(err)
				}
				switch token.location {
				case tokenSourceCookie:
					req.AddCookie(test.cookie)
				case tokenSourceHeader:
					req.Header.Set("Authorization", fmt.Sprintf("%s=%s", tokenName, signedToken))
				case tokenSourceQuery:
					q := req.URL.Query()
					q.Set(tokenName, signedToken)
					req.URL.RawQuery = q.Encode()
				case "":
					t.Fatal("malformed test: token injection location is empty")
				default:
					t.Fatalf("malformed test: token injection location %s is not supported", token.location)
				}
			}

			w := httptest.NewRecorder()
			handler(w, req)
			w.Result()
		})
	}
}
