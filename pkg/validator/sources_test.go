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

	//"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/testutils"
)

func TestAuthorizationSources(t *testing.T) {
	var testcases = []struct {
		name                         string
		allowedTokenNames            []string
		allowedTokenSources          []string
		enableQueryViolations        bool
		enableCookieViolations       bool
		enableHeaderViolations       bool
		enableBearerHeaderViolations bool
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
				"token_name": "access_token",
				"claim_name": "foo",
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
				"token_name": "jwt_access_token",
				"claim_name": "foo",
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
				"token_name": "access_token",
				"claim_name": "foo",
			},
			shouldErr: false,
		},
		{
			name: "default token source priorities, same token name, different tokens injected in query parameter and auth header",
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "access_token",
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
				{
					Name:     "access_token",
					Location: tokenSourceQuery,
					Claims: &claims.UserClaims{
						Name: "bar",
					},
				},
			},
			want: map[string]interface{}{
				"token_name": "access_token",
				"claim_name": "foo",
			},
			shouldErr: false,
		},
		{
			name:                "custom token source priorities, same token name, different tokens injected in query parameter and auth header",
			allowedTokenSources: []string{tokenSourceQuery, tokenSourceCookie, tokenSourceHeader},
			tokens: []*testutils.InjectedTestToken{
				{
					Name:     "access_token",
					Location: tokenSourceHeader,
					Claims: &claims.UserClaims{
						Name: "foo",
					},
				},
				{
					Name:     "access_token",
					Location: tokenSourceQuery,
					Claims: &claims.UserClaims{
						Name: "bar",
					},
				},
			},
			want: map[string]interface{}{
				"token_name": "access_token",
				"claim_name": "bar",
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
				"token_name": "jwt_access_token",
				"claim_name": "bar",
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
			allowedTokenNames: []string{"foobar_token"},
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
		{
			name:                  "query paramater token source violations",
			enableQueryViolations: true,
			shouldErr:             true,
			err:                   errors.ErrNoTokenFound,
		},
		{
			name:                   "cookie token source violations",
			enableCookieViolations: true,
			shouldErr:              true,
			err:                    errors.ErrNoTokenFound,
		},
		{
			name:                   "header token source violations",
			enableHeaderViolations: true,
			shouldErr:              true,
			err:                    errors.ErrNoTokenFound,
		},
		{
			name:                         "bearer header token source violations",
			enableBearerHeaderViolations: true,
			shouldErr:                    true,
			err:                          errors.ErrNoTokenFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			keyManagers := testutils.NewTestKeyManagers("HS512", testutils.GetSharedKey())
			verifyKeys := kms.GetVerifyKeys(keyManagers)
			signingKeys := kms.GetSignKeys(keyManagers)

			validator := NewTokenValidator()
			accessList := testutils.NewTestGuestAccessList()
			if err := validator.AddAccessList(ctx, accessList); err != nil {
				t.Fatal(err)
			}
			if err := validator.AddKeys(ctx, verifyKeys); err != nil {
				t.Fatal(err)
			}

			if len(tc.allowedTokenSources) > 0 {
				if err := validator.SetSourcePriority(tc.allowedTokenSources); err != nil {
					t.Fatal(err)
				}
			}
			if len(tc.allowedTokenNames) > 0 {
				if err := validator.SetAllowedTokenNames(tc.allowedTokenNames); err != nil {
					t.Fatal(err)
				}
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				ctx := context.Background()
				var msgs []string
				msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
				msgs = append(msgs, fmt.Sprintf("allowed token names: %s", tc.allowedTokenNames))
				for i, tkn := range tc.tokens {
					msgs = append(msgs, fmt.Sprintf("token %d, name: %s, location: %s", i, tkn.Name, tkn.Location))
				}
				var opts *options.TokenValidatorOptions
				if tc.enableBearerHeaderViolations {
					opts = options.NewTokenValidatorOptions()
					opts.ValidateBearerHeader = true
				}
				userClaims, tokenName, err := validator.Authorize(ctx, r, opts)
				if tests.EvalErrWithLog(t, err, tc.want, tc.shouldErr, tc.err, msgs) {
					return
				}
				got := make(map[string]interface{})
				got["token_name"] = tokenName
				got["claim_name"] = userClaims.Name
				tests.EvalObjectsWithLog(t, "response", tc.want, got, msgs)
			}

			reqURI := "/protected/path"
			if tc.enableQueryViolations {
				reqURI += "?access_token=foobarfoo"
			}

			req, err := http.NewRequest("GET", reqURI, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.enableCookieViolations {
				req.AddCookie(&http.Cookie{
					Name:    "foobar",
					Value:   "foobar",
					Expires: time.Now().Add(time.Minute * time.Duration(30)),
				})
				req.AddCookie(&http.Cookie{
					Name:    "access_token",
					Value:   "foobar",
					Expires: time.Now().Add(time.Minute * time.Duration(30)),
				})
			}

			if tc.enableBearerHeaderViolations {
				req.Header.Add("Authorization", "Bearer")
			}

			if tc.enableHeaderViolations {
				req.Header.Add("Authorization", "access_token")
			}

			for _, token := range tc.tokens {
				tokenName := token.Name
				if tokenName == "" {
					tokenName = "access_token"
				}
				token.Claims.Roles = append(token.Claims.Roles, "guest")
				testutils.PopulateDefaultClaims(token.Claims)

				signedToken, err := signingKeys[0].SignToken("HS512", token.Claims)
				if err != nil {
					t.Fatal(err)
				}
				switch token.Location {
				case tokenSourceCookie:
					req.AddCookie(testutils.GetCookie(tokenName, signedToken, 10))
				case tokenSourceHeader:
					req.Header.Set("Authorization", fmt.Sprintf("%s=%s", tokenName, signedToken))
				case tokenSourceQuery:
					q := req.URL.Query()
					q.Set(tokenName, signedToken)
					req.URL.RawQuery = q.Encode()
				case "":
					t.Fatal("malformed test: token injection location is empty")
				default:
					t.Fatalf("malformed test: token injection location %s is not supported", token.Location)
				}
			}

			w := httptest.NewRecorder()
			handler(w, req)
			w.Result()
		})
	}
}
