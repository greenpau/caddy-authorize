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

package jwt

import (
	"fmt"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/testutils"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	port := "8080"
	securePort := "8443"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tokenName := "access_token"
	localhost, _ := url.Parse(baseURL)
	tester := caddytest.NewTester(t)
	tester.InitServer(`
    {
      http_port     `+port+`
      https_port    `+securePort+`
	  debug
    }

    `+host+`, localhost {
      route /dummy/jwt* {
        jwt {
          primary yes
		  crypto key token name `+tokenName+`
		  crypto key verify `+testutils.GetSharedKey()+`
		  set auth url /auth
          disable auth redirect query
		  allow roles *
		  inject headers with claims
          set token sources header query cookie
		}
        respond * "caddy jwt plugin" 200
      }

      route /protected/viewer* {
	    jwt {
		  allow roles admin editor viewer
          disable auth redirect query
		}
        respond * "viewers, editors, and administrators" 200
      }

      route /protected/editor* {
	    jwt {
          deny roles admin with get to editor/blocked
		  allow roles admin editor
          disable auth redirect query
		}
        respond * "editors and administrators" 200
      }

      route /protected/admin* {
        jwt {
		  allow roles admin
          disable auth redirect query
		}
        respond * "administrators only" 200
      }

      route /protected/authenticated* {
        jwt {
		  allow roles admin editor viewer anonymous guest
		  set auth url https://auth.google.com/oauth2
		}
        respond * "authenticated users only" 200
      }

      route /protected/guest* {
        jwt {
		  allow roles anonymous guest
		}
        respond * "guests only" 200
      }

      route /protected/unauth* {
        jwt {
		  allow scope read:books
		}
      }

      route /protected/api* {
        jwt {
		  allow scope read:books
		  disable auth redirect
		}
      }

	  route /auth* {
        respond * "caddy auth portal plugin" 200
	  }

      route /version* {
        respond * "1.0.0" 200
      }
    }
    `, "caddyfile")

	expectedResponse := map[string]string{
		"/version":                  "1.0.0",
		"/auth":                     "caddy auth portal plugin",
		"/dummy/jwt":                "caddy jwt plugin",
		"/protected/viewer":         "viewers, editors, and administrators",
		"/protected/editor":         "editors and administrators",
		"/protected/admin":          "administrators only",
		"/protected/authenticated":  "authenticated users only",
		"/protected/guest":          "guests only",
		"/protected/editor/allowed": "editors and administrators",
		"/protected/api":            "",
	}

	var testcases = []struct {
		name              string
		roles             []string
		accessGrantedPath []string
		accessDeniedPath  []string
		unauthorizedPath  []string
		headers           map[string]string
	}{
		{
			name:  "access with admin role",
			roles: []string{"admin"},
			accessGrantedPath: []string{
				"/version",
				"/dummy/jwt",
				"/protected/viewer",
				"/protected/admin",
				"/protected/editor/allowed",
				"/protected/authenticated",
			},
			accessDeniedPath: []string{
				"/protected/guest",
				"/protected/editor/blocked",
			},
		},
		{
			name:  "access with editor role",
			roles: []string{"editor"},
			accessGrantedPath: []string{
				"/version",
				"/dummy/jwt",
				"/protected/viewer",
				"/protected/editor",
				"/protected/authenticated",
			},
			accessDeniedPath: []string{
				"/protected/guest",
				"/protected/admin",
			},
		},
		{
			name:  "access with viewer role",
			roles: []string{"viewer"},
			accessGrantedPath: []string{
				"/version",
				"/dummy/jwt",
				"/protected/viewer",
				"/protected/authenticated",
			},
			accessDeniedPath: []string{
				"/protected/guest",
				"/protected/admin",
				"/protected/editor",
			},
		},
		{
			name:  "access with guest role",
			roles: []string{"guest", "anonymous"},
			accessGrantedPath: []string{
				"/version",
				"/dummy/jwt",
				"/protected/authenticated",
				"/protected/guest",
			},
			accessDeniedPath: []string{
				"/protected/viewer",
				"/protected/admin",
				"/protected/editor",
			},
		},
		{
			name:  "access as unauthenticated user",
			roles: []string{},
			accessGrantedPath: []string{
				"/version",
			},
			accessDeniedPath: []string{
				"/protected/viewer",
				"/protected/guest",
				"/protected/admin",
				"/protected/editor",
				"/protected/authenticated",
				"/dummy/jwt",
			},
			headers: map[string]string{
				"X-Forwarded-Host":  "app.contoso.com",
				"X-Forwarded-Port":  "443",
				"X-Forwarded-Proto": "https",
				"X-Real-Ip":         "10.11.12.14",
				"X-Request-Id":      "7a37b3b708b1497c95be8a6bf2a8274c",
			},
		},
		{
			name:  "access as unauthorized user no redirect",
			roles: []string{},
			unauthorizedPath: []string{
				"/protected/api",
			},
		},
		{
			name:  "access as unauthorized user with redirect",
			roles: []string{},
			unauthorizedPath: []string{
				"/protected/unauth",
			},
		},
	}

	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			got := make(map[string]interface{})
			want := make(map[string]interface{})
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatalf("failed to create cookiejar: %s", err)
			}
			tester.Client.Jar = jar
			cookies := []*http.Cookie{}
			if len(tc.roles) > 0 {
				if len(tc.unauthorizedPath) == 0 {
					usr := testutils.NewTestUser()
					usr.Claims.Roles = tc.roles
					msgs = append(msgs, fmt.Sprintf("roles: %s", tc.roles))
					signingKey := testutils.NewTestSigningKey()
					if err := signingKey.SignToken("HS512", usr); err != nil {
						t.Fatalf("Failed to get JWT token for %v: %v", usr.Claims, err)
					}
					msgs = append(msgs, fmt.Sprintf("token: %s", usr.Token))
					cookies = append(cookies, &http.Cookie{Name: "access_token", Value: usr.Token})
				}
				tester.Client.Jar.SetCookies(localhost, cookies)
			}
			for _, p := range tc.accessGrantedPath {
				msgs = append(msgs, fmt.Sprintf("accessing %s", p))
				want[p] = map[string]interface{}{
					"status_code": 200,
					"response":    expectedResponse[p],
				}
				resp, respBody := tester.AssertGetResponse(baseURL+p, 200, expectedResponse[p])
				got[p] = map[string]interface{}{
					"status_code": resp.StatusCode,
					"response":    respBody,
				}
			}
			for _, p := range tc.accessDeniedPath {
				msgs = append(msgs, fmt.Sprintf("accessing %s", p))
				var redirectURL string
				var redirectEnabled bool
				if !strings.Contains(tc.name, "role") {
					redirectEnabled = true
				}
				switch p {
				case "/protected/guest":
					redirectURL = baseURL + "/auth?redirect_url=" + url.QueryEscape(scheme+"://"+host+":"+securePort+p)
				case "/protected/authenticated":
					redirectURL = "https://auth.google.com/oauth2?redirect_url=" + url.QueryEscape(scheme+"://"+host+":"+securePort+p)
				default:
					redirectURL = baseURL + "/auth"
				}
				if redirectEnabled {
					want[p] = map[string]interface{}{
						"status_code": 302,
					}
					resp := tester.AssertRedirect(baseURL+p, redirectURL, 302)
					got[p] = map[string]interface{}{
						"status_code": resp.StatusCode,
					}
				} else {
					want[p] = map[string]interface{}{
						"status_code": 403,
					}
					resp, _ := tester.AssertGetResponse(baseURL+p, 403, "Forbidden")
					got[p] = map[string]interface{}{
						"status_code": resp.StatusCode,
					}
				}
			}
			for _, p := range tc.unauthorizedPath {
				msgs = append(msgs, fmt.Sprintf("accessing %s", p))
				if p == "/protected/api" {
					want[p] = map[string]interface{}{
						"status_code": 401,
						"response":    expectedResponse[p],
					}
					resp, respBody := tester.AssertGetResponse(baseURL+p, 401, expectedResponse[p])
					got[p] = map[string]interface{}{
						"status_code": resp.StatusCode,
						"response":    respBody,
					}
				} else {
					want[p] = map[string]interface{}{
						"status_code": 302,
					}
					var redirectURL = baseURL + "/auth?redirect_url=" + url.QueryEscape(scheme+"://"+host+":"+securePort+p)
					resp := tester.AssertRedirect(baseURL+p, redirectURL, 302)
					got[p] = map[string]interface{}{
						"status_code": resp.StatusCode,
					}
				}
			}
			tests.EvalObjectsWithLog(t, "responses", want, got, msgs)
		})
	}
	time.Sleep(1 * time.Second)
}
