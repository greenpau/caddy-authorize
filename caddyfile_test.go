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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	"github.com/greenpau/caddy-auth-jwt/internal/testutils"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParser(t *testing.T) {
	var testcases = []struct {
		name      string
		config    string
		shouldErr bool
		err       error
	}{
		{
			name: "auto generate crypto key",
			config: `
            jwt {
                primary yes
            }`,
		},
		{
			name: "default shared key in default context",
			config: `
			jwt {
			    context default
				primary yes
				crypto key token name "foobar token"
				crypto key verify foobar
				allow roles viewer editor with get to /internal/dashboard
				allow roles viewer editor with post
				allow audience https://localhost/ https://example.com/
				allow origin any
			}`,
		},
		{
			name: "multiple shared keys in default context",
			config: `
            jwt {
                context default
                primary yes
                crypto key token name "foobar token"
                crypto key verify foobar
                crypto key abc123 token name foobar_token
                crypto key abc123 verify foobar
            }`,
		},
		{
			name: "multiple shared keys in with implicit token name config",
			config: `
            jwt {
                context default
                primary yes
                crypto key verify foobar
                crypto key abc123 verify foobar
            }`,
		},
		{
			name: "multiple shared keys in with explicit default token name config",
			config: `
            jwt {
                context default
                primary yes
                crypto default token name jwt_token
                crypto key verify foobar
                crypto key abc123 verify foobar
                crypto key abc123 token name foobar_token
            }`,
		},
		{
			name: "enable valid request handling parameters",
			config: `
            jwt {
                context default
                primary yes
                crypto key verify foobar
                enable js redirect
                enable strip token
            }`,
		},
		{
			name: "enable invalid request handling parameters",
			config: `
            jwt {
                enable foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: unsupported directive for enable: foobar"),
		},
		{
			name: "configure header claim injection",
			config: `
            jwt {
                primary yes
                crypto key verify foobar
                inject headers with claims
            }`,
		},
		{
			name: "invalid crypto key config",
			config: `
            jwt {
                crypto default barfoo foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf(`Testfile:4 - Error during parsing: crypto key config error: key config entry "default barfoo foobar" is invalid: unknown default setting`),
		},
		{
			name: "crypto directive too short",
			config: `
            jwt {
                crypto foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf(`Testfile:3 - Error during parsing: crypto directive "foobar" is too short`),
		},
		{
			name: "crypto directive throws error",
			config: `
            jwt {
                crypto default foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf(`Testfile:3 - Error during parsing: crypto directive "default foobar" is too short`),
		},
		{
			name: "crypto directive throws unsupported error",
			config: `
            jwt {
                crypto foobar barfoo foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf(`Testfile:3 - Error during parsing: crypto directive value of "foobar barfoo foobar" is unsupported`),
		},
		{
			name: "configure invalid header claim injection",
			config: `
            jwt {
                inject foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: unsupported directive for inject: foobar"),
		},
		{
			name: "configure invalid top level keyword",
			config: `
            jwt {
			    primary no
                foobar barfoo
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:4 - Error during parsing: unsupported root directive: foobar"),
		},
		{
			name: "configure empty context",
			config: `
            jwt {
                context ""
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:4 - Error during parsing: context directive must not be empty"),
		},
		{
			name: "configure context without args",
			config: `
            jwt {
                context
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: context directive has no value"),
		},

		{
			name: "configure context with invalid args",
			config: `
            jwt {
                context foobar foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: context directive value of foobar is unsupported"),
		},
		{
			name: "configure empty primary context indicator",
			config: `
            jwt {
                primary ""
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: primary directive error: empty switch"),
		},
		{
			name: "configure invalid primary context indicator",
			config: `
            jwt {
                primary foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: primary directive error: invalid switch: foobar"),
		},
		{
			name: "set disable settings",
			config: `
            jwt {
                primary yes
                disable auth redirect query
                disable auth redirect
            }`,
		},
		{
			name: "set empty disable settings",
			config: `
            jwt {
                disable ""
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: disable directive has no value"),
		},
		{
			name: "set invalid disable settings",
			config: `
            jwt {
                disable "foobar"
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: disable directive \"foobar\" is unsupported"),
		},
		{
			name: "validate token parameters",
			config: `
            jwt {
                primary yes
                validate path acl
                validate source address
                validate bearer header
            }`,
		},
		{
			name: "empty validate token settings",
			config: `
            jwt {
                validate ""
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: validate directive has no value"),
		},
		{
			name: "set invalid disable settings",
			config: `
            jwt {
                validate foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: validate directive \"foobar\" is unsupported"),
		},
		{
			name: "set general settings",
			config: `
            jwt {
                primary yes
                set token sources header
                set auth url /xauth
                set forbidden url /forbidden.html
                set user identity mail
            }`,
		},
		{
			name: "empty validate set settings",
			config: `
            jwt {
                set ""
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: set directive has no value"),
		},
		{
			name: "set invalid settings",
			config: `
            jwt {
                set foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: set directive \"foobar\" is unsupported"),
		},
		{
			name: "empty acl shortcut",
			config: `
            jwt {
                allow
            }`,
			shouldErr: true,
			err:       fmt.Errorf("Testfile:3 - Error during parsing: allow directive has no value"),
		},
		{
			name: "invalid acl shortcut",
			config: `
            jwt {
                allow roles
            }`,
			shouldErr: true,
			err:       fmt.Errorf(`Testfile:3 - Error during parsing: allow directive "roles" is too short`),
		},
		{
			name: "invalid acl shortcut args",
			config: `
            jwt {
                allow roles foobar with post to /foobar foobar
            }`,
			shouldErr: true,
			err:       fmt.Errorf(`Testfile:3 - Error during parsing: allow directive value of "roles foobar with post to /foobar foobar" is unsupported`),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %s", tc.config))
			h := httpcaddyfile.Helper{
				Dispenser: caddyfile.NewTestDispenser(tc.config),
			}
			handler, err := parseCaddyfile(h)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			if handler == nil {
				t.Fatalf("handler is nil")
			}

		})
	}
}

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
		  crypto key foobar1 token name `+tokenName+`
		  crypto key foobar1 verify `+testutils.GetSharedKey()+`
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

					ks := testutils.NewTestCryptoKeyStore()
					if err := ks.SignToken("access_token", "HS512", usr); err != nil {
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
