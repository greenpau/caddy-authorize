package jwt

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	jwtlib "github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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
	tokenSecret := "0e2fdcf8-6868-41a7-884b-7308795fc286"
	tokenIssuer := "e1008f2d-ccfa-4e62-bbe6-c202ec2988cc"
	localhost, _ := url.Parse(baseURL)
	tester := caddytest.NewTester(t)
	tester.InitServer(`
    {
      http_port     `+port+`
      https_port    `+securePort+`
	  debug
    }

    `+hostPort+` {
      route /dummy/jwt* {
        jwt {
          primary yes
		  trusted_tokens {
		    static_secret {
              token_name `+tokenName+`
		      token_secret `+tokenSecret+`
		      token_issuer `+tokenIssuer+`
			}
          }
		  auth_url /auth
		  allow roles *
		}
        respond * "caddy jwt plugin" 200
      }

      route /protected/viewer* {
	    jwt {
		  allow roles admin editor viewer
		}
        respond * "viewers, editors, and administrators" 200
      }

      route /protected/editor* {
	    jwt {
		  allow roles admin editor
		}
        respond * "editors and administrators" 200
      }

      route /protected/admin* {
        jwt {
		  allow roles admin
		}
        respond * "administrators only" 200
      }

      route /protected/authenticated* {
        jwt {
		  allow roles admin editor viewer anonymous guest
		}
        respond * "authenticated users only" 200
      }

      route /protected/guest* {
        jwt {
		  allow roles anonymous guest
		}
        respond * "guests only" 200
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
		"/version":                 "1.0.0",
		"/auth":                    "caddy auth portal plugin",
		"/dummy/jwt":               "caddy jwt plugin",
		"/protected/viewer":        "viewers, editors, and administrators",
		"/protected/editor":        "editors and administrators",
		"/protected/admin":         "administrators only",
		"/protected/authenticated": "authenticated users only",
		"/protected/guest":         "guests only",
	}

	var tests = []struct {
		name              string
		roles             []string
		accessGrantedPath []string
		accessDeniedPath  []string
	}{
		{
			name:  "access with admin role",
			roles: []string{"admin"},
			accessGrantedPath: []string{
				"/version",
				"/dummy/jwt",
				"/protected/viewer",
				"/protected/editor",
				"/protected/admin",
				"/protected/authenticated",
			},
			accessDeniedPath: []string{
				"/protected/guest",
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
			},
			accessDeniedPath: []string{
				"/protected/viewer",
				"/protected/guest",
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
		},
	}

	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testFailed bool
			t.Logf("test: %s", test.name)
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatalf("failed to create cookiejar: %s", err)
			}
			tester.Client.Jar = jar
			cookies := []*http.Cookie{}
			if len(test.roles) > 0 {
				claims := jwtlib.MapClaims{
					"exp":    time.Now().Add(10 * time.Minute).Unix(),
					"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
					"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					"name":   "Smith, John",
					"email":  "smithj@outlook.com",
					"origin": "localhost",
					"sub":    "smithj@outlook.com",
					"roles":  test.roles,
				}

				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS512, claims)
				tokenString, err := token.SignedString([]byte(tokenSecret))
				if err != nil {
					t.Fatalf("bad token signing: %v", err)
				}

				cookie := &http.Cookie{
					Name:  "access_token",
					Value: tokenString,
				}
				t.Logf("Token string: %s", tokenString)
				cookies = append(cookies, cookie)
				tester.Client.Jar.SetCookies(localhost, cookies)
			}
			for _, p := range test.accessGrantedPath {
				t.Logf("test: %s, accessing %s", test.name, p)
				resp, respBody := tester.AssertGetResponse(baseURL+p, 200, expectedResponse[p])
				if respBody != expectedResponse[p] {
					testFailed = true
				}
				if resp.StatusCode != 200 {
					testFailed = true
				}
			}
			for _, p := range test.accessDeniedPath {
				t.Logf("test: %s, accessing %s", test.name, p)
				resp := tester.AssertRedirect(baseURL+p, baseURL+"/auth", 302)
				if resp.StatusCode != 302 {
					t.Logf("status code: %d", resp.StatusCode)
					testFailed = true
				}
			}
			if testFailed {
				t.Fatalf("FAILED: %s", test.name)
			}
		})
	}

	t.Logf("Finished testing")

	time.Sleep(1 * time.Second)
}
