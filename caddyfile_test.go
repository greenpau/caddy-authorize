package jwt

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"
)

func TestCaddyfile(t *testing.T) {
	scheme := "https"
	host := "localhost"
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
        respond * "protected" 200
      }

      route /protected/editor* {
	    jwt {
		  allow roles admin editor
		}
        respond * "protected" 200
      }

      route /protected/admin* {
        jwt {
		  allow roles admin
		}
        respond * "protected" 200
      }

      route /protected/authenticated* {
        jwt {
		  allow roles admin editor viewer anonymous guest
		}
        respond * "protected" 200
      }

      route /protected/guest* {
        jwt {
		  allow roles anonymous guest
		}
        respond * "protected" 200
      }

	  route /auth* {
        respond * "caddy auth portal plugin" 200
	  }

      route /version* {
        respond * "1.0.0" 200
      }
    }
    `, "caddyfile")

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
				"/version", "/auth",
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
				"/version", "/auth",
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
				"/version", "/auth",
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
				"/version", "/auth",
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
				"/version", "/auth",
				"/dummy/jwt",
			},
			accessDeniedPath: []string{
				"/protected/viewer",
				"/protected/guest",
				"/protected/admin",
				"/protected/editor",
				"/protected/authenticated",
			},
		},
	}

	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			t.Logf("test: %s", test.name)
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatalf("failed to create cookiejar: %s", err)
			}
			tester.Client.Jar = jar
			cookies := []*http.Cookie{}
			if len(test.roles) > 0 {
				cookie := &http.Cookie{
					Name:  "access_token",
					Value: "anonymous",
				}
				cookies = append(cookies, cookie)
				tester.Client.Jar.SetCookies(localhost, cookies)
			}
			for _, p := range test.accessGrantedPath {
				t.Logf("test: %s, accessing %s", test.name, p)
				req, _ := http.NewRequest("GET", baseURL+p, nil)
				resp := tester.AssertResponseCode(req, 200)
				t.Logf("%v", resp)
				//time.Sleep(5 * time.Second)
			}
			for _, p := range test.accessDeniedPath {
				t.Logf("test: %s, accessing %s", test.name, p)
				req, _ := http.NewRequest("GET", baseURL+p, nil)
				resp := tester.AssertResponseCode(req, 400)
				t.Logf("%v", resp)
				//time.Sleep(5 * time.Second)
			}
		})
	}

	t.Logf("Finished testing")

	time.Sleep(1 * time.Second)
}
