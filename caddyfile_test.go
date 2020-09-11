package jwt

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestCaddyfile(t *testing.T) {
	scheme := "http"
	host := "localhost"
	port := "8080"
	securePort := "8443"
	hostPort := host + ":" + port
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

	cookies := []*http.Cookie{}
	cookie := &http.Cookie{
		Name:  "access_token",
		Value: "anonymous",
	}
	cookies = append(cookies, cookie)
	tester.Client.Jar.SetCookies(localhost, cookies)

	req, _ := http.NewRequest("POST", baseURL+"/prometheus", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}
