package jwt

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"net/http"
	"os"
)

func init() {
	caddy.RegisterModule(AuthzProvider{})
}

// AuthzProvider authorizes access to endpoints based on
// the presense and content of JWT token.
type AuthzProvider struct {
	Name        string             `json:"-"`
	TokenName   string             `json:"token_name,omitempty"`
	TokenSecret string             `json:"token_secret,omitempty"`
	TokenIssuer string             `json:"token_issuer,omitempty"`
	AuthURLPath string             `json:"auth_url_path,omitempty"`
	AccessList  []*AccessListEntry `json:"access_list,omitempty"`
	CommonTokenParameters
	logger *zap.Logger `json:"-"`
}

// CommonTokenParameters represents commont token parameters
type CommonTokenParameters struct {
	AllowedTokenTypes   []string `json:"token_types,omitempty"`
	AllowedTokenSources []string `json:"token_sources,omitempty"`
	PassClaims          bool     `json:"pass_claims,omitempty"`
	StripToken          bool     `json:"strip_token,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthzProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(AuthzProvider) },
	}
}

// Provision provisions JWT authorization provider
func (m *AuthzProvider) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("provisioning plugin instance")
	m.Name = "jwt"
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthzProvider) Validate() error {
	if m.TokenName == "" {
		m.TokenName = "access_token"
	}
	m.logger.Info(
		"found JWT token name",
		zap.String("token_name", m.TokenName),
	)

	if m.TokenSecret == "" {
		if os.Getenv("JWT_TOKEN_SECRET") == "" {
			return fmt.Errorf("%s: token_secret must be defined either "+
				"via JWT_TOKEN_SECRET environment variable or "+
				"via token_secret configuration element",
				m.Name,
			)
		}
	}

	if m.TokenIssuer == "" {
		m.logger.Warn(
			"JWT token issuer not found, using default",
			zap.String("token_issuer", "localhost"),
		)
		m.TokenIssuer = "localhost"
	}

	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m AuthzProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	m.logger.Error(fmt.Sprintf("authenticating ... %v", r))
	return m.failAzureAuthentication(w, nil)
}

func (m AuthzProvider) failAzureAuthentication(w http.ResponseWriter, err error) (caddyauth.User, bool, error) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	return caddyauth.User{}, false, err
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthzProvider)(nil)
	_ caddy.Validator         = (*AuthzProvider)(nil)
	_ caddyauth.Authenticator = (*AuthzProvider)(nil)
)
