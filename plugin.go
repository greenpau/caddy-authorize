package jwt

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
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
	logger         *zap.Logger     `json:"-"`
	TokenValidator *TokenValidator `json:"-"`
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
	if m.TokenValidator == nil {
		m.TokenValidator = NewTokenValidator()
	}
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

	m.TokenValidator.TokenName = m.TokenName
	m.TokenValidator.TokenSecret = m.TokenSecret
	m.TokenValidator.TokenIssuer = m.TokenIssuer
	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		return fmt.Errorf("%s: backend validation error: %s", m.Name, err)
	}

	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m AuthzProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	if reqDump, err := httputil.DumpRequest(r, true); err == nil {
		m.logger.Debug(fmt.Sprintf("request: %s", reqDump))
	}
	userClaims, validUser, err := m.TokenValidator.Authorize(r)
	if err != nil {
		m.logger.Debug(
			"token validation error",
			zap.String("error", err.Error()),
		)
		w.WriteHeader(401)
		w.Write([]byte(`Unauthorized`))
		return caddyauth.User{}, false, err
	}
	if !validUser {
		m.logger.Debug(
			"token validation error",
			zap.String("error", "invalid user"),
		)
		w.WriteHeader(401)
		w.Write([]byte(`Unauthorized User`))
		return caddyauth.User{}, false, nil
	}

	if userClaims == nil {
		m.logger.Debug(
			"token validation error",
			zap.String("error", "nil claims"),
		)
		w.WriteHeader(401)
		w.Write([]byte(`User Unauthorized`))
		return caddyauth.User{}, false, nil
	}

	userIdentity := caddyauth.User{
		ID: userClaims.Email,
		Metadata: map[string]string{
			"roles": strings.Join(userClaims.Roles, " "),
		},
	}

	if userClaims.Name != "" {
		userIdentity.Metadata["name"] = userClaims.Name
	}
	if userClaims.Email != "" {
		userIdentity.Metadata["email"] = userClaims.Email
	}

	return userIdentity, true, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthzProvider)(nil)
	_ caddy.Validator         = (*AuthzProvider)(nil)
	_ caddyauth.Authenticator = (*AuthzProvider)(nil)
)
