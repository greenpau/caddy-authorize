package jwt

import (
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
)

// Plugin Errors
const (
	ErrProvisonFailed strError = "authorization provider provisioning error"
)

// ProviderPool is the global authorization provider pool.
// It provides access to all instances of JWT plugin.
var ProviderPool *AuthProviderPool

func init() {
	ProviderPool = &AuthProviderPool{}
	caddy.RegisterModule(AuthProvider{})
}

// AuthProvider authorizes access to endpoints based on
// the presense and content of JWT token.
type AuthProvider struct {
	mu              sync.Mutex
	Name            string             `json:"-"`
	Provisioned     bool               `json:"-"`
	ProvisionFailed bool               `json:"-"`
	Context         string             `json:"context,omitempty"`
	Master          bool               `json:"master,omitempty"`
	TokenName       string             `json:"token_name,omitempty"`
	TokenSecret     string             `json:"token_secret,omitempty"`
	TokenIssuer     string             `json:"token_issuer,omitempty"`
	AuthURLPath     string             `json:"auth_url_path,omitempty"`
	AccessList      []*AccessListEntry `json:"access_list,omitempty"`
	CommonTokenParameters
	TokenValidator *TokenValidator `json:"-"`

	RSASignMethodConfig

	logger    *zap.Logger
	tokenKeys map[string]interface{} // the value must be a *rsa.PrivateKey or *rsa.PublicKey
}

// CommonTokenParameters represents commont token parameters
type CommonTokenParameters struct {
	AllowedTokenTypes   []string `json:"token_types,omitempty"`
	AllowedTokenSources []string `json:"token_sources,omitempty"`
	PassClaims          bool     `json:"pass_claims,omitempty"`
	StripToken          bool     `json:"strip_token,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(AuthProvider) },
	}
}

// Provision provisions JWT authorization provider
func (m *AuthProvider) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	ProviderPool.Register(m)
	if m.Master {
		m.logger.Info(
			"provisioned plugin instance",
			zap.String("instance_name", m.Name),
		)
	}
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthProvider) Validate() error {
	m.logger.Info(
		"validated plugin instance",
		zap.String("instance_name", m.Name),
	)
	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m AuthProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	//if reqDump, err := httputil.DumpRequest(r, true); err == nil {
	//	m.logger.Debug(fmt.Sprintf("request: %s", reqDump))
	//}

	if m.ProvisionFailed {
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return caddyauth.User{}, false, ErrProvisonFailed
	}

	if !m.Provisioned {
		if err := ProviderPool.Provision(m.Name); err != nil {
			m.logger.Error(
				"authorization provider provisioning error",
				zap.String("instance_name", m.Name),
				zap.String("error", err.Error()),
			)
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return caddyauth.User{}, false, err
		}
	}

	userClaims, validUser, err := m.TokenValidator.Authorize(r)
	if err != nil {
		m.logger.Debug(
			"token validation error",
			zap.String("error", err.Error()),
		)
		for k := range m.TokenValidator.Cookies {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(302)
		w.Write([]byte(`Unauthorized`))
		return caddyauth.User{}, false, err
	}
	if !validUser {
		m.logger.Debug(
			"token validation error",
			zap.String("error", "user invalid"),
		)
		for k := range m.TokenValidator.Cookies {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(302)
		w.Write([]byte(`Unauthorized User`))
		return caddyauth.User{}, false, nil
	}

	if userClaims == nil {
		m.logger.Debug(
			"token validation error",
			zap.String("error", "nil claims"),
		)
		for k := range m.TokenValidator.Cookies {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(302)
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
	_ caddy.Provisioner       = (*AuthProvider)(nil)
	_ caddy.Validator         = (*AuthProvider)(nil)
	_ caddyauth.Authenticator = (*AuthProvider)(nil)
)
