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

package authz

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/handlers"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/validator"
	"go.uber.org/zap"
)

// Authorizer authorizes access to endpoints based on
// the presense and content of JWT token.
type Authorizer struct {
	Name                        string                   `json:"-"`
	Context                     string                   `json:"context,omitempty" xml:"context,omitempty" yaml:"context,omitempty"`
	PrimaryInstance             bool                     `json:"primary,omitempty" xml:"primary,omitempty" yaml:"primary,omitempty"`
	AuthURLPath                 string                   `json:"auth_url_path,omitempty" xml:"auth_url_path,omitempty" yaml:"auth_url_path,omitempty"`
	AuthRedirectDisabled        bool                     `json:"disable_auth_redirect,omitempty" xml:"disable_auth_redirect,omitempty" yaml:"disable_auth_redirect,omitempty"`
	AuthRedirectQueryDisabled   bool                     `json:"disable_auth_redirect_query,omitempty" xml:"disable_auth_redirect_query,omitempty" yaml:"disable_auth_redirect_query,omitempty"`
	AuthRedirectQueryParameter  string                   `json:"auth_redirect_query_param,omitempty" xml:"auth_redirect_query_param,omitempty" yaml:"auth_redirect_query_param,omitempty"`
	RedirectWithJavascript      bool                     `json:"redirect_with_javascript,omitempty" xml:"redirect_with_javascript,omitempty" yaml:"redirect_with_javascript,omitempty"`
	AccessListRules             []*acl.RuleConfiguration `json:"access_list_rules,omitempty" xml:"access_list_rules,omitempty" yaml:"access_list_rules,omitempty"`
	CryptoKeyConfigs            []*kms.CryptoKeyConfig   `json:"crypto_key_configs,omitempty" xml:"crypto_key_configs,omitempty" yaml:"crypto_key_configs,omitempty"`
	AllowedTokenSources         []string                 `json:"allowed_token_sources,omitempty" xml:"allowed_token_sources,omitempty" yaml:"allowed_token_sources,omitempty"`
	StripTokenEnabled           bool                     `json:"strip_token_enabled,omitempty" xml:"strip_token_enabled,omitempty" yaml:"strip_token_enabled,omitempty"`
	ForbiddenURL                string                   `json:"forbidden_url,omitempty" xml:"forbidden_url,omitempty" yaml:"forbidden_url,omitempty"`
	UserIdentityField           string                   `json:"user_identity_field,omitempty" xml:"user_identity_field,omitempty" yaml:"user_identity_field,omitempty"`
	ValidateBearerHeader        bool                     `json:"validate_bearer_header,omitempty" xml:"validate_bearer_header,omitempty" yaml:"validate_bearer_header,omitempty"`
	ValidateMethodPath          bool                     `json:"validate_method_path,omitempty" xml:"validate_method_path,omitempty" yaml:"validate_method_path,omitempty"`
	ValidateAccessListPathClaim bool                     `json:"validate_access_list_path_claim,omitempty" xml:"validate_access_list_path_claim,omitempty" yaml:"validate_access_list_path_claim,omitempty"`
	ValidateSourceAddress       bool                     `json:"validate_source_address,omitempty" xml:"validate_source_address,omitempty" yaml:"validate_source_address,omitempty"`
	PassClaimsWithHeaders       bool                     `json:"pass_claims_with_headers,omitempty" xml:"pass_claims_with_headers,omitempty" yaml:"pass_claims_with_headers,omitempty"`
	tokenValidator              *validator.TokenValidator
	opts                        *options.TokenValidatorOptions
	accessList                  *acl.AccessList
	logger                      *zap.Logger
	startedAt                   time.Time
	primaryInstanceName         string
}

// Provision provisions JWT authorization provider instances.
func (m *Authorizer) Provision(upstreamOptions map[string]interface{}) error {
	ctx := context.Background()
	if _, exists := upstreamOptions["logger"]; !exists {
		return fmt.Errorf("configuration requires valid logger")
	}
	m.logger = upstreamOptions["logger"].(*zap.Logger)
	m.startedAt = time.Now().UTC()
	if err := AuthManager.Register(ctx, m); err != nil {
		return err
	}
	m.logger.Info(
		"provisioned plugin instance",
		zap.String("instance_name", m.Name),
		zap.Time("started_at", m.startedAt),
	)
	return nil
}

// Validate implements caddy.Validator.
func (m *Authorizer) Validate() error {
	ctx := context.Background()
	if err := AuthManager.Validate(ctx, m); err != nil {
		return err
	}
	m.logger.Info(
		"validated plugin instance",
		zap.String("instance_name", m.Name),
	)
	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m Authorizer) Authenticate(w http.ResponseWriter, r *http.Request, upstreamOptions map[string]interface{}) (map[string]interface{}, bool, error) {
	ctx := context.Background()
	usr, err := m.tokenValidator.Authorize(ctx, r)
	if err != nil {
		m.logger.Debug(
			"token validation error",
			zap.String("error", err.Error()),
		)
		if strings.Contains(err.Error(), "user role is valid, but not allowed by") {
			if m.ForbiddenURL != "" {
				w.Header().Set("Location", m.ForbiddenURL)
				w.WriteHeader(303)
			} else {
				w.WriteHeader(403)
			}
			w.Write([]byte(`Forbidden`))
			return nil, false, err
		}
		tvCookies := m.tokenValidator.GetAuthCookies()
		if tvCookies != nil {
			for _, cookie := range r.Cookies() {
				if _, exists := tvCookies[cookie.Name]; exists {
					w.Header().Add("Set-Cookie", cookie.Name+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
				}
			}
		}
		if !m.AuthRedirectDisabled {
			redirOpts := make(map[string]interface{})
			redirOpts["auth_url_path"] = m.AuthURLPath
			redirOpts["auth_redirect_query_disabled"] = m.AuthRedirectQueryDisabled
			redirOpts["redirect_param"] = m.AuthRedirectQueryParameter
			//redirOpts["logger"] = m.logger
			if m.RedirectWithJavascript {
				handlers.HandleJSRedirect(w, r, redirOpts)
			} else {
				handlers.HandleHeaderRedirect(w, r, redirOpts)
			}
		}
		return nil, false, err
	}

	if usr.Cached {
		if m.PassClaimsWithHeaders {
			for k, v := range usr.GetRequestHeaders() {
				r.Header.Set(k, v)
			}
		}
		// TODO(greenpau): implement strip token enabled.
		// if m.StripTokenEnabled {
		// }
		return usr.GetRequestIdentity(), true, nil
	}

	if m.PassClaimsWithHeaders {
		headers := make(map[string]string)
		if usr.Claims.Name != "" {
			headers["X-Token-User-Name"] = usr.Claims.Name
		}
		if usr.Claims.Email != "" {
			headers["X-Token-User-Email"] = usr.Claims.Email
		}
		if len(usr.Claims.Roles) > 0 {
			headers["X-Token-User-Roles"] = strings.Join(usr.Claims.Roles, " ")
		}
		if usr.Claims.Subject != "" {
			headers["X-Token-Subject"] = usr.Claims.Subject
		}
		usr.SetRequestHeaders(headers)
	}

	userIdentity := make(map[string]interface{})
	userIdentity["roles"] = strings.Join(usr.Claims.Roles, " ")
	if usr.Claims.ID != "" {
		userIdentity["claim_id"] = usr.Claims.ID
	}
	if usr.Claims.Subject != "" {
		userIdentity["sub"] = usr.Claims.Subject
	}
	if usr.Claims.Email != "" {
		userIdentity["email"] = usr.Claims.Email
	}

	switch m.UserIdentityField {
	case "sub", "subject":
		userIdentity["id"] = usr.Claims.Subject
	case "id":
		userIdentity["id"] = usr.Claims.ID
	default:
		if usr.Claims.Email == "" {
			userIdentity["id"] = usr.Claims.Subject
		} else {
			userIdentity["id"] = usr.Claims.Email
		}
	}

	if usr.Claims.Name != "" {
		userIdentity["name"] = usr.Claims.Name
	}
	if usr.Claims.Email != "" {
		userIdentity["email"] = usr.Claims.Email
	}
	usr.SetRequestIdentity(userIdentity)

	if err := m.tokenValidator.CacheUser(usr); err != nil {
		m.logger.Error(
			"token caching error",
			zap.String("error", err.Error()),
		)
	}

	// TODO(greenpau): implement strip token enabled.
	// if m.StripTokenEnabled {
	// }

	return userIdentity, true, nil
}
