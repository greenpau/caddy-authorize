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

package auth

import (
	"fmt"
	jwtacl "github.com/greenpau/caddy-auth-jwt/pkg/acl"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	jwthandlers "github.com/greenpau/caddy-auth-jwt/pkg/handlers"
	jwtvalidator "github.com/greenpau/caddy-auth-jwt/pkg/validator"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

// Authorizer authorizes access to endpoints based on
// the presense and content of JWT token.
type Authorizer struct {
	Name                       string                           `json:"-"`
	Provisioned                bool                             `json:"-"`
	ProvisionFailed            bool                             `json:"-"`
	Context                    string                           `json:"context,omitempty"`
	PrimaryInstance            bool                             `json:"primary,omitempty"`
	AuthURLPath                string                           `json:"auth_url_path,omitempty"`
	AuthRedirectQueryDisabled  bool                             `json:"disable_auth_redirect_query,omitempty"`
	AuthRedirectQueryParameter string                           `json:"auth_redirect_query_param,omitempty"`
	AccessList                 []*jwtacl.AccessListEntry        `json:"access_list,omitempty"`
	TrustedTokens              []*jwtconfig.CommonTokenConfig   `json:"trusted_tokens,omitempty"`
	TokenValidator             *jwtvalidator.TokenValidator     `json:"-"`
	TokenValidatorOptions      *jwtconfig.TokenValidatorOptions `json:"token_validate_options,omitempty"`
	AllowedTokenTypes          []string                         `json:"token_types,omitempty"`
	AllowedTokenSources        []string                         `json:"token_sources,omitempty"`
	PassClaims                 bool                             `json:"pass_claims,omitempty"`
	StripToken                 bool                             `json:"strip_token,omitempty"`
	ForbiddenURL               string                           `json:"forbidden_url,omitempty"`
	UserIdentityField          string                           `json:"user_identity_field,omitempty"`

	ValidateMethodPath          bool `json:"validate_method_path,omitempty"`
	ValidateAccessListPathClaim bool `json:"validate_acl_path_claim,omitempty"`

	PassClaimsWithHeaders bool `json:"pass_claims_with_headers,omitempty"`

	logger    *zap.Logger
	startedAt time.Time
}

// Provision provisions JWT authorization provider
func (m *Authorizer) Provision(upstreamOptions map[string]interface{}) error {
	if _, exists := upstreamOptions["logger"]; !exists {
		return fmt.Errorf("configuration requires valid logger")
	}
	m.logger = upstreamOptions["logger"].(*zap.Logger)
	m.startedAt = time.Now().UTC()
	if err := AuthManager.Register(m); err != nil {
		return fmt.Errorf(
			"authentication provider registration error, instance %s, error: %s",
			m.Name, err,
		)
	}
	if m.PrimaryInstance {
		m.logger.Info(
			"provisioned plugin instance",
			zap.String("instance_name", m.Name),
			zap.Time("started_at", m.startedAt),
		)
	}
	return nil
}

// Validate implements caddy.Validator.
func (m *Authorizer) Validate() error {
	m.logger.Info(
		"validated plugin instance",
		zap.String("instance_name", m.Name),
	)
	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m Authorizer) Authenticate(w http.ResponseWriter, r *http.Request, upstreamOptions map[string]interface{}) (map[string]interface{}, bool, error) {
	/*
		var reqID string
		if _, exists := upstreamOptions["request_id"]; exists {
			reqID = upstreamOptions["request_id"].(string)
		} else {
			reqID = uuid.NewV4().String()
		}
	*/

	if m.ProvisionFailed {
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return nil, false, jwterrors.ErrProvisonFailed
	}

	if !m.Provisioned {
		provisionedInstance, err := AuthManager.Provision(m.Name)
		if err != nil {
			m.logger.Error(
				"authorization provider provisioning error",
				zap.String("instance_name", m.Name),
				zap.String("error", err.Error()),
			)
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return nil, false, err
		}
		m = *provisionedInstance
	}

	var opts *jwtconfig.TokenValidatorOptions
	if m.ValidateMethodPath {
		opts = m.TokenValidatorOptions.Clone()
		opts.Metadata["method"] = r.Method
		opts.Metadata["path"] = r.URL.Path
	} else {
		opts = m.TokenValidatorOptions
	}

	userClaims, validUser, err := m.TokenValidator.Authorize(r, opts)
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
		for k := range m.TokenValidator.Cookies {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		redirOpts := make(map[string]interface{})
		redirOpts["auth_url_path"] = m.AuthURLPath
		redirOpts["auth_redirect_query_disabled"] = m.AuthRedirectQueryDisabled
		redirOpts["redirect_param"] = m.AuthRedirectQueryParameter
		//redirOpts["logger"] = m.logger
		jwthandlers.AddRedirectLocationHeader(w, r, redirOpts)
		w.WriteHeader(302)
		w.Write([]byte(`Unauthorized`))
		return nil, false, err
	}
	if !validUser {
		m.logger.Debug(
			"token validation error",
			zap.String("error", "user invalid"),
		)
		for k := range m.TokenValidator.Cookies {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		redirOpts := make(map[string]interface{})
		redirOpts["auth_url_path"] = m.AuthURLPath
		redirOpts["auth_redirect_query_disabled"] = m.AuthRedirectQueryDisabled
		redirOpts["redirect_param"] = m.AuthRedirectQueryParameter
		//redirOpts["logger"] = m.logger
		jwthandlers.AddRedirectLocationHeader(w, r, redirOpts)
		w.WriteHeader(302)
		w.Write([]byte(`Unauthorized User`))
		return nil, false, nil
	}

	if userClaims == nil {
		m.logger.Debug(
			"token validation error",
			zap.String("error", "nil claims"),
		)
		for k := range m.TokenValidator.Cookies {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		redirOpts := make(map[string]interface{})
		redirOpts["auth_url_path"] = m.AuthURLPath
		redirOpts["auth_redirect_query_disabled"] = m.AuthRedirectQueryDisabled
		redirOpts["redirect_param"] = m.AuthRedirectQueryParameter
		//redirOpts["logger"] = m.logger
		jwthandlers.AddRedirectLocationHeader(w, r, redirOpts)
		w.WriteHeader(302)
		w.Write([]byte(`User Unauthorized`))
		return nil, false, nil
	}

	userIdentity := make(map[string]interface{})

	userIdentity["roles"] = strings.Join(userClaims.Roles, " ")

	if userClaims.ID != "" {
		userIdentity["claim_id"] = userClaims.ID
	}
	if userClaims.Subject != "" {
		userIdentity["sub"] = userClaims.Subject
	}
	if userClaims.Email != "" {
		userIdentity["email"] = userClaims.Email
	}

	switch m.UserIdentityField {
	case "sub", "subject":
		userIdentity["id"] = userClaims.Subject
	case "id":
		userIdentity["id"] = userClaims.ID
	default:
		userIdentity["id"] = userClaims.Email
		if userClaims.Email == "" {
			userIdentity["id"] = userClaims.Subject
		}
	}

	if userClaims.Name != "" {
		userIdentity["name"] = userClaims.Name
		if m.PassClaimsWithHeaders {
			r.Header.Set("X-Token-User-Name", userClaims.Name)
		}
	}

	if userClaims.Email != "" {
		userIdentity["email"] = userClaims.Email
		if m.PassClaimsWithHeaders {
			r.Header.Set("X-Token-User-Email", userClaims.Email)
		}
	}

	if m.PassClaimsWithHeaders {
		if len(userClaims.Roles) > 0 {
			r.Header.Set("X-Token-User-Roles", strings.Join(userClaims.Roles, " "))
		}
		if userClaims.Subject != "" {
			r.Header.Set("X-Token-Subject", userClaims.Subject)
		}
	}

	return userIdentity, true, nil
}
