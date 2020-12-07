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
	jwtvalidator "github.com/greenpau/caddy-auth-jwt/pkg/validator"
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"
)

// AuthManager is the global authorization provider pool.
// It provides access to all instances of JWT plugin.
var AuthManager *InstanceManager

func init() {
	AuthManager = &InstanceManager{}
}

// InstanceManager provides access to all instances of the plugin.
type InstanceManager struct {
	mu               sync.Mutex
	Members          []*Authorizer
	RefMembers       map[string]*Authorizer
	PrimaryInstances map[string]*Authorizer
	MemberCount      int
}

// Register registers authorization provider instance with the pool.
func (p *InstanceManager) Register(m *Authorizer) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if m.Name == "" {
		p.MemberCount++
		m.Name = fmt.Sprintf("jwt-%d", p.MemberCount)
	}
	if p.RefMembers == nil {
		p.RefMembers = make(map[string]*Authorizer)
	}
	if _, exists := p.RefMembers[m.Name]; !exists {
		p.RefMembers[m.Name] = m
		p.Members = append(p.Members, m)
	}
	if m.Context == "" {
		m.Context = "default"
	}
	if p.PrimaryInstances == nil {
		p.PrimaryInstances = make(map[string]*Authorizer)
	}

	if m.PrimaryInstance {
		if _, ok := p.PrimaryInstances[m.Context]; ok {
			// The time different check is necessary to determine whether this is a configuration
			// load or reload. Typically, the provisioning of a plugin would happen in a second.
			timeDiff := m.startedAt.Sub(p.PrimaryInstances[m.Context].startedAt).Milliseconds()
			if timeDiff < 1000 {
				return jwterrors.ErrTooManyPrimaryInstances.WithArgs(m.Context)
			}
		}

		p.PrimaryInstances[m.Context] = m

		// Check that primary instance has trusted tokens
		if len(m.TrustedTokens) == 0 {
			return jwterrors.ErrNoTrustedTokensFound.WithArgs(m.Name)
		}

		allowedTokenNames := make(map[string]bool)

		// Iterate over trusted tokens
		for _, entry := range m.TrustedTokens {
			if entry == nil {
				continue
			}

			if entry.TokenName != "" {
				allowedTokenNames[entry.TokenName] = true
			}

			if entry.TokenLifetime == 0 {
				entry.TokenLifetime = 900
			}

			if !entry.HasRSAKeys() && entry.TokenSecret == "" {
				entry.TokenSecret = os.Getenv(jwtconfig.EnvTokenSecret)
				if entry.TokenSecret == "" {
					return jwterrors.ErrUndefinedSecret.WithArgs(m.Name)
				}
			}
		}

		if m.AuthURLPath == "" {
			m.AuthURLPath = "/auth"
		}

		if m.AuthRedirectQueryParameter == "" {
			m.AuthRedirectQueryParameter = "redirect_url"
		}

		if len(m.AccessList) == 0 {
			entry := jwtacl.NewAccessListEntry()
			entry.Allow()
			if err := entry.SetClaim("roles"); err != nil {
				return jwterrors.ErrInvalidConfiguration.WithArgs(m.Name, err)
			}

			for _, v := range []string{"anonymous", "guest"} {
				if err := entry.AddValue(v); err != nil {
					return jwterrors.ErrInvalidConfiguration.WithArgs(m.Name, err)
				}
			}
			m.AccessList = append(m.AccessList, entry)
		}

		for i, entry := range m.AccessList {
			if err := entry.Validate(); err != nil {
				return jwterrors.ErrInvalidConfiguration.WithArgs(m.Name, err)
			}
			if len(entry.Methods) > 0 || entry.Path != "" {
				m.ValidateMethodPath = true
			}
			m.logger.Debug(
				"JWT access list entry",
				zap.String("instance_name", m.Name),
				zap.Int("seq_id", i),
				zap.Any("acl", entry),
			)
		}

		if len(m.AllowedTokenTypes) == 0 {
			m.AllowedTokenTypes = append(m.AllowedTokenTypes, "HS512")
		}

		for _, tt := range m.AllowedTokenTypes {
			if _, exists := jwtconfig.SigningMethods[tt]; !exists {
				return jwterrors.ErrUnsupportedSignatureMethod.WithArgs(m.Name, tt)
			}
		}

		if len(m.AllowedTokenSources) == 0 {
			m.AllowedTokenSources = jwtvalidator.AllTokenSources
		}

		for _, ts := range m.AllowedTokenSources {
			if _, exists := jwtvalidator.TokenSources[ts]; !exists {
				return jwterrors.ErrUnsupportedTokenSource.WithArgs(m.Name, ts)
			}
		}

		if m.TokenValidator == nil {
			m.TokenValidator = jwtvalidator.NewTokenValidator()
		}

		if m.TokenValidatorOptions == nil {
			m.TokenValidatorOptions = jwtconfig.NewTokenValidatorOptions()
		}

		if m.ValidateMethodPath {
			m.TokenValidatorOptions.ValidateMethodPath = true
		}

		if m.ValidateAccessListPathClaim {
			m.TokenValidatorOptions.ValidateAccessListPathClaim = true
		}

		for tokenName := range allowedTokenNames {
			m.TokenValidator.SetTokenName(tokenName)
		}
		m.TokenValidator.AccessList = m.AccessList
		m.TokenValidator.TokenSources = m.AllowedTokenSources
		m.TokenValidator.TokenConfigs = m.TrustedTokens

		if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
			return jwterrors.ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
		}

		m.logger.Debug(
			"JWT token configuration provisioned",
			zap.String("instance_name", m.Name),
			zap.Any("trusted_tokens", m.TrustedTokens),
			zap.String("auth_url_path", m.AuthURLPath),
			zap.String("token_sources", strings.Join(m.AllowedTokenSources, " ")),
			zap.String("token_types", strings.Join(m.AllowedTokenTypes, " ")),
			zap.Any("token_validator", m.TokenValidator),
			zap.Any("token_validator_options", m.TokenValidatorOptions),
			zap.String("forbidden_path", m.ForbiddenURL),
		)

		m.Provisioned = true
	}
	return nil
}

// Provision provisions non-primaryInstance instances in an authorization context.
func (p *InstanceManager) Provision(name string) (*Authorizer, error) {
	if name == "" {
		return nil, jwterrors.ErrEmptyProviderName
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.RefMembers == nil {
		return nil, jwterrors.ErrNoMemberReference
	}
	m, exists := p.RefMembers[name]
	if !exists {
		return nil, jwterrors.ErrUnknownProvider.WithArgs(name)
	}
	if m == nil {
		return nil, jwterrors.ErrInvalidProvider.WithArgs(name)
	}
	if m.Provisioned {
		return m, nil
	}
	if m.Context == "" {
		m.Context = "default"
	}
	primaryInstance, primaryInstanceExists := p.PrimaryInstances[m.Context]
	if !primaryInstanceExists {
		m.ProvisionFailed = true
		return nil, jwterrors.ErrNoPrimaryInstanceProvider.WithArgs(m.Context, name)
	}

	allowedTokenNames := make(map[string]bool)

	if len(m.TrustedTokens) == 0 {
		m.TrustedTokens = primaryInstance.TrustedTokens
	}

	// Iterate over trusted tokens
	for _, entry := range m.TrustedTokens {
		if entry == nil {
			continue
		}

		if entry.TokenName != "" {
			allowedTokenNames[entry.TokenName] = true
		}

		if entry.TokenLifetime == 0 {
			entry.TokenLifetime = 900
		}

		if !entry.HasRSAKeys() && entry.TokenSecret == "" {
			entry.TokenSecret = os.Getenv(jwtconfig.EnvTokenSecret)
			if entry.TokenSecret == "" {
				return nil, jwterrors.ErrUndefinedSecret.WithArgs(m.Name)
			}
		}
	}

	if m.AuthURLPath == "" {
		m.AuthURLPath = primaryInstance.AuthURLPath
	}

	if m.AuthRedirectQueryParameter == "" {
		m.AuthRedirectQueryParameter = primaryInstance.AuthRedirectQueryParameter
	}

	if len(m.AccessList) == 0 {
		for _, primaryInstanceEntry := range primaryInstance.AccessList {
			entry := jwtacl.NewAccessListEntry()
			*entry = *primaryInstanceEntry
			m.AccessList = append(m.AccessList, entry)
		}
	}
	for i, entry := range m.AccessList {
		if err := entry.Validate(); err != nil {
			m.ProvisionFailed = true
			return nil, jwterrors.ErrInvalidConfiguration.WithArgs(m.Name, err)
		}
		if len(entry.Methods) > 0 || entry.Path != "" {
			m.ValidateMethodPath = true
		}
		m.logger.Debug(
			"JWT access list entry",
			zap.String("instance_name", m.Name),
			zap.Int("seq_id", i),
			zap.Any("acl", entry),
		)
	}
	if len(m.AllowedTokenTypes) == 0 {
		m.AllowedTokenTypes = primaryInstance.AllowedTokenTypes
	}
	for _, tt := range m.AllowedTokenTypes {
		if _, exists := jwtconfig.SigningMethods[tt]; !exists {
			m.ProvisionFailed = true
			return nil, jwterrors.ErrUnsupportedSignatureMethod.WithArgs(m.Name, tt)
		}
	}
	if len(m.AllowedTokenSources) == 0 {
		m.AllowedTokenSources = primaryInstance.AllowedTokenSources
	}
	for _, ts := range m.AllowedTokenSources {
		if _, exists := jwtvalidator.TokenSources[ts]; !exists {
			m.ProvisionFailed = true
			return nil, jwterrors.ErrUnsupportedTokenSource.WithArgs(m.Name, ts)
		}
	}

	if m.TokenValidator == nil {
		m.TokenValidator = jwtvalidator.NewTokenValidator()
	}

	if m.TokenValidatorOptions == nil {
		m.TokenValidatorOptions = primaryInstance.TokenValidatorOptions.Clone()
	}

	if m.ValidateMethodPath {
		m.TokenValidatorOptions.ValidateMethodPath = true
	}
	if m.ValidateAccessListPathClaim {
		m.TokenValidatorOptions.ValidateAccessListPathClaim = true
	}

	for tokenName := range allowedTokenNames {
		m.TokenValidator.SetTokenName(tokenName)
	}

	m.TokenValidator.AccessList = m.AccessList
	m.TokenValidator.TokenSources = m.AllowedTokenSources
	m.TokenValidator.TokenConfigs = m.TrustedTokens
	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		m.ProvisionFailed = true
		return nil, jwterrors.ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
	}

	if m.ForbiddenURL == "" {
		m.ForbiddenURL = primaryInstance.ForbiddenURL
	}

	m.PassClaimsWithHeaders = primaryInstance.PassClaimsWithHeaders

	m.logger.Debug(
		"JWT token configuration provisioned for non-primary instance",
		zap.String("instance_name", m.Name),
		zap.Any("trusted_tokens", m.TrustedTokens),
		zap.String("auth_url_path", m.AuthURLPath),
		zap.String("token_sources", strings.Join(m.AllowedTokenSources, " ")),
		zap.String("token_types", strings.Join(m.AllowedTokenTypes, " ")),
		zap.Any("token_validator", m.TokenValidator),
		zap.Any("token_validator_options", m.TokenValidatorOptions),
		zap.String("forbidden_path", m.ForbiddenURL),
	)

	m.Provisioned = true
	m.ProvisionFailed = false

	return m, nil
}
