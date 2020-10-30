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
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"
)

// Pool Errors
const (
	ErrEmptyProviderName errors.StandardError = "authorization provider name is empty"
	ErrNoMemberReference errors.StandardError = "no member reference found"

	ErrTooManyPrimaryInstances     errors.StandardError = "found more than one primaryInstance instance of the plugin for %s context"
	ErrUndefinedSecret             errors.StandardError = "%s: token keys and secrets must be defined either via environment variables or via token_ configuration element"
	ErrInvalidConfiguration        errors.StandardError = "%s: default access list configuration error: %s"
	ErrUnsupportedSignatureMethod  errors.StandardError = "%s: unsupported token sign/verify method: %s"
	ErrUnsupportedTokenSource      errors.StandardError = "%s: unsupported token source: %s"
	ErrInvalidBackendConfiguration errors.StandardError = "%s: token validator configuration error: %s"
	ErrUnknownProvider             errors.StandardError = "authorization provider %s not found"
	ErrInvalidProvider             errors.StandardError = "authorization provider %s is nil"
	ErrNoPrimaryInstanceProvider   errors.StandardError = "no primaryInstance authorization provider found in %s context when configuring %s"
	ErrNoTrustedTokensFound        errors.StandardError = "no trusted tokens found in %s context"
	ErrLoadingKeys                 errors.StandardError = "loading %s keys: %v"
)

// AuthProviderPool provides access to all instances of the plugin.
type AuthProviderPool struct {
	mu               sync.Mutex
	Members          []*AuthProvider
	RefMembers       map[string]*AuthProvider
	PrimaryInstances map[string]*AuthProvider
	MemberCount      int
}

// Register registers authorization provider instance with the pool.
func (p *AuthProviderPool) Register(m *AuthProvider) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if m.Name == "" {
		p.MemberCount++
		m.Name = fmt.Sprintf("jwt-%d", p.MemberCount)
	}
	if p.RefMembers == nil {
		p.RefMembers = make(map[string]*AuthProvider)
	}
	if _, exists := p.RefMembers[m.Name]; !exists {
		p.RefMembers[m.Name] = m
		p.Members = append(p.Members, m)
	}
	if m.Context == "" {
		m.Context = "default"
	}
	if p.PrimaryInstances == nil {
		p.PrimaryInstances = make(map[string]*AuthProvider)
	}

	if m.PrimaryInstance {
		if _, ok := p.PrimaryInstances[m.Context]; ok {
			// The time different check is necessary to determine whether this is a configuration
			// load or reload. Typically, the provisioning of a plugin would happen in a second.
			timeDiff := m.startedAt.Sub(p.PrimaryInstances[m.Context].startedAt).Milliseconds()
			if timeDiff < 1000 {
				return ErrTooManyPrimaryInstances.WithArgs(m.Context)
			}
		}

		p.PrimaryInstances[m.Context] = m

		// Check that primary instance has trusted tokens
		if len(m.TrustedTokens) == 0 {
			return ErrNoTrustedTokensFound.WithArgs(m.Name)
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

			if entry.TokenIssuer == "" {
				entry.TokenIssuer = "localhost"
			}

			if entry.TokenLifetime == 0 {
				entry.TokenLifetime = 900
			}

			if !entry.HasRSAKeys() && entry.TokenSecret == "" {
				entry.TokenSecret = os.Getenv(EnvTokenSecret)
				if entry.TokenSecret == "" {
					return ErrUndefinedSecret.WithArgs(m.Name)
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
			entry := NewAccessListEntry()
			entry.Allow()
			if err := entry.SetClaim("roles"); err != nil {
				return ErrInvalidConfiguration.WithArgs(m.Name, err)
			}

			for _, v := range []string{"anonymous", "guest"} {
				if err := entry.AddValue(v); err != nil {
					return ErrInvalidConfiguration.WithArgs(m.Name, err)
				}
			}
			m.AccessList = append(m.AccessList, entry)
		}

		for i, entry := range m.AccessList {
			if err := entry.Validate(); err != nil {
				return ErrInvalidConfiguration.WithArgs(m.Name, err)
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
			if _, exists := methods[tt]; !exists {
				return ErrUnsupportedSignatureMethod.WithArgs(m.Name, tt)
			}
		}

		if len(m.AllowedTokenSources) == 0 {
			m.AllowedTokenSources = allTokenSources
		}

		for _, ts := range m.AllowedTokenSources {
			if _, exists := tokenSources[ts]; !exists {
				return ErrUnsupportedTokenSource.WithArgs(m.Name, ts)
			}
		}

		if m.TokenValidator == nil {
			m.TokenValidator = NewTokenValidator()
		}

		if m.TokenValidatorOptions == nil {
			m.TokenValidatorOptions = NewTokenValidatorOptions()
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
			return ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
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
func (p *AuthProviderPool) Provision(name string) (*AuthProvider, error) {
	if name == "" {
		return nil, ErrEmptyProviderName
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.RefMembers == nil {
		return nil, ErrNoMemberReference
	}
	m, exists := p.RefMembers[name]
	if !exists {
		return nil, ErrUnknownProvider.WithArgs(name)
	}
	if m == nil {
		return nil, ErrInvalidProvider.WithArgs(name)
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
		return nil, ErrNoPrimaryInstanceProvider.WithArgs(m.Context, name)
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

		if entry.TokenIssuer == "" {
			entry.TokenIssuer = "localhost"
		}

		if entry.TokenLifetime == 0 {
			entry.TokenLifetime = 900
		}

		if !entry.HasRSAKeys() && entry.TokenSecret == "" {
			entry.TokenSecret = os.Getenv(EnvTokenSecret)
			if entry.TokenSecret == "" {
				return nil, ErrUndefinedSecret.WithArgs(m.Name)
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
			entry := NewAccessListEntry()
			*entry = *primaryInstanceEntry
			m.AccessList = append(m.AccessList, entry)
		}
	}
	for i, entry := range m.AccessList {
		if err := entry.Validate(); err != nil {
			m.ProvisionFailed = true
			return nil, ErrInvalidConfiguration.WithArgs(m.Name, err)
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
		if _, exists := methods[tt]; !exists {
			m.ProvisionFailed = true
			return nil, ErrUnsupportedSignatureMethod.WithArgs(m.Name, tt)
		}
	}
	if len(m.AllowedTokenSources) == 0 {
		m.AllowedTokenSources = primaryInstance.AllowedTokenSources
	}
	for _, ts := range m.AllowedTokenSources {
		if _, exists := tokenSources[ts]; !exists {
			m.ProvisionFailed = true
			return nil, ErrUnsupportedTokenSource.WithArgs(m.Name, ts)
		}
	}

	if m.TokenValidator == nil {
		m.TokenValidator = NewTokenValidator()
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
		return nil, ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
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
