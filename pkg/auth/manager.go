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
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	kms "github.com/greenpau/caddy-auth-jwt/pkg/kms"
	jwtvalidator "github.com/greenpau/caddy-auth-jwt/pkg/validator"
	"go.uber.org/zap"
	"strings"
	"sync"
)

// InstanceStatus is the state of an Instance.
type InstanceStatus int

const (
	// Unknown is indeterminate state.
	Unknown InstanceStatus = iota
	// BootstrapPrimary is primary instance is ready for bootstrapping.
	BootstrapPrimary
	// BootstrapSecondary is non-primary instance is ready for bootstrapping.
	BootstrapSecondary
	// DelaySecondary is non-primary instance is not ready for bootstrapping.
	DelaySecondary
	// DuplicatePrimary is a dumplicate primary instance.
	DuplicatePrimary
)

// InstanceManager provides access to all instances of the plugin.
type InstanceManager struct {
	mu               sync.Mutex
	Members          map[string]*Authorizer
	PrimaryInstances map[string]*Authorizer
	MemberCount      map[string]int
	backlog          map[string]string
}

// AuthManager is the global authorization provider pool.
// It provides access to all instances of JWT plugin.
var AuthManager *InstanceManager

func init() {
	AuthManager = &InstanceManager{
		Members:          make(map[string]*Authorizer),
		PrimaryInstances: make(map[string]*Authorizer),
		MemberCount:      make(map[string]int),
		backlog:          make(map[string]string),
	}
}

// Validate validates the provisioning of an Authorizer instance.
func (mgr *InstanceManager) Validate(m *Authorizer) error {
	if !m.PrimaryInstance {
		return nil
	}
	m.logger.Debug("Instance validation", zap.String("instance_name", m.Name))
	for instanceName, ctxName := range mgr.backlog {
		if ctxName != m.Context {
			continue
		}
		instance := mgr.Members[instanceName]
		if err := mgr.Register(instance); err != nil {
			return err
		}
		m.logger.Debug("Non-primary instance validated", zap.String("instance_name", instanceName))
	}

	m.logger.Debug("Primary instance validated", zap.String("instance_name", m.Name))
	return nil
}

// Register registers authorization provider instance with the pool.
func (mgr *InstanceManager) Register(m *Authorizer) error {
	var primaryInstance *Authorizer
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if m.Context == "" {
		m.Context = "default"
	}
	if m.Name == "" {
		counter := mgr.incrementMemberCount(m.Context)
		m.Name = fmt.Sprintf("jwt-%s-%06d", m.Context, counter)
	}

	status := mgr.getInstanceStatus(m)
	switch status {
	case DelaySecondary:
		mgr.backlog[m.Name] = m.Context
		mgr.Members[m.Name] = m
		return nil
	case DuplicatePrimary:
		return jwterrors.ErrTooManyPrimaryInstances.WithArgs(m.Context)
	case BootstrapPrimary:
		m.logger.Debug("Primary instance registration", zap.String("instance_name", m.Name))
		mgr.PrimaryInstances[m.Context] = m
		mgr.Members[m.Name] = m
	default:
		// This is BootstrapSecondary.
		m.logger.Debug("Non-primary instance registration", zap.String("instance_name", m.Name))
		m.primaryInstanceName = mgr.PrimaryInstances[m.Context].Name
		primaryInstance = mgr.PrimaryInstances[m.Context]
	}

	// Initialize key managers.
	m.keyManagers = []*kms.KeyManager{}
	if len(m.TrustedTokens) == 0 {
		if m.PrimaryInstance {
			km, err := kms.NewKeyManager(nil)
			if err != nil {
				return err
			}
			m.keyManagers = append(m.keyManagers, km)
		} else {
			m.keyManagers = primaryInstance.keyManagers
		}
	} else {
		for _, tokenConfig := range m.TrustedTokens {
			km, err := kms.NewKeyManager(tokenConfig)
			if err != nil {
				return err
			}
			m.keyManagers = append(m.keyManagers, km)
		}
	}

	// Set authentication redirect URL.
	if m.AuthURLPath == "" {
		if m.PrimaryInstance {
			m.AuthURLPath = "/auth"
		} else {
			m.AuthURLPath = primaryInstance.AuthURLPath
		}
	}

	// Set authentication redirect URI parameter.
	if m.AuthRedirectQueryParameter == "" {
		if m.PrimaryInstance {
			m.AuthRedirectQueryParameter = "redirect_url"
		} else {
			m.AuthRedirectQueryParameter = primaryInstance.AuthRedirectQueryParameter
		}
	}

	if len(m.AccessList) == 0 {
		if m.PrimaryInstance {
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
		} else {
			for _, primaryInstanceEntry := range primaryInstance.AccessList {
				entry := jwtacl.NewAccessListEntry()
				*entry = *primaryInstanceEntry
				m.AccessList = append(m.AccessList, entry)
			}
		}
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

	if len(m.AllowedTokenSources) == 0 {
		if m.PrimaryInstance {
			m.AllowedTokenSources = jwtvalidator.AllTokenSources
		} else {
			m.AllowedTokenSources = primaryInstance.AllowedTokenSources
		}
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
		if m.PrimaryInstance {
			m.TokenValidatorOptions = kms.NewTokenValidatorOptions()
		} else {
			m.TokenValidatorOptions = primaryInstance.TokenValidatorOptions.Clone()
		}
	}

	if m.ValidateMethodPath {
		m.TokenValidatorOptions.ValidateMethodPath = true
	} else {
		if !m.PrimaryInstance {
			m.TokenValidatorOptions.ValidateMethodPath = primaryInstance.TokenValidatorOptions.ValidateMethodPath
		}
	}

	if m.ValidateAccessListPathClaim {
		m.TokenValidatorOptions.ValidateAccessListPathClaim = true
	} else {
		if !m.PrimaryInstance {
			m.TokenValidatorOptions.ValidateAccessListPathClaim = primaryInstance.TokenValidatorOptions.ValidateAccessListPathClaim
		}
	}

	if m.ValidateAllowMatchAll {
		m.TokenValidatorOptions.ValidateAllowMatchAll = true
	} else {
		if !m.PrimaryInstance {
			m.TokenValidatorOptions.ValidateAllowMatchAll = primaryInstance.TokenValidatorOptions.ValidateAllowMatchAll
		}
	}

	for _, entry := range m.TrustedTokens {
		m.TokenValidator.SetTokenName(entry.TokenName)
	}

	m.TokenValidator.AccessList = m.AccessList
	m.TokenValidator.TokenSources = m.AllowedTokenSources
	m.TokenValidator.KeyManagers = m.TrustedTokens

	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		return jwterrors.ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
	}

	if !m.PrimaryInstance {
		if m.ForbiddenURL == "" {
			m.ForbiddenURL = primaryInstance.ForbiddenURL
		}
		m.PassClaimsWithHeaders = primaryInstance.PassClaimsWithHeaders
		m.RedirectWithJavascript = primaryInstance.RedirectWithJavascript
	}

	m.logger.Debug(
		"JWT token configuration provisioned",
		zap.String("instance_name", m.Name),
		zap.Any("trusted_tokens", m.TrustedTokens),
		zap.String("auth_url_path", m.AuthURLPath),
		zap.String("token_sources", strings.Join(m.AllowedTokenSources, " ")),
		zap.Any("token_validator", m.TokenValidator),
		zap.Any("token_validator_options", m.TokenValidatorOptions),
		zap.String("forbidden_path", m.ForbiddenURL),
	)
	return nil
}

func (mgr *InstanceManager) incrementMemberCount(ctxName string) int {
	if _, exists := mgr.MemberCount[ctxName]; exists {
		mgr.MemberCount[ctxName]++
	} else {
		mgr.MemberCount[ctxName] = 1
	}
	return mgr.MemberCount[ctxName]
}

func (mgr *InstanceManager) getInstanceStatus(m *Authorizer) InstanceStatus {
	primary, primaryFound := mgr.PrimaryInstances[m.Context]
	if !primaryFound {
		// Initial startup with no primary instance.
		if m.PrimaryInstance {
			return BootstrapPrimary
		}
		return DelaySecondary
	}
	timeDiff := m.startedAt.Sub(primary.startedAt).Milliseconds()
	if timeDiff > 1000 {
		// Reload
		if m.PrimaryInstance {
			return BootstrapPrimary
		}
		return DelaySecondary
	}
	if m.PrimaryInstance {
		// Initial startup and likely multiple primary instances.
		return DuplicatePrimary
	}
	return BootstrapSecondary
}
