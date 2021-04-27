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
	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/validator"
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
func (mgr *InstanceManager) Validate(ctx context.Context, m *Authorizer) error {
	if !m.PrimaryInstance {
		return nil
	}
	m.logger.Debug("Instance validation", zap.String("instance_name", m.Name))
	for instanceName, ctxName := range mgr.backlog {
		if ctxName != m.Context {
			continue
		}
		instance := mgr.Members[instanceName]
		if err := mgr.Register(ctx, instance); err != nil {
			return err
		}
		m.logger.Debug("Non-primary instance validated", zap.String("instance_name", instanceName))
	}

	m.logger.Debug("Primary instance validated", zap.String("instance_name", m.Name))
	return nil
}

// Register registers authorization provider instance with the pool.
func (mgr *InstanceManager) Register(ctx context.Context, m *Authorizer) error {
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
		return errors.ErrTooManyPrimaryInstances.WithArgs(m.Context)
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

	// Set miscellaneous parameters.
	if !m.PrimaryInstance {
		if m.ForbiddenURL == "" {
			m.ForbiddenURL = primaryInstance.ForbiddenURL
		}
		m.PassClaimsWithHeaders = primaryInstance.PassClaimsWithHeaders
		m.RedirectWithJavascript = primaryInstance.RedirectWithJavascript
	}

	// Initialize token validator and associated options.
	m.tokenValidator = validator.NewTokenValidator()
	m.opts = options.NewTokenValidatorOptions()

	if m.ValidateMethodPath {
		m.opts.ValidateMethodPath = true
	} else {
		if !m.PrimaryInstance {
			m.opts.ValidateMethodPath = primaryInstance.opts.ValidateMethodPath
		}
	}

	if m.ValidateBearerHeader {
		m.opts.ValidateBearerHeader = true
	} else {
		if !m.PrimaryInstance {
			m.opts.ValidateBearerHeader = primaryInstance.opts.ValidateBearerHeader
		}
	}

	if m.ValidateAccessListPathClaim {
		m.opts.ValidateAccessListPathClaim = true
	} else {
		if !m.PrimaryInstance {
			m.opts.ValidateAccessListPathClaim = primaryInstance.opts.ValidateAccessListPathClaim
		}
	}

	if m.ValidateSourceAddress {
		m.opts.ValidateSourceAddress = true
	} else {
		if !m.PrimaryInstance {
			m.opts.ValidateSourceAddress = primaryInstance.opts.ValidateSourceAddress
		}
	}

	// Load token configuration into key managers, extract token verification
	// keys and add them to token validator.
	if len(m.CryptoKeyConfigs) == 0 && !m.PrimaryInstance {
		m.CryptoKeyConfigs = primaryInstance.CryptoKeyConfigs
	}

	ks := *kms.NewCryptoKeyStore()
	if len(m.CryptoKeyConfigs) == 0 {
		if err := ks.AutoGenerate(m.Context, "ES512"); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(m.Name, err)
		}
	} else {
		if err := ks.AddKeysWithConfigs(m.CryptoKeyConfigs); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(m.Name, err)
		}
		if err := ks.HasVerifyKeys(); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(m.Name, err)
		}
	}

	// Load access list.
	if len(m.AccessListRules) == 0 && !m.PrimaryInstance {
		m.AccessListRules = primaryInstance.AccessListRules
	}
	if len(m.AccessListRules) == 0 {
		return errors.ErrInvalidConfiguration.WithArgs(m.Name, "access list rule config not found")
	}
	accessList := acl.NewAccessList()
	accessList.SetLogger(m.logger)
	if err := accessList.AddRules(ctx, m.AccessListRules); err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(m.Name, err)
	}

	// Configure token validator with keys and access list.
	if err := m.tokenValidator.Configure(ctx, ks.GetVerifyKeys(), accessList, m.opts); err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(m.Name, err)
	}

	// Set allow token sources and their priority.
	if len(m.AllowedTokenSources) == 0 && !m.PrimaryInstance {
		m.AllowedTokenSources = primaryInstance.AllowedTokenSources
	}
	if len(m.AllowedTokenSources) > 0 {
		if err := m.tokenValidator.SetSourcePriority(m.AllowedTokenSources); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(m.Name, err)
		}
	}

	m.logger.Debug(
		"JWT token configuration provisioned",
		zap.String("instance_name", m.Name),
		zap.String("auth_url_path", m.AuthURLPath),
		zap.String("token_sources", strings.Join(m.tokenValidator.GetSourcePriority(), " ")),
		zap.Any("token_validator_options", m.opts),
		zap.Any("access_list_rules", m.AccessListRules),
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
