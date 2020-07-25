package jwt

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Pool Errors
const (
	ErrEmptyProviderName strError = "authorization provider name is empty"
	ErrNoMemberReference strError = "no member reference found"

	ErrTooManyMasters              strError = "found more than one master instance of the plugin for %s context"
	ErrUndefinedSecret             strError = "%s: token_secret must be defined either via JWT_TOKEN_SECRET environment variable or via token_secret configuration element"
	ErrInvalidConfiguration        strError = "%s: default access list configuration error: %s"
	ErrUnsupportedSignatureMethod  strError = "%s: unsupported token sign/verify method: %s"
	ErrUnsupportedTokenSource      strError = "%s: unsupported token source: %s"
	ErrInvalidBackendConfiguration strError = "%s: token validator configuration error: %s"
	ErrUnknownProvider             strError = "authorization provider %s not found"
	ErrInvalidProvider             strError = "authorization provider %s is nil"
	ErrNoMasterProvider            strError = "no master authorization provider found in %s context when configuring %s"
)

// AuthProviderPool provides access to all instances of the plugin.
type AuthProviderPool struct {
	mu          sync.Mutex
	Members     []*AuthProvider
	RefMembers  map[string]*AuthProvider
	Masters     map[string]*AuthProvider
	MemberCount int
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
	if p.Masters == nil {
		p.Masters = make(map[string]*AuthProvider)
	}
	if m.Master {
		if _, exists := p.Masters[m.Context]; exists {
			return ErrTooManyMasters.WithArgs(m.Context)
		}
		p.Masters[m.Context] = m
	}
	if m.TokenValidator == nil {
		m.TokenValidator = NewTokenValidator()
	}

	if m.Master {
		if m.TokenName == "" {
			m.TokenName = "access_token"
		}
		if m.TokenSecret == "" {
			if os.Getenv("JWT_TOKEN_SECRET") == "" {
				return ErrUndefinedSecret.WithArgs(m.Name)
			}
			m.TokenSecret = os.Getenv("JWT_TOKEN_SECRET")
		}
		if m.TokenIssuer == "" {
			m.TokenIssuer = "localhost"
		}

		if m.AuthURLPath == "" {
			m.AuthURLPath = "/auth"
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
			m.logger.Info(
				"JWT access list entry",
				zap.String("instance_name", m.Name),
				zap.Int("seq_id", i),
				zap.String("action", entry.GetAction()),
				zap.String("claim", entry.GetClaim()),
				zap.String("values", entry.GetValues()),
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

		if m.TokenName != "" {
			m.TokenValidator.SetTokenName(m.TokenName)
		}
		m.TokenValidator.TokenSecret = m.TokenSecret
		m.TokenValidator.TokenIssuer = m.TokenIssuer
		m.TokenValidator.AccessList = m.AccessList
		m.TokenValidator.TokenSources = m.AllowedTokenSources
		if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
			return ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
		}

		m.logger.Info(
			"JWT token configuration provisioned",
			zap.String("instance_name", m.Name),
			zap.String("token_name", m.TokenName),
			zap.String("token_issuer", m.TokenIssuer),
			zap.String("auth_url_path", m.AuthURLPath),
			zap.String("token_sources", strings.Join(m.AllowedTokenSources, " ")),
			zap.String("token_types", strings.Join(m.AllowedTokenTypes, " ")),
		)

		m.Provisioned = true
	}
	return nil
}

// Provision provisions non-master instances in an authorization context.
func (p *AuthProviderPool) Provision(name string) error {
	if name == "" {
		return ErrEmptyProviderName
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.RefMembers == nil {
		return ErrNoMemberReference
	}
	m, exists := p.RefMembers[name]
	if !exists {
		return ErrUnknownProvider.WithArgs(name)
	}
	if m == nil {
		return ErrInvalidProvider.WithArgs(name)
	}
	if m.Provisioned {
		return nil
	}
	if m.Context == "" {
		m.Context = "default"
	}
	master, masterExists := p.Masters[m.Context]
	if !masterExists {
		m.ProvisionFailed = true
		return ErrNoMasterProvider.WithArgs(m.Context, name)
	}

	if m.TokenName == "" {
		m.TokenName = master.TokenName
	}
	if m.TokenIssuer == "" {
		m.TokenIssuer = master.TokenIssuer
	}

	if m.TokenSecret == "" {
		m.TokenSecret = master.TokenSecret
	}
	if m.AuthURLPath == "" {
		m.AuthURLPath = master.AuthURLPath
	}
	if len(m.AccessList) == 0 {
		for _, masterEntry := range master.AccessList {
			entry := NewAccessListEntry()
			*entry = *masterEntry
			m.AccessList = append(m.AccessList, entry)
		}
	}
	for i, entry := range m.AccessList {
		if err := entry.Validate(); err != nil {
			m.ProvisionFailed = true
			return ErrInvalidConfiguration.WithArgs(m.Name, err)
		}
		m.logger.Info(
			"JWT access list entry",
			zap.String("instance_name", m.Name),
			zap.Int("seq_id", i),
			zap.String("action", entry.GetAction()),
			zap.String("claim", entry.GetClaim()),
			zap.String("values", entry.GetValues()),
		)
	}
	if len(m.AllowedTokenTypes) == 0 {
		m.AllowedTokenTypes = master.AllowedTokenTypes
	}
	for _, tt := range m.AllowedTokenTypes {
		if _, exists := methods[tt]; !exists {
			m.ProvisionFailed = true
			return ErrUnsupportedSignatureMethod.WithArgs(m.Name, tt)
		}
	}
	if len(m.AllowedTokenSources) == 0 {
		m.AllowedTokenSources = master.AllowedTokenSources
	}
	for _, ts := range m.AllowedTokenSources {
		if _, exists := tokenSources[ts]; !exists {
			m.ProvisionFailed = true
			return ErrUnsupportedTokenSource.WithArgs(m.Name, ts)
		}
	}

	if m.TokenValidator == nil {
		m.TokenValidator = NewTokenValidator()
	}

	if m.TokenName != "" {
		m.TokenValidator.SetTokenName(m.TokenName)
	}
	m.TokenValidator.TokenSecret = m.TokenSecret
	m.TokenValidator.TokenIssuer = m.TokenIssuer
	m.TokenValidator.AccessList = m.AccessList
	m.TokenValidator.TokenSources = m.AllowedTokenSources
	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		m.ProvisionFailed = true
		return ErrInvalidBackendConfiguration.WithArgs(m.Name, err)
	}

	m.logger.Info(
		"JWT token configuration provisioned",
		zap.String("instance_name", m.Name),
		zap.String("token_name", m.TokenName),
		zap.String("token_issuer", m.TokenIssuer),
		zap.String("auth_url_path", m.AuthURLPath),
		zap.String("token_sources", strings.Join(m.AllowedTokenSources, " ")),
		zap.String("token_types", strings.Join(m.AllowedTokenTypes, " ")),
	)

	m.Provisioned = true
	m.ProvisionFailed = false

	return nil
}
