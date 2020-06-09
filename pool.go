package jwt

import (
	"fmt"
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"
)

// AuthzProviderPool provides access to all instances of the plugin.
type AuthzProviderPool struct {
	mu          sync.Mutex
	Members     []*AuthzProvider
	RefMembers  map[string]*AuthzProvider
	Masters     map[string]*AuthzProvider
	MemberCount int
}

// Register registers authorization provider instance with the pool.
func (p *AuthzProviderPool) Register(m *AuthzProvider) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m.Name == "" {
		p.MemberCount++
		m.Name = fmt.Sprintf("jwt-%d", p.MemberCount)
	}
	if p.RefMembers == nil {
		p.RefMembers = make(map[string]*AuthzProvider)
	}
	if _, exists := p.RefMembers[m.Name]; !exists {
		p.RefMembers[m.Name] = m
		p.Members = append(p.Members, m)
	}
	if m.Context == "" {
		m.Context = "default"
	}
	if p.Masters == nil {
		p.Masters = make(map[string]*AuthzProvider)
	}
	if m.Master {
		if _, exists := p.Masters[m.Context]; exists {
			return fmt.Errorf("found more than one master instance of the plugin for %s context", m.Context)
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
				return fmt.Errorf("%s: token_secret must be defined either "+
					"via JWT_TOKEN_SECRET environment variable or "+
					"via token_secret configuration element",
					m.Name,
				)
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
				return fmt.Errorf("%s: default access list configuration error: %s", m.Name, err)
			}

			for _, v := range []string{"anonymous", "guest"} {
				if err := entry.AddValue(v); err != nil {
					return fmt.Errorf("%s: default access list configuration error: %s", m.Name, err)
				}
			}
			m.AccessList = append(m.AccessList, entry)
		}

		for i, entry := range m.AccessList {
			if err := entry.Validate(); err != nil {
				return fmt.Errorf("%s: access list configuration error: %s", m.Name, err)
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
				return fmt.Errorf("%s: unsupported token sign/verify method: %s", m.Name, tt)
			}
		}

		if len(m.AllowedTokenSources) == 0 {
			m.AllowedTokenSources = []string{"header", "cookie", "query"}
		}

		for _, ts := range m.AllowedTokenSources {
			if _, exists := tokenSources[ts]; !exists {
				return fmt.Errorf("%s: unsupported token source: %s", m.Name, ts)
			}
		}

		m.TokenValidator.TokenName = m.TokenName
		m.TokenValidator.TokenSecret = m.TokenSecret
		m.TokenValidator.TokenIssuer = m.TokenIssuer
		m.TokenValidator.AccessList = m.AccessList
		if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
			return fmt.Errorf("%s: token validator configuration error: %s", m.Name, err)
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
func (p *AuthzProviderPool) Provision(name string) error {
	if name == "" {
		return fmt.Errorf("authorization provider name is empty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.RefMembers == nil {
		return fmt.Errorf("no member reference found")
	}
	m, exists := p.RefMembers[name]
	if !exists {
		return fmt.Errorf("authorization provider %s not found", name)
	}
	if m == nil {
		return fmt.Errorf("authorization provider %s is nil", name)
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
		return fmt.Errorf("no master authorization provider found in %s context when configuring %s", m.Context, name)
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
			return fmt.Errorf("%s: access list configuration error: %s", m.Name, err)
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
			return fmt.Errorf("%s: unsupported token sign/verify method: %s", m.Name, tt)
		}
	}
	if len(m.AllowedTokenSources) == 0 {
		m.AllowedTokenSources = master.AllowedTokenSources
	}
	for _, ts := range m.AllowedTokenSources {
		if _, exists := tokenSources[ts]; !exists {
			m.ProvisionFailed = true
			return fmt.Errorf("%s: unsupported token source: %s", m.Name, ts)
		}
	}

	if m.TokenValidator == nil {
		m.TokenValidator = NewTokenValidator()
	}

	m.TokenValidator.TokenName = m.TokenName
	m.TokenValidator.TokenSecret = m.TokenSecret
	m.TokenValidator.TokenIssuer = m.TokenIssuer
	m.TokenValidator.AccessList = m.AccessList
	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		m.ProvisionFailed = true
		return fmt.Errorf("%s: token validator configuration error: %s", m.Name, err)
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
