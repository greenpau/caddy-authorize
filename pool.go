package jwt

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

var defaultKeyID = "0"

// rsaSource is what source will override the other
var rsaSource = []string{"key", "file", "dir"}

// rsaConfigSource is where config options will look
var rsaConfigSource = []string{"env", "config"} // this is how tokenSecret works

type loader struct {
	m *AuthProvider

	_dir          string
	_files, _keys map[string]string
}

func (l *loader) config() {
	configDir := l.m.TokenRSADir
	if configDir != "" {
		l._dir = configDir
	}

	for k, v := range l.m.TokenRSAFiles {
		l._files[k] = v
	}
	for k, v := range l.m.TokenRSAKeys {
		l._keys[k] = v
	}

	if l.m.TokenRSAFile != "" {
		if _, ok := l._files[defaultKeyID]; !ok {
			l._files[defaultKeyID] = l.m.TokenRSAFile // <- overwrite explict key
		}
	}
	if l.m.TokenRSAKey != "" {
		if _, ok := l._keys[defaultKeyID]; !ok {
			l._keys[defaultKeyID] = l.m.TokenRSAKey // <- overwrite explict key
		}
	}
}

func (l *loader) env() {
	envDir := os.Getenv(EnvTokenRSADir)
	if envDir != "" {
		l._dir = envDir
	}

	for _, envKV := range os.Environ() {
		kv := strings.SplitN(envKV, "=", 2)
		if len(kv) == 2 {
			switch {
			case strings.HasPrefix(kv[0], EnvTokenRSAFile):
				k := strings.TrimPrefix(kv[0], EnvTokenRSAFile)
				if len(k) == 0 {
					if _, ok := l._files[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._files[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			case strings.HasPrefix(kv[0], EnvTokenRSAKey):
				k := strings.TrimPrefix(kv[0], EnvTokenRSAKey)
				if len(k) == 0 {
					if _, ok := l._keys[defaultKeyID]; ok {
						continue // don't overwrite an explict key
					}
					k = defaultKeyID
				}
				l._keys[strings.ToLower(strings.TrimLeft(k, "_"))] = kv[1]
			}
		}
	}
}

var onceDir = new(sync.Once)
var onceFile = new(sync.Once)

func (l *loader) directory() (done bool, err error) {
	slash := string(filepath.Separator)
	if len(l._dir) > 0 {
		err = filepath.Walk(l._dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}

			absDir, err := filepath.Abs(l._dir)
			if err != nil {
				absDir = l._dir // just fall back to the value we had before
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				absPath = path
			}
			key := strings.TrimPrefix(absPath, absDir)
			key = strings.TrimSuffix(key, ".key")
			key = strings.Replace(key, slash, "_", -1)
			key = strings.Trim(key, "_")
			for i := 0; i < len(key); i++ {
				c := key[i]
				switch {
				case c == 95, // make sure we only have chars [0-9a-zA-Z_]
					c >= 48 && c <= 57,
					c >= 65 && c <= 90,
					c >= 97 && c <= 122:
					continue
				}
				return nil
			}

			if _, ok := l._keys[key]; !ok {
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return ErrReadFile.WithArgs("dir", err)
				}

				l._keys[key] = string(b)
			}
			return nil
		})
		if err != nil {
			return false, ErrWalkDir.WithArgs(err)
		}
		done = true // we have success
	}
	return done, err
}

func (l *loader) file() (done bool, err error) {
	if len(l._files) > 0 {
		for kid, filePath := range l._files {
			if _, ok := l._keys[kid]; !ok {
				b, err := ioutil.ReadFile(filePath)
				if err != nil {
					return false, ErrReadFile.WithArgs("file", err)
				}

				l._keys[kid] = string(b)
			}
		}
		done = true // success
	}
	return done, err
}

func (l *loader) key() (done bool, err error) {
	if len(l._keys) > 0 {
		done = len(l._files) == 0
	}
	return done, err
}

// loadEncryptionKeys loads keys for the RSA encryption based on the order determined
// by rsaSource and rsaConfigSource
func (m *AuthProvider) loadEncryptionKeys() error {
	l := &loader{
		m:      m,
		_keys:  make(map[string]string),
		_files: make(map[string]string),
	}

	// cs is the configSource
	cs := map[string]func(){
		"config": l.config,
		"env":    l.env,
	}

	// ss is the sourceSource
	ss := map[string]func() (bool, error){
		"dir":  l.directory,
		"file": l.file,
		"key":  l.key,
	}

	for _, configSrc := range rsaConfigSource {
		fn, exists := cs[configSrc]
		if !exists {
			return ErrUnknownConfigSource
		}
		fn()
	}

	for _, src := range rsaSource {
		fn, exists := ss[src]
		if !exists {
			return ErrUnknownConfigSource
		}
		done, err := fn()
		if err != nil {
			return err
		}
		if done {
			break
		}
	}

	var rtnErr error
	for k, v := range l._keys {
		m.logger.Info("RSA key processing...", zap.String("name", k))

		switch {
		case strings.Contains(v, "BEGIN RSA PRIVATE"):
			pk, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(v))
			if err != nil {
				rtnErr = fmt.Errorf("%v %w", rtnErr, err) // wraps error
				continue
			}
			if m.tokenKeys == nil {
				m.tokenKeys = make(map[string]interface{})
			}
			m.tokenKeys[k] = pk
			m.logger.Info("RSA private key added", zap.String("name", k))
		case strings.Contains(v, "BEGIN PUBLIC KEY"):
			pk, err := jwtlib.ParseRSAPublicKeyFromPEM([]byte(v))
			if err != nil {
				rtnErr = fmt.Errorf("%v %w", rtnErr, err) // wraps error
				continue
			}
			if m.tokenKeys == nil {
				m.tokenKeys = make(map[string]interface{})
			}
			m.tokenKeys[k] = pk
			m.logger.Info("RS public key added", zap.String("name", k))
		}
	}

	return rtnErr
}
