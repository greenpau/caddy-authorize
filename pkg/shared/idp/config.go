// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"github.com/greenpau/caddy-authorize/pkg/errors"
	cfgutils "github.com/greenpau/caddy-authorize/pkg/utils/cfg"
	"strings"
)

// BasicAuthConfig is a config for basic authentication.
type BasicAuthConfig struct {
	Enabled bool                   `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Realms  map[string]interface{} `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
}

// APIKeyAuthConfig is a config for API key-based authentication.
type APIKeyAuthConfig struct {
	Enabled bool                   `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Realms  map[string]interface{} `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
}

// IdentityProviderConfig is a config for an identity provider.
type IdentityProviderConfig struct {
	Context    string           `json:"context,omitempty" xml:"context,omitempty" yaml:"context,omitempty"`
	BasicAuth  BasicAuthConfig  `json:"basic_auth,omitempty" xml:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
	APIKeyAuth APIKeyAuthConfig `json:"api_key_auth,omitempty" xml:"api_key_auth,omitempty" yaml:"api_key_auth,omitempty"`
}

// ParseIdentityProviderConfig parses configuration into an identity provider config
func ParseIdentityProviderConfig(lines []string) (*IdentityProviderConfig, error) {
	m := make(map[string]*IdentityProviderConfig)
	if len(lines) == 0 {
		return nil, errors.ErrIdentityProviderConfigInvalid.WithArgs("empty config")
	}
	for _, encodedLine := range lines {
		contextName := "default"
		realmName := "local"
		var cfg *IdentityProviderConfig
		arr, err := cfgutils.DecodeArgs(encodedLine)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.HasPrefix(encodedLine, "basic auth"):
			arr = arr[2:]
		case strings.HasPrefix(encodedLine, "api key auth"):
			arr = arr[3:]
		default:
			return nil, errors.ErrIdentityProviderConfigInvalid.WithArgs(encodedLine)
		}
		if len(arr) > 0 {
			for {
				if len(arr) == 0 {
					break
				}
				if (len(arr) % 2) > 0 {
					return nil, errors.ErrIdentityProviderConfigInvalid.WithArgs(encodedLine)
				}
				k := arr[0]
				switch k {
				case "context":
					contextName = arr[1]
					arr = arr[2:]
				case "realm":
					realmName = arr[1]
					arr = arr[2:]
				default:
					return nil, errors.ErrIdentityProviderConfigInvalid.WithArgs(encodedLine)
				}
			}
		}

		if _, exists := m[contextName]; exists {
			cfg = m[contextName]
		} else {
			cfg = &IdentityProviderConfig{Context: contextName}
			m[contextName] = cfg
		}

		switch {
		case strings.HasPrefix(encodedLine, "basic auth"):
			cfg.BasicAuth.Enabled = true
			if cfg.BasicAuth.Realms == nil {
				cfg.BasicAuth.Realms = make(map[string]interface{})
			}
			cfg.BasicAuth.Realms[realmName] = true
		case strings.HasPrefix(encodedLine, "api key auth"):
			cfg.APIKeyAuth.Enabled = true
			if cfg.APIKeyAuth.Realms == nil {
				cfg.APIKeyAuth.Realms = make(map[string]interface{})
			}
			cfg.APIKeyAuth.Realms[realmName] = true
		}
	}

	if len(m) > 1 {
		return nil, errors.ErrIdentityProviderConfigInvalid.WithArgs("multiple contexts")
	}
	var providers []*IdentityProviderConfig
	for _, provider := range m {
		providers = append(providers, provider)
	}
	return providers[0], nil
}
