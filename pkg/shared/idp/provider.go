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
	"sync"
)

// Provider is an interface to an identity provider.
type Provider interface {
	BasicAuth(*ProviderRequest) error
	APIKeyAuth(*ProviderRequest) error
}

// ProviderCatalog is a map of identity providers
type ProviderCatalog struct {
	mu      sync.RWMutex
	entries map[string]Provider
}

var (
	// Catalog is identity provider catalog.
	Catalog *ProviderCatalog
)

func init() {
	Catalog = &ProviderCatalog{
		entries: make(map[string]Provider),
	}
}

// Register registers identity provider with Catalog.
func (c *ProviderCatalog) Register(s string, p Provider) error {
	if s == "" {
		s = "default"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[s] = p
	return nil
}

// BasicAuth performs basic authentication.
func (c *ProviderCatalog) BasicAuth(r *ProviderRequest) error {
	r.applyDefaults()
	p, exists := c.entries[r.Context]
	if !exists {
		return errors.ErrProviderCatalogRegisterContextNotRegistered
	}
	return p.BasicAuth(r)
}

// APIKeyAuth performs API key authentication.
func (c *ProviderCatalog) APIKeyAuth(r *ProviderRequest) error {
	r.applyDefaults()
	p, exists := c.entries[r.Context]
	if !exists {
		return errors.ErrProviderCatalogRegisterContextNotRegistered
	}
	return p.APIKeyAuth(r)
}
