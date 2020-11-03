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

package cache

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"sync"
	"time"
)

// TokenCache contains cached tokens
type TokenCache struct {
	mu      sync.RWMutex
	Entries map[string]claims.UserClaims
}

// NewTokenCache returns TokenCache instance.
func NewTokenCache() *TokenCache {
	c := &TokenCache{
		Entries: map[string]claims.UserClaims{},
	}
	go manageTokenCache(c)
	return c
}

func manageTokenCache(cache *TokenCache) {
	intervals := time.NewTicker(time.Minute * time.Duration(5))
	for range intervals.C {
		if cache == nil {
			return
		}
		cache.mu.RLock()
		if cache.Entries == nil {
			cache.mu.RUnlock()
			continue
		}
		cache.mu.RUnlock()
		cache.mu.Lock()
		for k, claims := range cache.Entries {
			if err := claims.Valid(); err != nil {
				delete(cache.Entries, k)
			}
		}
		cache.mu.Unlock()
	}
	return
}

// Add adds a token and the associated claim to cache.
func (c *TokenCache) Add(token string, claims claims.UserClaims) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Entries[token] = claims
	return nil
}

// Delete removes cached token from
func (c *TokenCache) Delete(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Entries, token)
	return nil
}

// Get returns user claims if the token associated with
// the claim exists in cache. If the token is expired, it
// will be removed from the cache.
func (c *TokenCache) Get(token string) *claims.UserClaims {
	c.mu.RLock()
	claims, exists := c.Entries[token]
	c.mu.RUnlock()
	if !exists {
		return nil
	}
	if claims.ExpiresAt < time.Now().Unix() {
		c.Delete(token)
		return nil
	}
	return &claims
}
