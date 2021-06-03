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
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"sync"
	"time"
)

// TokenCache contains cached tokens
type TokenCache struct {
	mu      sync.RWMutex
	Entries map[string]*user.User `json:"entries,omitempty" xml:"entries,omitempty" yaml:"entries,omitempty"`
}

// NewTokenCache returns TokenCache instance.
func NewTokenCache(i int) *TokenCache {
	c := &TokenCache{
		Entries: make(map[string]*user.User),
	}
	go manageTokenCache(i, c)
	return c
}

func manageTokenCache(i int, cache *TokenCache) {
	if i == 0 {
		i = 300000
	}
	// intervals := time.NewTicker(time.Minute * time.Duration(5))
	intervals := time.NewTicker(time.Millisecond * time.Duration(i))
	for range intervals.C {
		// if cache == nil {
		//	break
		// }
		cache.mu.RLock()
		if cache.Entries == nil {
			cache.mu.RUnlock()
			continue
		}
		cache.mu.RUnlock()
		cache.mu.Lock()
		for k, usr := range cache.Entries {
			if err := usr.Claims.Valid(); err != nil {
				delete(cache.Entries, k)
			}
		}
		cache.mu.Unlock()
	}
}

// Add adds a token and the associated claim to cache.
func (c *TokenCache) Add(usr *user.User) error {
	if usr == nil {
		return errors.ErrCacheNilUser
	}
	if usr.Token == "" {
		return errors.ErrCacheEmptyToken
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	usr.Cached = true
	c.Entries[usr.Token] = usr
	return nil
}

// Delete removes cached token from
func (c *TokenCache) Delete(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Entries, token)
	return nil
}

// Get returns User instance if the token associated with
// the claim exists in cache. If the token is expired, it
// will be removed from the cache.
func (c *TokenCache) Get(token string) *user.User {
	c.mu.RLock()
	usr, exists := c.Entries[token]
	c.mu.RUnlock()
	if !exists {
		return nil
	}
	if usr.Claims.ExpiresAt < time.Now().Unix() {
		c.Delete(token)
		return nil
	}
	return usr
}
