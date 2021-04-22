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

package grantor

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"sort"
)

// TokenGrantor creates and issues JWT tokens.
type TokenGrantor struct {
	keys       []*kms.Key
	tokenNames []string
}

// NewTokenGrantor returns an instance of TokenGrantor
func NewTokenGrantor() *TokenGrantor {
	return &TokenGrantor{}
}

// GetTokenNames returns a sorted list of token names.
func (g *TokenGrantor) GetTokenNames() []string {
	return g.tokenNames
}

// AddKeysFromKeyManagers adds kms.Key from multiple kms.KeyManager instances
// to TokenGrantor.
func (g *TokenGrantor) AddKeysFromKeyManagers(mgrs []*kms.KeyManager) error {
	keys := kms.GetSignKeys(mgrs)
	if len(keys) == 0 {
		return errors.ErrTokenGrantorNoSigningKeysFound
	}
	g.keys = keys
	return g.rebase()
}

// GrantToken returns a signed token from user claims.
func (g *TokenGrantor) GrantToken(method interface{}, usr *user.User) error {
	if usr == nil {
		return errors.ErrTokenGrantorNoClaimsFound
	}
	for _, k := range g.keys {
		if method == nil {
			return k.SignToken(k.Sign.Token.DefaultMethod, usr)
		}
		signMethod, ok := method.(string)
		if !ok {
			continue
		}
		if signMethod == "" {
			return k.SignToken(k.Sign.Token.DefaultMethod, usr)
		}
		if _, exists := k.Sign.Token.Methods[signMethod]; !exists {
			continue
		}
		return k.SignToken(signMethod, usr)
	}
	return errors.ErrTokenGrantorNoSigningKeysFound
}

func (g *TokenGrantor) rebase() error {
	tokenNames := []string{}
	tokenNameMap := make(map[string]bool)
	for _, k := range g.keys {
		tokenNameMap[k.Sign.Token.Name] = true
	}

	for tokenName := range tokenNameMap {
		tokenNames = append(tokenNames, tokenName)
	}
	sort.Strings(tokenNames)
	g.tokenNames = tokenNames
	return nil
}
