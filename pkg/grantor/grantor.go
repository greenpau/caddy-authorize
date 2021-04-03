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
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	kms "github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"sort"
)

// TokenGrantor creates and issues JWT tokens.
type TokenGrantor struct {
	keyManagers []*kms.KeyManager
	tokenNames  []string
}

// NewTokenGrantor returns an instance of TokenGrantor
func NewTokenGrantor() *TokenGrantor {
	return &TokenGrantor{}
}

// GetTokenNames returns a sorted list of token names.
func (g *TokenGrantor) GetTokenNames() []string {
	return g.tokenNames
}

// AddKeyManager adds kms.KeyManager instance to TokenGrantor.
func (g *TokenGrantor) AddKeyManager(keyManager *kms.KeyManager) {
	g.keyManagers = append(g.keyManagers, keyManager)
	g.rebase()
}

// Validate check whether TokenGrantor has valid configuration.
func (g *TokenGrantor) Validate() error {
	if len(g.keyManagers) == 0 {
		return jwterrors.ErrTokenGrantorEmpty
	}
	return nil
}

// GrantToken returns a signed token from user claims
func (g *TokenGrantor) GrantToken(userClaims *jwtclaims.UserClaims) (string, error) {
	return g.GrantTokenWithMethod(nil, userClaims)
}

// GrantTokenWithMethod returns a signed token from user claims and supplied method.
func (g *TokenGrantor) GrantTokenWithMethod(method interface{}, userClaims *jwtclaims.UserClaims) (string, error) {
	if userClaims == nil {
		return "", jwterrors.ErrNoClaims
	}
	for _, keyManager := range g.keyManagers {
		signMethod, signOK := keyManager.CanSign(method)
		if !signOK {
			continue
		}
		return keyManager.SignToken(signMethod, *userClaims)
	}
	return "", jwterrors.ErrTokenGrantorNoSigningKeysFound
}

func (g *TokenGrantor) rebase() {
	tokenNames := []string{}
	tokenNameMap := make(map[string]bool)
	for _, keyManager := range g.keyManagers {
		if keyManager.TokenName == "" {
			continue
		}
		tokenNameMap[keyManager.TokenName] = true
	}
	for tokenName := range tokenNameMap {
		tokenNames = append(tokenNames, tokenName)
	}
	sort.Strings(tokenNames)
	g.tokenNames = tokenNames
}
