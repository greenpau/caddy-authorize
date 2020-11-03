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
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

// TokenGrantor creates and issues JWT tokens.
type TokenGrantor struct {
	jwtconfig.CommonTokenConfig
}

// NewTokenGrantor returns an instance of TokenGrantor
func NewTokenGrantor() *TokenGrantor {
	g := &TokenGrantor{}
	return g
}

// Validate check whether TokenGrantor has valid configuration.
func (g *TokenGrantor) Validate() error {
	if g.TokenSecret == "" {
		return jwterrors.ErrEmptySecret
	}

	return nil
}

// GrantToken returns a signed token from user claims
func (g *TokenGrantor) GrantToken(method string, userClaims *jwtclaims.UserClaims) (string, error) {
	if _, exists := jwtconfig.SigningMethods[method]; !exists {
		return "", jwterrors.ErrUnsupportedSigningMethod.WithArgs(method)
	}
	if userClaims == nil {
		return "", jwterrors.ErrNoClaims
	}
	if g.TokenSecret == "" {
		return "", jwterrors.ErrEmptySecret
	}
	return userClaims.GetToken(method, []byte(g.TokenSecret))
}
