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

package testutils

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	// "github.com/greenpau/caddy-auth-jwt/pkg/options"
	"time"
)

// InjectedTestToken is an instance of injected token.
type InjectedTestToken struct {
	Name string
	// The locations to inject a token in this test.
	Location string
	// The basic user claims.
	Claims *claims.UserClaims
}

// PopulateDefaultClaims adds exp, iat, nbf claims to a user claim set.
func PopulateDefaultClaims(uc *claims.UserClaims) {
	if uc == nil {
		panic(errors.ErrClaimNil)
	}
	uc.ExpiresAt = time.Now().Add(10 * time.Minute).Unix()
	uc.IssuedAt = time.Now().Add(10 * time.Minute * -1).Unix()
	uc.NotBefore = time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()
}

// NewTestGuestAccessList return ACL with guest access.
func NewTestGuestAccessList() *acl.AccessList {

	accessList := acl.NewAccessList()
	accessListEntry := acl.NewAccessListEntry()
	accessListEntry.Allow()
	if err := accessListEntry.SetClaim("roles"); err != nil {
		panic(err)
	}
	for _, v := range []string{"anonymous", "guest"} {
		if err := accessListEntry.AddValue(v); err != nil {
			panic(err)
		}
	}
	if err := accessList.Add(accessListEntry); err != nil {
		panic(err)
	}
	return accessList
}

// NewTestKeyManager returns an instance of key manager
func NewTestKeyManagers(method string, secret interface{}) []*kms.KeyManager {
	tokenConfig, err := kms.NewTokenConfig(method, secret)
	if err != nil {
		panic(err)
	}
	keyManager, err := kms.NewKeyManager(tokenConfig)
	if err != nil {
		panic(err)
	}
	return []*kms.KeyManager{keyManager}
}
