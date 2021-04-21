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

package validator

import (
	"context"
	"net/http"
	"strings"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/cache"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"
)

type guardian interface {
	authorize(context.Context, *http.Request, *user.User) error
}

type guardianBase struct {
	accessList *acl.AccessList
}

type guardianWithSrcAddr struct {
	accessList *acl.AccessList
}

type guardianWithPathClaim struct {
	accessList *acl.AccessList
}

type guardianWithMethodPath struct {
	accessList *acl.AccessList
}

type guardianWithSrcAddrPathClaim struct {
	accessList *acl.AccessList
}

type guardianWithMethodPathSrcAddr struct {
	accessList *acl.AccessList
}

type guardianWithMethodPathPathClaim struct {
	accessList *acl.AccessList
}

type guardianWithMethodPathSrcAddrPathClaim struct {
	accessList *acl.AccessList
}

// TokenValidator validates tokens in http requests.
type TokenValidator struct {
	keystore        *kms.Keystore
	authHeaders     map[string]interface{}
	authCookies     map[string]interface{}
	authQueryParams map[string]interface{}
	cache           *cache.TokenCache
	accessList      *acl.AccessList
	guardian        guardian
	tokenSources    []string
	opts            *options.TokenValidatorOptions
}

// NewTokenValidator returns an instance of TokenValidator
func NewTokenValidator() *TokenValidator {
	v := &TokenValidator{
		keystore:        kms.NewKeystore(),
		authHeaders:     make(map[string]interface{}),
		authCookies:     make(map[string]interface{}),
		authQueryParams: make(map[string]interface{}),
	}

	for _, name := range defaultTokenNames {
		v.authHeaders[name] = true
		v.authCookies[name] = true
		v.authQueryParams[name] = true
	}

	v.cache = cache.NewTokenCache()
	v.tokenSources = defaultTokenSources
	return v
}

// GetAuthCookies returns auth cookies registered with TokenValidator.
func (v *TokenValidator) GetAuthCookies() map[string]interface{} {
	return v.authCookies
}

// SetAllowedTokenNames sets the names of the tokens evaluated
// by TokenValidator.
func (v *TokenValidator) SetAllowedTokenNames(arr []string) error {
	if len(arr) == 0 {
		return errors.ErrTokenNamesNotFound
	}
	m := make(map[string]bool)
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s == "" {
			return errors.ErrEmptyTokenName
		}
		if _, exists := m[s]; exists {
			return errors.ErrDuplicateTokenName.WithArgs(s)
		}
		m[s] = true
	}
	v.clearAuthSources()
	for _, s := range arr {
		v.authHeaders[s] = true
		v.authCookies[s] = true
		v.authQueryParams[s] = true
	}
	return nil
}

// SetSourcePriority sets the order in which various token sources are being
// evaluated for the presence of keys. The default order is cookie, header,
// and query parameters.
func (v *TokenValidator) SetSourcePriority(arr []string) error {
	if len(arr) == 0 || len(arr) > 3 {
		return errors.ErrInvalidSourcePriority
	}
	m := make(map[string]bool)
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s != tokenSourceHeader && s != tokenSourceCookie && s != tokenSourceQuery {
			return errors.ErrInvalidSourceName.WithArgs(s)
		}
		if _, exists := m[s]; exists {
			return errors.ErrDuplicateSourceName.WithArgs(s)
		}
		m[s] = true
	}
	v.tokenSources = arr
	return nil
}

// GetSourcePriority returns the allowed token sources in their priority order.
func (v *TokenValidator) GetSourcePriority() []string {
	return v.tokenSources
}

func (g *guardianBase) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	return nil
}

func (g *guardianWithSrcAddr) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := utils.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}
	return nil
}

func (g *guardianWithPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

func (g *guardianWithSrcAddrPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := utils.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}
	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

func (g *guardianWithMethodPath) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	return nil
}

func (g *guardianWithMethodPathSrcAddr) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := utils.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}
	return nil
}

func (g *guardianWithMethodPathPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

func (g *guardianWithMethodPathSrcAddrPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := utils.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}

	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

// Configure adds access list and keys for the verification of tokens.
func (v *TokenValidator) Configure(ctx context.Context, keys []*kms.Key, accessList *acl.AccessList, opts *options.TokenValidatorOptions) error {
	if err := v.addKeys(ctx, keys); err != nil {
		return err
	}
	if err := v.addAccessList(ctx, accessList); err != nil {
		return err
	}
	if opts == nil {
		return errors.ErrTokenValidatorOptionsNotFound
	}

	v.opts = opts

	switch {
	case opts.ValidateMethodPath && opts.ValidateSourceAddress && opts.ValidateAccessListPathClaim:
		g := &guardianWithMethodPathSrcAddrPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateMethodPath && opts.ValidateAccessListPathClaim:
		g := &guardianWithMethodPathPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateMethodPath && opts.ValidateSourceAddress:
		g := &guardianWithMethodPathSrcAddr{accessList: accessList}
		v.guardian = g
	case opts.ValidateSourceAddress && opts.ValidateAccessListPathClaim:
		g := &guardianWithSrcAddrPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateAccessListPathClaim:
		g := &guardianWithPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateMethodPath:
		g := &guardianWithMethodPath{accessList: accessList}
		v.guardian = g
	case opts.ValidateSourceAddress:
		g := &guardianWithSrcAddr{accessList: accessList}
		v.guardian = g
	default:
		g := &guardianBase{accessList: accessList}
		v.guardian = g
	}
	return nil
}

func (v *TokenValidator) addAccessList(ctx context.Context, accessList *acl.AccessList) error {
	if accessList == nil {
		return errors.ErrNoAccessList
	}
	if len(accessList.GetRules()) == 0 {
		return errors.ErrAccessListNoRules
	}

	v.accessList = accessList
	return nil
}

func (v *TokenValidator) addKeys(ctx context.Context, keys []*kms.Key) error {
	var tokenNames []string
	tokenMap := make(map[string]bool)
	if len(keys) == 0 {
		return errors.ErrValidatorKeystoreNoKeys
	}
	for _, k := range keys {
		if !k.Verify.Token.Capable {
			continue
		}
		if k.Verify.Token.Name == "" {
			continue
		}
		if k.Verify.Token.MaxLifetime == 0 {
			continue
		}
		v.keystore.AddKey(k)
		tokenMap[k.Verify.Token.Name] = true
	}
	if len(tokenMap) == 0 {
		return errors.ErrValidatorKeystoreNoVerifyKeys
	}

	for k := range tokenMap {
		tokenNames = append(tokenNames, k)
	}

	if err := v.SetAllowedTokenNames(tokenNames); err != nil {
		return err
	}

	return nil
}

// CacheUser adds a user to token validator cache.
func (v *TokenValidator) CacheUser(usr *user.User) error {
	return v.cache.Add(usr.Token, usr)
}
