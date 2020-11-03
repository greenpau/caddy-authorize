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

package errors

// Generic Errors
const (
	ErrEmptyACLAction              StandardError = "empty access list action"
	ErrEmptyACLClaim               StandardError = "empty access list claim"
	ErrEmptyMethod                 StandardError = "empty http method"
	ErrEmptyPath                   StandardError = "empty http path"
	ErrEmptyClaim                  StandardError = "empty claim value"
	ErrEmptyValue                  StandardError = "empty value"
	ErrNoValues                    StandardError = "no acl.Values"
	ErrUnsupportedACLAction        StandardError = "unsupported access list action: %s"
	ErrUnsupportedClaim            StandardError = "access list does not support %s claim, only roles"
	ErrUnsupportedMethod           StandardError = "unsupported http method: %s"
	ErrKeyIDNotFound               StandardError = "key ID not found"
	ErrUnsupportedKeyType          StandardError = "unsupported key type %T for key ID %s"
	ErrRSAKeysNotFound             StandardError = "no RSA keys found"
	ErrEmptySecret                 StandardError = "grantor token secret not configured"
	ErrNoClaims                    StandardError = "provided claims are nil"
	ErrUnsupportedSigningMethod    StandardError = "grantor does not support %s token signing method"
	ErrUnknownConfigSource         StandardError = "sig key config source is not found"
	ErrReadPEMFile                 StandardError = "(source: %s): read PEM file: %v"
	ErrWalkDir                     StandardError = "walking directory: %v"
	ErrProvisonFailed              StandardError = "authorization provider provisioning error"
	ErrEmptyProviderName           StandardError = "authorization provider name is empty"
	ErrNoMemberReference           StandardError = "no member reference found"
	ErrTooManyPrimaryInstances     StandardError = "found more than one primaryInstance instance of the plugin for %s context"
	ErrUndefinedSecret             StandardError = "%s: token keys and secrets must be defined either via environment variables or via token_ configuration element"
	ErrInvalidConfiguration        StandardError = "%s: default access list configuration error: %s"
	ErrUnsupportedSignatureMethod  StandardError = "%s: unsupported token sign/verify method: %s"
	ErrUnsupportedTokenSource      StandardError = "%s: unsupported token source: %s"
	ErrInvalidBackendConfiguration StandardError = "%s: token validator configuration error: %s"
	ErrUnknownProvider             StandardError = "authorization provider %s not found"
	ErrInvalidProvider             StandardError = "authorization provider %s is nil"
	ErrNoPrimaryInstanceProvider   StandardError = "no primaryInstance authorization provider found in %s context when configuring %s"
	ErrNoTrustedTokensFound        StandardError = "no trusted tokens found in %s context"
	ErrLoadingKeys                 StandardError = "loading %s keys: %v"
	ErrInvalidClaimExpiresAt       StandardError = "invalid exp type"
	ErrInvalidClaimIssuedAt        StandardError = "invalid iat type"
	ErrInvalidClaimNotBefore       StandardError = "invalid nbf type"
	ErrInvalidSigningMethod        StandardError = "unsupported signing method"
	ErrUnsupportedSecret           StandardError = "empty secrets are not supported"
	ErrInvalidRole                 StandardError = "invalid role type %T in roles"
	ErrInvalidRoleType             StandardError = "invalid roles type %T"
	ErrInvalidOrg                  StandardError = "invalid org type %T in orgs"
	ErrInvalidOrgType              StandardError = "invalid orgs type %T"
	ErrInvalidAppMetadataRoleType  StandardError = "invalid roles type %T in app_metadata-authorization"
	ErrInvalidAddrType             StandardError = "invalid ip address type %T in addr"
	ErrInvalidAccessListPath       StandardError = "invalid acl path type %T in paths"
	ErrSigningOptionsNotFound      StandardError = "signing options not found"
	ErrSigningMethodNotFound       StandardError = "signing method not found"
	ErrSharedSigningKeyNotFound    StandardError = "shared secret for signing not found"
	ErrPrivateSigningKeyNotFound   StandardError = "private key for signing not found"
	ErrNoBackends                  StandardError = "no token backends available"
	ErrExpiredToken                StandardError = "expired token"
	ErrNoAccessList                StandardError = "user role is valid, but denied by default deny on empty access list"
	ErrAccessNotAllowed            StandardError = "user role is valid, but not allowed by access list"
	ErrAccessNotAllowedByPathACL   StandardError = "user role is valid, but not allowed by path access list"
	ErrSourceAddressNotFound       StandardError = "source ip validation is enabled, but no ip address claim found"
	ErrSourceAddressMismatch       StandardError = "source ip address mismatch between the claim %s and request %s"
	ErrNoParsedClaims              StandardError = "failed to extract claims"
	ErrNoTokenFound                StandardError = "no token found"
	ErrInvalidParsedClaims         StandardError = "failed to extract claims: %s"
	ErrInvalidSecret               StandardError = "secret key backend error: %s"
	ErrInvalid                     StandardError = "%v"
)
