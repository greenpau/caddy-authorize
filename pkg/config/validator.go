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

package config

// TokenValidatorOptions provides options for TokenValidator
type TokenValidatorOptions struct {
    ValidateSourceAddress       bool
    SourceAddress               string
    ValidateBearerHeader        bool
    ValidateMethodPath          bool
    ValidateAccessListPathClaim bool
    Metadata                    map[string]interface{}
}

// NewTokenValidatorOptions returns an instance of TokenValidatorOptions
func NewTokenValidatorOptions() *TokenValidatorOptions {
    opts := &TokenValidatorOptions{
        ValidateSourceAddress: false,
    }
    return opts
}

// Clone makes a copy of TokenValidatorOptions without metadata.
func (opts *TokenValidatorOptions) Clone() *TokenValidatorOptions {
    clonedOpts := &TokenValidatorOptions{
        ValidateSourceAddress:       opts.ValidateSourceAddress,
        ValidateBearerHeader:        opts.ValidateBearerHeader,
        ValidateMethodPath:          opts.ValidateMethodPath,
        ValidateAccessListPathClaim: opts.ValidateAccessListPathClaim,
        Metadata:                    make(map[string]interface{}),
    }
    return clonedOpts
}
