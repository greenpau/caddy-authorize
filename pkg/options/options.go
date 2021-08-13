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

package options

// TokenValidatorOptions provides options for TokenValidator.
type TokenValidatorOptions struct {
	ValidateSourceAddress       bool `json:"validate_source_address,omitempty" xml:"validate_source_address,omitempty" yaml:"validate_source_address,omitempty"`
	ValidateBearerHeader        bool `json:"validate_bearer_header,omitempty" xml:"validate_bearer_header,omitempty" yaml:"validate_bearer_header,omitempty"`
	ValidateMethodPath          bool `json:"validate_method_path,omitempty" xml:"validate_method_path,omitempty" yaml:"validate_method_path,omitempty"`
	ValidateAccessListPathClaim bool `json:"validate_access_list_path_claim,omitempty" xml:"validate_access_list_path_claim,omitempty" yaml:"validate_access_list_path_claim,omitempty"`
}

// TokenGrantorOptions provides options for TokenGrantor.
type TokenGrantorOptions struct {
	EnableSourceAddress bool `json:"enable_source_address,omitempty" xml:"enable_source_address,omitempty" yaml:"enable_source_address,omitempty"`
}

// NewTokenValidatorOptions returns an instance of TokenValidatorOptions
func NewTokenValidatorOptions() *TokenValidatorOptions {
	return &TokenValidatorOptions{}
}

// NewTokenGrantorOptions returns an instance of TokenGrantorOptions
func NewTokenGrantorOptions() *TokenGrantorOptions {
	return &TokenGrantorOptions{}
}
