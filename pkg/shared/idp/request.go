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

package idp

// ProviderResponse is a response from an identity provider.
type ProviderResponse struct {
	Name    string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Payload string `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
}

// ProviderRequest is a request to an identity provider.
type ProviderRequest struct {
	Address  string           `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Context  string           `json:"context,omitempty" xml:"context,omitempty" yaml:"context,omitempty"`
	Realm    string           `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Secret   string           `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Response ProviderResponse `json:"response,omitempty" xml:"response,omitempty" yaml:"response,omitempty"`
}

func (r *ProviderRequest) applyDefaults() {
	if r.Context == "" {
		r.Context = "default"
	}
}
