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

import (
	"fmt"
	"github.com/greenpau/caddy-authorize/internal/tests"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"testing"
)

func TestParseIdentityProviderConfig(t *testing.T) {
	var testcases = []struct {
		name      string
		config    []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "basic and api key auth with realms",
			config: []string{
				"basic auth realm foo",
				"api key auth realm bar",
			},
			want: map[string]interface{}{
				"config": &IdentityProviderConfig{
					Context: "default",
					BasicAuth: BasicAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"foo": true,
						},
					},
					APIKeyAuth: APIKeyAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"bar": true,
						},
					},
				},
			},
		},
		{
			name: "basic and api key auth with default realm",
			config: []string{
				"basic auth",
				"api key auth",
			},
			want: map[string]interface{}{
				"config": &IdentityProviderConfig{
					Context: "default",
					BasicAuth: BasicAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"local": true,
						},
					},
					APIKeyAuth: APIKeyAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"local": true,
						},
					},
				},
			},
		},
		{
			name: "basic and api key auth with foo realm in bar context",
			config: []string{
				"basic auth realm foo context bar",
				"api key auth realm foo context bar",
			},
			want: map[string]interface{}{
				"config": &IdentityProviderConfig{
					Context: "bar",
					BasicAuth: BasicAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"foo": true,
						},
					},
					APIKeyAuth: APIKeyAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"foo": true,
						},
					},
				},
			},
		},
		{
			name: "invalid config",
			config: []string{
				"foo",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigInvalid.WithArgs("foo"),
		},
		{
			name:      "empty config",
			config:    []string{},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigInvalid.WithArgs("empty config"),
		},
		{
			name:      "malformed config with incomplete realm",
			config:    []string{"basic auth realm"},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigInvalid.WithArgs("basic auth realm"),
		},
		{
			name:      "malformed config with unsupported keyword",
			config:    []string{"basic auth realm foo bar baz"},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigInvalid.WithArgs("basic auth realm foo bar baz"),
		},
		{
			name:      "malformed config with bad encoding",
			config:    []string{`basic auth realm foo bar "baz`},
			shouldErr: true,
			err:       fmt.Errorf(`record on line 1; parse error on line 2, column 0: extraneous or missing " in quoted-field`),
		},
		{
			name: "malformed config with multiple contexts",
			config: []string{
				"basic auth realm local context foo",
				"api key auth realm local context bar",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigInvalid.WithArgs("multiple contexts"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %v", tc.config))
			config, err := ParseIdentityProviderConfig(tc.config)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["config"] = config
			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}
