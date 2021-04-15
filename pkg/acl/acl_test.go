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

package acl

import (
	"context"
	// "fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"
	// "reflect"
	// "strings"
	"testing"
)

func TestNewAccessList(t *testing.T) {
	var testcases = []struct {
		name      string
		config    []*RuleConfiguration
		batch     bool
		input     map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "new access list with logging",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `allow any stop log`,
				},
			},
			batch: true,
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			ctx := context.Background()
			logger := utils.NewLogger()
			accessList := NewAccessList()
			accessList.SetLogger(logger)
			if tc.batch {
				err = accessList.AddRules(ctx, tc.config)
				if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
					return
				}
			} else {
				for _, rule := range tc.config {
					err = accessList.AddRule(ctx, rule)
					if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
						return
					}
				}
			}

			got := make(map[string]interface{})
			got["allow"] = accessList.Allow(ctx, tc.input)

			tests.EvalObjects(t, "eval", tc.want, got)
		})
	}
}
