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

package acl

import (
	"context"
	"fmt"
	"github.com/greenpau/caddy-authorize/internal/tests"
	logutils "github.com/greenpau/caddy-authorize/pkg/utils/log"
	"testing"
)

func TestNewAccessList(t *testing.T) {
	var testcases = []struct {
		name         string
		config       []*RuleConfiguration
		batch        bool
		defaultAllow bool
		input        map[string]interface{}
		want         map[string]interface{}
		shouldErr    bool
		err          error
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
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with batched conditions",
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
		{
			name: "new access list with default allow",
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
			defaultAllow: true,
			input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with invalid conditions",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"",
						"",
					},
					Action: `allow any stop log`,
				},
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, failed to extract condition tokens: EOF"),
		},
		{
			name: "new access list with invalid batched conditions",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"",
						"",
					},
					Action: `allow any stop log`,
				},
			},
			batch:     true,
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, failed to extract condition tokens: EOF"),
		},

		{
			name: "new access list with allow verdict",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `allow any log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": true,
			},
		},
		{
			name: "new access list with deny verdict",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `deny any log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": false,
			},
		},
		{
			name: "new access list with deny and stop verdict",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `deny any stop log`,
				},
			},
			input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"allow": false,
			},
		},
		{
			name: "new access list with default deny",
			config: []*RuleConfiguration{
				{
					Comment: "foobar barfoo",
					Conditions: []string{
						"exact match roles foobar",
						"exact match org nyc",
					},
					Action: `deny any stop log`,
				},
			},
			input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"allow": false,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			ctx := context.Background()
			logger := logutils.NewLogger()
			accessList := NewAccessList()
			accessList.SetLogger(logger)
			if tc.defaultAllow {
				accessList.SetDefaultAllowAction()
			}
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

			tc.want["rule_count"] = len(tc.config)
			got := make(map[string]interface{})
			got["allow"] = accessList.Allow(ctx, tc.input)
			got["rule_count"] = len(accessList.GetRules())

			tests.EvalObjects(t, "eval", tc.want, got)
		})
	}
}
