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
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"
	"reflect"
	"strings"
	"testing"
)

func TestNewAclRule(t *testing.T) {
	var testcases = []struct {
		name           string
		config         *RuleConfiguration
		loggerDisabled bool
		want           map[string]interface{}
		shouldErr      bool
		err            error
	}{
		{name: "allow any and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowMatchAnyStop",
				"config_rule_type":      "aclRuleAllowMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow any and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowMatchAllStop",
				"config_rule_type":      "aclRuleAllowMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow all and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowStop",
				"config_rule_type":      "aclRuleAllowStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowMatchAny",
				"config_rule_type":      "aclRuleAllowMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow any without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowMatchAll",
				"config_rule_type":      "aclRuleAllowMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow all without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllow",
				"config_rule_type":      "aclRuleAllow",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow any and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow any and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow any and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow any and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow all and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow all and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow all and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow all and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerStop",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerStop",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerStop",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerStop",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerMatchAny",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow any with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerMatchAny",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow any with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerMatchAny",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow any with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerMatchAny",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow any with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerMatchAll",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow all with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerMatchAll",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow all with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerMatchAll",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow all with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerMatchAll",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow all with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLogger",
				"config_rule_type":      "aclRuleAllowWithDebugLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLogger",
				"config_rule_type":      "aclRuleAllowWithInfoLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLogger",
				"config_rule_type":      "aclRuleAllowWithWarnLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLogger",
				"config_rule_type":      "aclRuleAllowWithErrorLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithCounterMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow any and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithCounterMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow all and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithCounterStop",
				"config_rule_type":      "aclRuleAllowWithCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithCounterMatchAny",
				"config_rule_type":      "aclRuleAllowWithCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow any with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithCounterMatchAll",
				"config_rule_type":      "aclRuleAllowWithCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow all with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithCounter",
				"config_rule_type":      "aclRuleAllowWithCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed allow with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow any and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow any and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow any and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow any and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any stop counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow all and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow all and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow all and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow all and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow stop counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerCounterStop",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerCounterStop",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerCounterStop",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerCounterStop",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow stop counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow any with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow any with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow any with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow any with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow any with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow any with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow any counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow all with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow all with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow all with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow all with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow all with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `allow counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "allow with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithDebugLoggerCounter",
				"config_rule_type":      "aclRuleAllowWithDebugLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed allow with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithInfoLoggerCounter",
				"config_rule_type":      "aclRuleAllowWithInfoLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed allow with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithWarnLoggerCounter",
				"config_rule_type":      "aclRuleAllowWithWarnLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed allow with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "allow with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleAllowWithErrorLoggerCounter",
				"config_rule_type":      "aclRuleAllowWithErrorLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionAllow",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed allow with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `allow counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyMatchAnyStop",
				"config_rule_type":      "aclRuleDenyMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny any and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyMatchAllStop",
				"config_rule_type":      "aclRuleDenyMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny all and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyStop",
				"config_rule_type":      "aclRuleDenyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny and stop processing without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyMatchAny",
				"config_rule_type":      "aclRuleDenyMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny any without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyMatchAll",
				"config_rule_type":      "aclRuleDenyMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny all without counter and logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDeny",
				"config_rule_type":      "aclRuleDeny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny without counter and logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny any and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny any and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny any and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny any and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny all and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny all and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny all and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny all and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerStop",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny and stop processing with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log tag foobar`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerStop",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"tag":                   "foobar",
				"log_level":             "info",
			},
		}, {name: "failed deny and stop processing with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop log tag foobar`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerStop",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny and stop processing with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerStop",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny and stop processing with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerMatchAny",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny any with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerMatchAny",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny any with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerMatchAny",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny any with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerMatchAny",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny any with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerMatchAll",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny all with debug logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerMatchAll",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny all with info logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerMatchAll",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny all with warn logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerMatchAll",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny all with error logging and without counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLogger",
				"config_rule_type":      "aclRuleDenyWithDebugLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny with debug logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLogger",
				"config_rule_type":      "aclRuleDenyWithInfoLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny with info logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLogger",
				"config_rule_type":      "aclRuleDenyWithWarnLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny with warn logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLogger",
				"config_rule_type":      "aclRuleDenyWithErrorLogger",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny with error logging and without counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithCounterMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny any and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithCounterMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny all and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithCounterStop",
				"config_rule_type":      "aclRuleDenyWithCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny and stop processing with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithCounterMatchAny",
				"config_rule_type":      "aclRuleDenyWithCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny any with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithCounterMatchAll",
				"config_rule_type":      "aclRuleDenyWithCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny all with counter and without logging",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithCounter",
				"config_rule_type":      "aclRuleDenyWithCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
			},
		}, {name: "failed deny with counter and without logging",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny counter`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny any and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny any and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny any and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny any and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any stop counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny all and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny all and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny all and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerCounterMatchAllStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny all and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny stop counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerCounterStop",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny and stop processing with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerCounterStop",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny and stop processing with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerCounterStop",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny and stop processing with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerCounterStop",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerCounterStop",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny and stop processing with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny stop counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny any with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny any with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny any with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny any with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny any with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerCounterMatchAny",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny any with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny any counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny all with debug logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny all with info logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny all with warn logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny all with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerCounterMatchAll",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny all with error logging and with counter",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"foo org nyc",
				},
				Action: `deny counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: foo org nyc"),
		}, {name: "deny with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log debug`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithDebugLoggerCounter",
				"config_rule_type":      "aclRuleDenyWithDebugLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "debug",
			},
		}, {name: "failed deny with debug logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny counter log debug`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log info`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithInfoLoggerCounter",
				"config_rule_type":      "aclRuleDenyWithInfoLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "info",
			},
		}, {name: "failed deny with info logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny counter log info`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log warn`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithWarnLoggerCounter",
				"config_rule_type":      "aclRuleDenyWithWarnLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "warn",
			},
		}, {name: "failed deny with warn logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny counter log warn`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {name: "deny with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log error`,
			},
			want: map[string]interface{}{
				"rule_type":             "*acl.aclRuleDenyWithErrorLoggerCounter",
				"config_rule_type":      "aclRuleDenyWithErrorLoggerCounter",
				"comment":               "foobar barfoo",
				"action_name":           "ruleActionDeny",
				"default_verdict_name":  "ruleVerdictUnknown",
				"reserved_verdict_name": "ruleVerdictReserved",
				"default_action_name":   "ruleActionUnknown",
				"reserved_action_name":  "ruleActionReserved",
				"log_level":             "error",
			},
		}, {name: "failed deny with error logging and with counter",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact roles foobar"},
				Action:     `deny counter log error`,
			},
			shouldErr: true,
			err:       fmt.Errorf("invalid rule syntax, invalid condition syntax, match not found: exact roles foobar"),
		}, {
			name: "invalid rule syntax failed to extract condition tokens",
			config: &RuleConfiguration{
				Conditions: []string{
					"",
				}, Action: "deny",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, failed to extract condition tokens: empty"),
		}, {
			name: "invalid rule syntax duplicate field in conditions",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
					"match roles anonymous guest",
				}, Action: "deny",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, duplicate field: roles"),
		}, {
			name: "invalid rule syntax failed to extract action tokens",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
				}, Action: "",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, failed to extract action tokens: empty"),
		}, {
			name: "invalid rule syntax, allow misplaced in action",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
				}, Action: "allow allow any",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, allow must preceed stop/counter/log directives"),
		}, {
			name: "invalid rule syntax, tag without value",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
				}, Action: "allow any tag",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, tag must be followed by value"),
		}, {
			name: "invalid rule syntax, unsupported keyword",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
				}, Action: "allow any foobar",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf(`invalid rule syntax, invalid "foobar" token`),
		}, {
			name: "invalid rule syntax, log with no logger available",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
				}, Action: "allow any log",
			},
			loggerDisabled: true,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, no logger found for log enabled rule: aclRuleAllowWithInfoLogger"),
		}, {
			name: "invalid rule syntax, no conditions",
			config: &RuleConfiguration{
				Action: "allow any log",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf("invalid rule syntax, no match conditions found"),
		}, {
			name: "invalid rule syntax, reserved action",
			config: &RuleConfiguration{
				Conditions: []string{
					"match roles anonymous guest",
				}, Action: "reserved any log",
			},
			loggerDisabled: false,
			shouldErr:      true,
			err:            fmt.Errorf(`invalid rule syntax, type "aclRuleReservedWithInfoLogger" is unsupported`),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var rule aclRule
			ctx := context.Background()
			// t.Logf(tc.name)
			logger := utils.NewLogger()
			if tc.loggerDisabled {
				logger = nil
			}
			parsedACLRule, err := newACLRule(ctx, 0, tc.config, logger)
			if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
				return
			}
			rule = parsedACLRule
			ruleConfig := rule.getConfig(ctx)
			got := make(map[string]interface{})
			got["rule_type"] = reflect.TypeOf(rule).String()
			got["config_rule_type"] = ruleConfig.ruleType
			got["comment"] = ruleConfig.comment
			if ruleConfig.logLevel != "" {
				got["log_level"] = ruleConfig.logLevel
			}
			if ruleConfig.tag == "foobar" {
				got["tag"] = ruleConfig.tag
			}
			got["action_name"] = getRuleActionName(ruleConfig.action)
			got["default_action_name"] = getRuleActionName(ruleActionUnknown)
			got["reserved_action_name"] = getRuleActionName(ruleActionReserved)
			got["default_verdict_name"] = getRuleVerdictName(ruleVerdictUnknown)
			got["reserved_verdict_name"] = getRuleVerdictName(ruleVerdictReserved)
			tests.EvalObjects(t, "output", tc.want, got)
		})
	}
}

func TestEvalAclRule(t *testing.T) {
	var testcases = []struct {
		name        string
		config      *RuleConfiguration
		input       map[string]interface{}
		want        map[string]interface{}
		emptyFields bool
		shouldErr   bool
		err         error
	}{
		{name: "allow any and stop processing without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAnyStop",
			},
		}, {name: "allow any and stop processing without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAnyStop",
			},
		}, {name: "allow any and stop processing without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAnyStop",
			},
		}, {name: "allow any and stop processing without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAnyStop",
			},
		}, {name: "allow any and stop processing without counter and logging with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowMatchAnyStop",
			},
		}, {name: "allow all and stop processing without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAllStop",
			},
		}, {name: "allow all and stop processing without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAllStop",
			},
		}, {name: "allow all and stop processing without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAllStop",
			},
		}, {name: "allow all and stop processing without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAllStop",
			},
		}, {name: "allow all and stop processing without counter and logging with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowMatchAllStop",
			},
		}, {name: "allow and stop processing without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowStop",
			},
		}, {name: "allow and stop processing without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowStop",
			},
		}, {name: "allow and stop processing without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowStop",
			},
		}, {name: "allow and stop processing without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowStop",
			},
		}, {name: "allow and stop processing without counter and logging with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowStop",
			},
		}, {name: "allow any without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAny",
			},
		}, {name: "allow any without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAny",
			},
		}, {name: "allow any without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAny",
			},
		}, {name: "allow any without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAny",
			},
		}, {name: "allow any without counter and logging with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowMatchAny",
			},
		}, {name: "allow all without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAll",
			},
		}, {name: "allow all without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowMatchAll",
			},
		}, {name: "allow all without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAll",
			},
		}, {name: "allow all without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowMatchAll",
			},
		}, {name: "allow all without counter and logging with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowMatchAll",
			},
		}, {name: "allow without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllow",
			},
		}, {name: "allow without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllow",
			},
		}, {name: "allow without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllow",
			},
		}, {name: "allow without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllow",
			},
		}, {name: "allow without counter and logging with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllow",
			},
		}, {name: "allow any and stop processing with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
			},
		}, {name: "allow all and stop processing with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
			},
		}, {name: "allow and stop processing with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerStop",
			},
		}, {name: "allow and stop processing with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerStop",
			},
		}, {name: "allow and stop processing with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerStop",
			},
		}, {name: "allow and stop processing with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerStop",
			},
		}, {name: "allow and stop processing with debug logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerStop",
			},
		}, {name: "allow and stop processing with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerStop",
			},
		}, {name: "allow and stop processing with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerStop",
			},
		}, {name: "allow and stop processing with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerStop",
			},
		}, {name: "allow and stop processing with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerStop",
			},
		}, {name: "allow and stop processing with info logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerStop",
			},
		}, {name: "allow and stop processing with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerStop",
			},
		}, {name: "allow and stop processing with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerStop",
			},
		}, {name: "allow and stop processing with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerStop",
			},
		}, {name: "allow and stop processing with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerStop",
			},
		}, {name: "allow and stop processing with warn logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerStop",
			},
		}, {name: "allow and stop processing with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerStop",
			},
		}, {name: "allow and stop processing with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerStop",
			},
		}, {name: "allow and stop processing with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerStop",
			},
		}, {name: "allow and stop processing with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerStop",
			},
		}, {name: "allow and stop processing with error logging and without counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerStop",
			},
		}, {name: "allow any with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAny",
			},
		}, {name: "allow any with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAny",
			},
		}, {name: "allow any with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAny",
			},
		}, {name: "allow any with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAny",
			},
		}, {name: "allow any with debug logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAny",
			},
		}, {name: "allow any with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAny",
			},
		}, {name: "allow any with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAny",
			},
		}, {name: "allow any with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAny",
			},
		}, {name: "allow any with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAny",
			},
		}, {name: "allow any with info logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAny",
			},
		}, {name: "allow any with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAny",
			},
		}, {name: "allow any with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAny",
			},
		}, {name: "allow any with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAny",
			},
		}, {name: "allow any with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAny",
			},
		}, {name: "allow any with warn logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAny",
			},
		}, {name: "allow any with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAny",
			},
		}, {name: "allow any with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAny",
			},
		}, {name: "allow any with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAny",
			},
		}, {name: "allow any with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAny",
			},
		}, {name: "allow any with error logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAny",
			},
		}, {name: "allow all with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAll",
			},
		}, {name: "allow all with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAll",
			},
		}, {name: "allow all with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAll",
			},
		}, {name: "allow all with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerMatchAll",
			},
		}, {name: "allow all with debug logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAll",
			},
		}, {name: "allow all with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAll",
			},
		}, {name: "allow all with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAll",
			},
		}, {name: "allow all with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAll",
			},
		}, {name: "allow all with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerMatchAll",
			},
		}, {name: "allow all with info logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAll",
			},
		}, {name: "allow all with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAll",
			},
		}, {name: "allow all with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAll",
			},
		}, {name: "allow all with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAll",
			},
		}, {name: "allow all with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerMatchAll",
			},
		}, {name: "allow all with warn logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAll",
			},
		}, {name: "allow all with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAll",
			},
		}, {name: "allow all with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAll",
			},
		}, {name: "allow all with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAll",
			},
		}, {name: "allow all with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerMatchAll",
			},
		}, {name: "allow all with error logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAll",
			},
		}, {name: "allow with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLogger",
			},
		}, {name: "allow with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLogger",
			},
		}, {name: "allow with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLogger",
			},
		}, {name: "allow with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLogger",
			},
		}, {name: "allow with debug logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithDebugLogger",
			},
		}, {name: "allow with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLogger",
			},
		}, {name: "allow with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLogger",
			},
		}, {name: "allow with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLogger",
			},
		}, {name: "allow with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLogger",
			},
		}, {name: "allow with info logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithInfoLogger",
			},
		}, {name: "allow with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLogger",
			},
		}, {name: "allow with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLogger",
			},
		}, {name: "allow with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLogger",
			},
		}, {name: "allow with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLogger",
			},
		}, {name: "allow with warn logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithWarnLogger",
			},
		}, {name: "allow with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLogger",
			},
		}, {name: "allow with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLogger",
			},
		}, {name: "allow with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLogger",
			},
		}, {name: "allow with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLogger",
			},
		}, {name: "allow with error logging and without counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithErrorLogger",
			},
		}, {name: "allow any and stop processing with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with counter and without logging with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAnyStop",
			},
		}, {name: "allow all and stop processing with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with counter and without logging with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAllStop",
			},
		}, {name: "allow and stop processing with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterStop",
			},
		}, {name: "allow and stop processing with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterStop",
			},
		}, {name: "allow and stop processing with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterStop",
			},
		}, {name: "allow and stop processing with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterStop",
			},
		}, {name: "allow and stop processing with counter and without logging with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithCounterStop",
			},
		}, {name: "allow any with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAny",
			},
		}, {name: "allow any with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAny",
			},
		}, {name: "allow any with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAny",
			},
		}, {name: "allow any with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAny",
			},
		}, {name: "allow any with counter and without logging with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAny",
			},
		}, {name: "allow all with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAll",
			},
		}, {name: "allow all with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAll",
			},
		}, {name: "allow all with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAll",
			},
		}, {name: "allow all with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounterMatchAll",
			},
		}, {name: "allow all with counter and without logging with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithCounterMatchAll",
			},
		}, {name: "allow with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounter",
			},
		}, {name: "allow with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithCounter",
			},
		}, {name: "allow with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounter",
			},
		}, {name: "allow with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithCounter",
			},
		}, {name: "allow with counter and without logging with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithCounter",
			},
		}, {name: "allow any and stop processing with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with debug logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with info logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with warn logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "allow any and stop processing with error logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any stop counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "allow all and stop processing with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with debug logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with info logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with warn logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "allow all and stop processing with error logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow stop counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "allow and stop processing with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterStop",
			},
		}, {name: "allow and stop processing with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterStop",
			},
		}, {name: "allow and stop processing with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterStop",
			},
		}, {name: "allow and stop processing with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterStop",
			},
		}, {name: "allow and stop processing with debug logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterStop",
			},
		}, {name: "allow and stop processing with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterStop",
			},
		}, {name: "allow and stop processing with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterStop",
			},
		}, {name: "allow and stop processing with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterStop",
			},
		}, {name: "allow and stop processing with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterStop",
			},
		}, {name: "allow and stop processing with info logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterStop",
			},
		}, {name: "allow and stop processing with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterStop",
			},
		}, {name: "allow and stop processing with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterStop",
			},
		}, {name: "allow and stop processing with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterStop",
			},
		}, {name: "allow and stop processing with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterStop",
			},
		}, {name: "allow and stop processing with warn logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterStop",
			},
		}, {name: "allow and stop processing with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterStop",
			},
		}, {name: "allow and stop processing with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterStop",
			},
		}, {name: "allow and stop processing with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterStop",
			},
		}, {name: "allow and stop processing with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterStop",
			},
		}, {name: "allow and stop processing with error logging and with counter with allow stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow stop counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllowStop),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterStop",
			},
		}, {name: "allow any with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
			},
		}, {name: "allow any with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
			},
		}, {name: "allow any with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
			},
		}, {name: "allow any with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
			},
		}, {name: "allow any with debug logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
			},
		}, {name: "allow any with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
			},
		}, {name: "allow any with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
			},
		}, {name: "allow any with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
			},
		}, {name: "allow any with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
			},
		}, {name: "allow any with info logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
			},
		}, {name: "allow any with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
			},
		}, {name: "allow any with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
			},
		}, {name: "allow any with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
			},
		}, {name: "allow any with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
			},
		}, {name: "allow any with warn logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
			},
		}, {name: "allow any with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
			},
		}, {name: "allow any with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
			},
		}, {name: "allow any with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
			},
		}, {name: "allow any with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
			},
		}, {name: "allow any with error logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow any counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
			},
		}, {name: "allow all with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
			},
		}, {name: "allow all with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
			},
		}, {name: "allow all with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
			},
		}, {name: "allow all with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
			},
		}, {name: "allow all with debug logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
			},
		}, {name: "allow all with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
			},
		}, {name: "allow all with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
			},
		}, {name: "allow all with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
			},
		}, {name: "allow all with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
			},
		}, {name: "allow all with info logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
			},
		}, {name: "allow all with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
			},
		}, {name: "allow all with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
			},
		}, {name: "allow all with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
			},
		}, {name: "allow all with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
			},
		}, {name: "allow all with warn logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
			},
		}, {name: "allow all with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
			},
		}, {name: "allow all with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
			},
		}, {name: "allow all with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
			},
		}, {name: "allow all with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
			},
		}, {name: "allow all with error logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `allow counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
			},
		}, {name: "allow with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounter",
			},
		}, {name: "allow with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounter",
			},
		}, {name: "allow with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounter",
			},
		}, {name: "allow with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithDebugLoggerCounter",
			},
		}, {name: "allow with debug logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithDebugLoggerCounter",
			},
		}, {name: "allow with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounter",
			},
		}, {name: "allow with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounter",
			},
		}, {name: "allow with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounter",
			},
		}, {name: "allow with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithInfoLoggerCounter",
			},
		}, {name: "allow with info logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithInfoLoggerCounter",
			},
		}, {name: "allow with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounter",
			},
		}, {name: "allow with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounter",
			},
		}, {name: "allow with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounter",
			},
		}, {name: "allow with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithWarnLoggerCounter",
			},
		}, {name: "allow with warn logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithWarnLoggerCounter",
			},
		}, {name: "allow with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounter",
			},
		}, {name: "allow with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounter",
			},
		}, {name: "allow with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounter",
			},
		}, {name: "allow with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleAllowWithErrorLoggerCounter",
			},
		}, {name: "allow with error logging and with counter with allow verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `allow counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictAllow),
				"rule_type": "*acl.aclRuleAllowWithErrorLoggerCounter",
			},
		}, {name: "deny any and stop processing without counter and logging with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyMatchAnyStop",
			},
		}, {name: "deny any and stop processing without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAnyStop",
			},
		}, {name: "deny any and stop processing without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAnyStop",
			},
		}, {name: "deny any and stop processing without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAnyStop",
			},
		}, {name: "deny any and stop processing without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAnyStop",
			},
		}, {name: "deny all and stop processing without counter and logging with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyMatchAllStop",
			},
		}, {name: "deny all and stop processing without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAllStop",
			},
		}, {name: "deny all and stop processing without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAllStop",
			},
		}, {name: "deny all and stop processing without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAllStop",
			},
		}, {name: "deny all and stop processing without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAllStop",
			},
		}, {name: "deny and stop processing without counter and logging with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyStop",
			},
		}, {name: "deny and stop processing without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyStop",
			},
		}, {name: "deny and stop processing without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyStop",
			},
		}, {name: "deny and stop processing without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyStop",
			},
		}, {name: "deny and stop processing without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyStop",
			},
		}, {name: "deny any without counter and logging with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyMatchAny",
			},
		}, {name: "deny any without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAny",
			},
		}, {name: "deny any without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAny",
			},
		}, {name: "deny any without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAny",
			},
		}, {name: "deny any without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAny",
			},
		}, {name: "deny all without counter and logging with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyMatchAll",
			},
		}, {name: "deny all without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAll",
			},
		}, {name: "deny all without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyMatchAll",
			},
		}, {name: "deny all without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAll",
			},
		}, {name: "deny all without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyMatchAll",
			},
		}, {name: "deny without counter and logging with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDeny",
			},
		}, {name: "deny without counter and logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDeny",
			},
		}, {name: "deny without counter and logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDeny",
			},
		}, {name: "deny without counter and logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDeny",
			},
		}, {name: "deny without counter and logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDeny",
			},
		}, {name: "deny any and stop processing with debug logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
			},
		}, {name: "deny all and stop processing with debug logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
			},
		}, {name: "deny and stop processing with debug logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerStop",
			},
		}, {name: "deny and stop processing with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerStop",
			},
		}, {name: "deny and stop processing with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerStop",
			},
		}, {name: "deny and stop processing with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerStop",
			},
		}, {name: "deny and stop processing with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerStop",
			},
		}, {name: "deny and stop processing with info logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log tag foobar`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerStop",
			},
		}, {name: "deny and stop processing with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log tag foobar`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerStop",
			},
		}, {name: "deny and stop processing with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log tag foobar`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerStop",
			},
		}, {name: "deny and stop processing with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log tag foobar`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerStop",
			},
		}, {name: "deny and stop processing with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log tag foobar`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerStop",
			},
		}, {name: "deny and stop processing with warn logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerStop",
			},
		}, {name: "deny and stop processing with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerStop",
			},
		}, {name: "deny and stop processing with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerStop",
			},
		}, {name: "deny and stop processing with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerStop",
			},
		}, {name: "deny and stop processing with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerStop",
			},
		}, {name: "deny and stop processing with error logging and without counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerStop",
			},
		}, {name: "deny and stop processing with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerStop",
			},
		}, {name: "deny and stop processing with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerStop",
			},
		}, {name: "deny and stop processing with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerStop",
			},
		}, {name: "deny and stop processing with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerStop",
			},
		}, {name: "deny any with debug logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAny",
			},
		}, {name: "deny any with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAny",
			},
		}, {name: "deny any with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAny",
			},
		}, {name: "deny any with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAny",
			},
		}, {name: "deny any with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAny",
			},
		}, {name: "deny any with info logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAny",
			},
		}, {name: "deny any with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAny",
			},
		}, {name: "deny any with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAny",
			},
		}, {name: "deny any with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAny",
			},
		}, {name: "deny any with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAny",
			},
		}, {name: "deny any with warn logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAny",
			},
		}, {name: "deny any with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAny",
			},
		}, {name: "deny any with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAny",
			},
		}, {name: "deny any with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAny",
			},
		}, {name: "deny any with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAny",
			},
		}, {name: "deny any with error logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAny",
			},
		}, {name: "deny any with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAny",
			},
		}, {name: "deny any with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAny",
			},
		}, {name: "deny any with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAny",
			},
		}, {name: "deny any with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAny",
			},
		}, {name: "deny all with debug logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAll",
			},
		}, {name: "deny all with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAll",
			},
		}, {name: "deny all with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAll",
			},
		}, {name: "deny all with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAll",
			},
		}, {name: "deny all with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerMatchAll",
			},
		}, {name: "deny all with info logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAll",
			},
		}, {name: "deny all with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAll",
			},
		}, {name: "deny all with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAll",
			},
		}, {name: "deny all with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAll",
			},
		}, {name: "deny all with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerMatchAll",
			},
		}, {name: "deny all with warn logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAll",
			},
		}, {name: "deny all with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAll",
			},
		}, {name: "deny all with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAll",
			},
		}, {name: "deny all with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAll",
			},
		}, {name: "deny all with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerMatchAll",
			},
		}, {name: "deny all with error logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAll",
			},
		}, {name: "deny all with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAll",
			},
		}, {name: "deny all with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAll",
			},
		}, {name: "deny all with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAll",
			},
		}, {name: "deny all with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerMatchAll",
			},
		}, {name: "deny with debug logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithDebugLogger",
			},
		}, {name: "deny with debug logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLogger",
			},
		}, {name: "deny with debug logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLogger",
			},
		}, {name: "deny with debug logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLogger",
			},
		}, {name: "deny with debug logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLogger",
			},
		}, {name: "deny with info logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithInfoLogger",
			},
		}, {name: "deny with info logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLogger",
			},
		}, {name: "deny with info logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLogger",
			},
		}, {name: "deny with info logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLogger",
			},
		}, {name: "deny with info logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLogger",
			},
		}, {name: "deny with warn logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithWarnLogger",
			},
		}, {name: "deny with warn logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLogger",
			},
		}, {name: "deny with warn logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLogger",
			},
		}, {name: "deny with warn logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLogger",
			},
		}, {name: "deny with warn logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLogger",
			},
		}, {name: "deny with error logging and without counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithErrorLogger",
			},
		}, {name: "deny with error logging and without counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLogger",
			},
		}, {name: "deny with error logging and without counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLogger",
			},
		}, {name: "deny with error logging and without counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLogger",
			},
		}, {name: "deny with error logging and without counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLogger",
			},
		}, {name: "deny any and stop processing with counter and without logging with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAnyStop",
			},
		}, {name: "deny all and stop processing with counter and without logging with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAllStop",
			},
		}, {name: "deny and stop processing with counter and without logging with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithCounterStop",
			},
		}, {name: "deny and stop processing with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterStop",
			},
		}, {name: "deny and stop processing with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterStop",
			},
		}, {name: "deny and stop processing with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterStop",
			},
		}, {name: "deny and stop processing with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterStop",
			},
		}, {name: "deny any with counter and without logging with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAny",
			},
		}, {name: "deny any with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAny",
			},
		}, {name: "deny any with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAny",
			},
		}, {name: "deny any with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAny",
			},
		}, {name: "deny any with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAny",
			},
		}, {name: "deny all with counter and without logging with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAll",
			},
		}, {name: "deny all with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAll",
			},
		}, {name: "deny all with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounterMatchAll",
			},
		}, {name: "deny all with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAll",
			},
		}, {name: "deny all with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounterMatchAll",
			},
		}, {name: "deny with counter and without logging with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithCounter",
			},
		}, {name: "deny with counter and without logging with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounter",
			},
		}, {name: "deny with counter and without logging with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithCounter",
			},
		}, {name: "deny with counter and without logging with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounter",
			},
		}, {name: "deny with counter and without logging with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithCounter",
			},
		}, {name: "deny any and stop processing with debug logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "deny any and stop processing with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
			},
		}, {name: "deny all and stop processing with debug logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "deny all and stop processing with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
			},
		}, {name: "deny and stop processing with debug logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterStop",
			},
		}, {name: "deny and stop processing with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterStop",
			},
		}, {name: "deny and stop processing with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterStop",
			},
		}, {name: "deny and stop processing with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterStop",
			},
		}, {name: "deny and stop processing with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterStop",
			},
		}, {name: "deny and stop processing with info logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterStop",
			},
		}, {name: "deny and stop processing with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterStop",
			},
		}, {name: "deny and stop processing with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterStop",
			},
		}, {name: "deny and stop processing with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterStop",
			},
		}, {name: "deny and stop processing with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterStop",
			},
		}, {name: "deny and stop processing with warn logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterStop",
			},
		}, {name: "deny and stop processing with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterStop",
			},
		}, {name: "deny and stop processing with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterStop",
			},
		}, {name: "deny and stop processing with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterStop",
			},
		}, {name: "deny and stop processing with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterStop",
			},
		}, {name: "deny and stop processing with error logging and with counter with deny stop verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDenyStop),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterStop",
			},
		}, {name: "deny and stop processing with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterStop",
			},
		}, {name: "deny and stop processing with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterStop",
			},
		}, {name: "deny and stop processing with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterStop",
			},
		}, {name: "deny and stop processing with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny stop counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterStop",
			},
		}, {name: "deny any with debug logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
			},
		}, {name: "deny any with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
			},
		}, {name: "deny any with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
			},
		}, {name: "deny any with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
			},
		}, {name: "deny any with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
			},
		}, {name: "deny any with info logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
			},
		}, {name: "deny any with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
			},
		}, {name: "deny any with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
			},
		}, {name: "deny any with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
			},
		}, {name: "deny any with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
			},
		}, {name: "deny any with warn logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
			},
		}, {name: "deny any with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
			},
		}, {name: "deny any with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
			},
		}, {name: "deny any with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
			},
		}, {name: "deny any with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
			},
		}, {name: "deny any with error logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
			},
		}, {name: "deny any with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
			},
		}, {name: "deny any with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
			},
		}, {name: "deny any with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
			},
		}, {name: "deny any with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny any counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
			},
		}, {name: "deny all with debug logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
			},
		}, {name: "deny all with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
			},
		}, {name: "deny all with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
			},
		}, {name: "deny all with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
			},
		}, {name: "deny all with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
			},
		}, {name: "deny all with info logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
			},
		}, {name: "deny all with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
			},
		}, {name: "deny all with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
			},
		}, {name: "deny all with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
			},
		}, {name: "deny all with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
			},
		}, {name: "deny all with warn logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
			},
		}, {name: "deny all with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
			},
		}, {name: "deny all with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
			},
		}, {name: "deny all with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
			},
		}, {name: "deny all with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
			},
		}, {name: "deny all with error logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
				"org":   []string{"nyc"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
			},
		}, {name: "deny all with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
			},
		}, {name: "deny all with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
			},
		}, {name: "deny all with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
			},
		}, {name: "deny all with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment: "foobar barfoo",
				Conditions: []string{
					"exact match roles foobar",
					"exact match org nyc",
				},
				Action: `deny counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
			},
		}, {name: "deny with debug logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log debug`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounter",
			},
		}, {name: "deny with debug logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounter",
			},
		}, {name: "deny with debug logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithDebugLoggerCounter",
			},
		}, {name: "deny with debug logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log debug`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounter",
			},
		}, {name: "deny with debug logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log debug`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithDebugLoggerCounter",
			},
		}, {name: "deny with info logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log info`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounter",
			},
		}, {name: "deny with info logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounter",
			},
		}, {name: "deny with info logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithInfoLoggerCounter",
			},
		}, {name: "deny with info logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log info`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounter",
			},
		}, {name: "deny with info logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log info`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithInfoLoggerCounter",
			},
		}, {name: "deny with warn logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log warn`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounter",
			},
		}, {name: "deny with warn logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounter",
			},
		}, {name: "deny with warn logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithWarnLoggerCounter",
			},
		}, {name: "deny with warn logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log warn`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounter",
			},
		}, {name: "deny with warn logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log warn`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithWarnLoggerCounter",
			},
		}, {name: "deny with error logging and with counter with deny verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log error`,
			}, input: map[string]interface{}{
				"roles": []string{"foobar"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictDeny),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounter",
			},
		}, {name: "deny with error logging and with counter with continue verdict",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounter",
			},
		}, {name: "deny with error logging and with counter with continue verdict 1",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			want: map[string]interface{}{
				"verdict":   getRuleVerdictName(ruleVerdictContinue),
				"rule_type": "*acl.aclRuleDenyWithErrorLoggerCounter",
			},
		}, {name: "deny with error logging and with counter with continue verdict 2",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log error`,
			}, input: map[string]interface{}{
				"name":  "John Smith",
				"roles": []string{"barfoo"},
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounter",
			},
		}, {name: "deny with error logging and with counter with continue verdict 3",
			config: &RuleConfiguration{
				Comment:    "foobar barfoo",
				Conditions: []string{"exact match roles foobar"},
				Action:     `deny counter log error`,
			}, input: map[string]interface{}{
				"name": "John Smith",
			},
			emptyFields: true,
			want: map[string]interface{}{
				"verdict":      getRuleVerdictName(ruleVerdictContinue),
				"empty_fields": true,
				"rule_type":    "*acl.aclRuleDenyWithErrorLoggerCounter",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf(tc.name)
			var rule aclRule
			ctx := context.Background()
			logger := utils.NewLogger()
			parsedACLRule, err := newACLRule(ctx, 0, tc.config, logger)
			if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
				return
			}
			rule = parsedACLRule
			ruleType := reflect.TypeOf(rule).String()
			got := make(map[string]interface{})
			got["rule_type"] = ruleType
			if tc.emptyFields {
				got["empty_fields"] = tc.emptyFields
				if strings.Contains(ruleType, "Match") {
					rule.emptyFields(ctx)
				}
			}
			got["verdict"] = getRuleVerdictName(rule.eval(ctx, tc.input))
			rule.emptyFields(ctx)
			// t.Logf("config: %v", tc.config)
			// t.Logf("input: %v", tc.input)
			tests.EvalObjects(t, "match result", tc.want, got)
		})
	}
}
