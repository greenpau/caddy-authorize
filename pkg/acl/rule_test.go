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
	"reflect"
	"strings"
	"testing"
)

func TestNewAclRule(t *testing.T) {
	var testcases = []struct {
		name      string
		config    string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{name: "allow any and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow any and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow all and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowStop",
				"config_rule_type": "*acl.aclRuleAllowStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowMatchAny",
				"config_rule_type": "*acl.aclRuleAllowMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow any without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowMatchAll",
				"config_rule_type": "*acl.aclRuleAllowMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow all without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllow",
				"config_rule_type": "*acl.aclRuleAllow",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerStop",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerStop",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerStop",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerStop",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLogger",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLogger",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLogger",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLogger",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow any and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow all and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithCounterStop",
				"config_rule_type": "*acl.aclRuleAllowWithCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithCounterMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow any with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithCounterMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow all with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithCounter",
				"config_rule_type": "*acl.aclRuleAllowWithCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed allow with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow stop counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow stop counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow stop counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                allow counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                allow counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithDebugLoggerCounter",
				"config_rule_type": "*acl.aclRuleAllowWithDebugLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithInfoLoggerCounter",
				"config_rule_type": "*acl.aclRuleAllowWithInfoLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithWarnLoggerCounter",
				"config_rule_type": "*acl.aclRuleAllowWithWarnLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleAllowWithErrorLoggerCounter",
				"config_rule_type": "*acl.aclRuleAllowWithErrorLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed allow with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                allow counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny any and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny all and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyStop",
				"config_rule_type": "*acl.aclRuleDenyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny and stop processing without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyMatchAny",
				"config_rule_type": "*acl.aclRuleDenyMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny any without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyMatchAll",
				"config_rule_type": "*acl.aclRuleDenyMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny all without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDeny",
				"config_rule_type": "*acl.aclRuleDeny",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny without counter and logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny any and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny all and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerStop",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerStop",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerStop",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerStop",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny and stop processing with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny any with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny all with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLogger",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLogger",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLogger",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLogger",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLogger",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny with %s logging and without counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny any and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny all and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithCounterStop",
				"config_rule_type": "*acl.aclRuleDenyWithCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny and stop processing with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithCounterMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny any with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithCounterMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny all with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithCounter",
				"config_rule_type": "*acl.aclRuleDenyWithCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Unknown",
			},
		}, {name: "failed deny with counter and without logging",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny any and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny stop counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAllStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny all and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny stop counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerCounterStop",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterStop",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny and stop processing with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny stop counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAny",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny any with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                match_any
                deny counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerCounterMatchAll",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny all with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                exact match org nyc
                deny counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log debug
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithDebugLoggerCounter",
				"config_rule_type": "*acl.aclRuleDenyWithDebugLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Debug",
			},
		}, {name: "failed deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log debug
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log info
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithInfoLoggerCounter",
				"config_rule_type": "*acl.aclRuleDenyWithInfoLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Info",
			},
		}, {name: "failed deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log info
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log warn
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithWarnLoggerCounter",
				"config_rule_type": "*acl.aclRuleDenyWithWarnLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Warn",
			},
		}, {name: "failed deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log warn
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		}, {name: "deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log error
            `,
			want: map[string]interface{}{
				"rule_type":        "*acl.aclRuleDenyWithErrorLoggerCounter",
				"config_rule_type": "*acl.aclRuleDenyWithErrorLoggerCounter",
				"comment":          "foobar barfoo",
				"log_level":        "Error",
			},
		}, {name: "failed deny with %s logging and with counter",
			config: `
                comment foobar barfoo
                exact match roles foobar
                deny counter log error
            `,
			shouldErr: true,
			err:       fmt.Errorf("xxxx"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var rule aclRule
			ctx := context.Background()
			t.Logf(tc.name)
			t.Logf(tc.config)
			cfg := strings.TrimSpace(tc.config)
			parsedACLRule, err := newACLRule(ctx, cfg)
			if tests.EvalErr(t, err, cfg, tc.shouldErr, tc.err) {
				return
			}
			rule = parsedACLRule
			ruleConfig := rule.getConfig(ctx)
			got := make(map[string]interface{})
			got["rule_type"] = reflect.TypeOf(rule).String()
			got["config_rule_type"] = ruleConfig.ruleType
			got["comment"] = ruleConfig.comment
			tests.EvalObjects(t, "output", tc.want, got)
		})
	}
}
