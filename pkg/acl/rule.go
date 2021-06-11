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
	"github.com/greenpau/caddy-auth-jwt/pkg/utils/cfgutils"
	"go.uber.org/zap"
	"strings"
	"sync/atomic"
)

type ruleVerdict int
type ruleAction int
type ruleMatchStrategy int

const (
	ruleVerdictUnknown   ruleVerdict = 0
	ruleVerdictReserved  ruleVerdict = 1
	ruleVerdictDeny      ruleVerdict = 2
	ruleVerdictDenyStop  ruleVerdict = 3
	ruleVerdictContinue  ruleVerdict = 4
	ruleVerdictAllow     ruleVerdict = 5
	ruleVerdictAllowStop ruleVerdict = 6

	ruleActionUnknown  ruleAction = 0
	ruleActionReserved ruleAction = 1
	ruleActionDeny     ruleAction = 2
	ruleActionAllow    ruleAction = 3
)

type ruleConfig struct {
	ruleType       string
	comment        string
	fields         []string
	index          map[string]int
	conditions     []*config
	action         ruleAction
	logEnabled     bool
	tag            string
	logLevel       string
	counterEnabled bool
	matchAll       bool
}

// RuleConfiguration consists of a list of conditions and and actions
type RuleConfiguration struct {
	Comment    string   `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Conditions []string `json:"conditions,omitempty" xml:"conditions,omitempty" yaml:"conditions,omitempty"`
	Action     string   `json:"action,omitempty" xml:"action,omitempty" yaml:"action,omitempty"`
}

type aclRule interface {
	eval(context.Context, map[string]interface{}) ruleVerdict
	getConfig(context.Context) *ruleConfig
	emptyFields(context.Context)
}

type aclRuleAllowMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleAllowMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleAllowStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
}

type aclRuleAllowMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleAllowMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleAllow struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
}

type aclRuleAllowWithDebugLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithInfoLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithWarnLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithErrorLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithDebugLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithInfoLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithWarnLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithErrorLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithDebugLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithInfoLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithWarnLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithErrorLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithDebugLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithInfoLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithWarnLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithErrorLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithDebugLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithInfoLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithWarnLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithErrorLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleAllowWithDebugLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithInfoLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithWarnLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithErrorLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleAllowWithCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithDebugLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithInfoLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithWarnLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithErrorLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithDebugLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithInfoLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithWarnLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithErrorLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithDebugLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithInfoLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithWarnLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithErrorLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithDebugLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithInfoLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithWarnLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithErrorLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithDebugLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithInfoLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithWarnLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithErrorLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithDebugLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithInfoLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithWarnLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleAllowWithErrorLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleDenyMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleDenyStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
}

type aclRuleDenyMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleDenyMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
}

type aclRuleDeny struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
}

type aclRuleDenyWithDebugLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithInfoLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithWarnLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithErrorLoggerMatchAnyStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithDebugLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithInfoLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithWarnLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithErrorLoggerMatchAllStop struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithDebugLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithInfoLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithWarnLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithErrorLoggerStop struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithDebugLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithInfoLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithWarnLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithErrorLoggerMatchAny struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithDebugLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithInfoLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithWarnLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithErrorLoggerMatchAll struct {
	config     *ruleConfig
	conditions []aclRuleCondition
	fields     []string
	logger     *zap.Logger
	tag        string
}

type aclRuleDenyWithDebugLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithInfoLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithWarnLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithErrorLogger struct {
	config    *ruleConfig
	condition aclRuleCondition
	field     string
	logger    *zap.Logger
	tag       string
}

type aclRuleDenyWithCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithDebugLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithInfoLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithWarnLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithErrorLoggerCounterMatchAnyStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithDebugLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithInfoLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithWarnLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithErrorLoggerCounterMatchAllStop struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithDebugLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithInfoLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithWarnLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithErrorLoggerCounterStop struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithDebugLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithInfoLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithWarnLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithErrorLoggerCounterMatchAny struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithDebugLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithInfoLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithWarnLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithErrorLoggerCounterMatchAll struct {
	config       *ruleConfig
	conditions   []aclRuleCondition
	fields       []string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithDebugLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithInfoLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithWarnLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

type aclRuleDenyWithErrorLoggerCounter struct {
	config       *ruleConfig
	condition    aclRuleCondition
	field        string
	logger       *zap.Logger
	tag          string
	counterMiss  uint64
	counterMatch uint64
}

func (rule *aclRuleAllowMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllow) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithDebugLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithInfoLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithWarnLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowWithErrorLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDeny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLogger) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAnyStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAllStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerCounterStop) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAny) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAll) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithDebugLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithInfoLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithWarnLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleDenyWithErrorLoggerCounter) getConfig(ctx context.Context) *ruleConfig {
	return rule.config
}

func (rule *aclRuleAllowMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllow) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithDebugLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithInfoLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithWarnLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithErrorLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithDebugLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithInfoLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithWarnLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithErrorLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithInfoLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithWarnLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithErrorLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleAllowWithDebugLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithInfoLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithWarnLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleAllowWithErrorLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDeny) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithDebugLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithInfoLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithWarnLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithErrorLoggerStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithDebugLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithInfoLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithWarnLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithErrorLogger) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAnyStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAllStop) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithInfoLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithWarnLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithErrorLoggerCounterStop) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAny) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAll) emptyFields(ctx context.Context) {
	rule.fields = make([]string, 0)
}

func (rule *aclRuleDenyWithDebugLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithInfoLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithWarnLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func (rule *aclRuleDenyWithErrorLoggerCounter) emptyFields(ctx context.Context) {
	rule.field = ""
}

func newACLRule(ctx context.Context, ruleID int, cfg *RuleConfiguration, logger *zap.Logger) (aclRule, error) {
	var action, logLevel, tag string
	var stopEnabled, logEnabled, counterEnabled, matchAny bool
	var skipNext, lastToken bool
	var conditions []aclRuleCondition
	var condConfigs []*config
	var fields []string
	fieldIndex := make(map[string]int)

	for i, c := range cfg.Conditions {
		tokens, err := cfgutils.DecodeArgs(c)
		if err != nil {
			return nil, fmt.Errorf("invalid rule syntax, failed to extract condition tokens: %s", err)
		}
		parsedACLRuleCondition, err := newACLRuleCondition(ctx, tokens)
		if err != nil {
			return nil, fmt.Errorf("invalid rule syntax, %v", err)
		}
		conditions = append(conditions, parsedACLRuleCondition)
		condConfig := parsedACLRuleCondition.getConfig(ctx)
		condConfigs = append(condConfigs, condConfig)
		if _, exists := fieldIndex[condConfig.field]; exists {
			return nil, fmt.Errorf("invalid rule syntax, duplicate field: %s", condConfig.field)
		}
		fieldIndex[condConfig.field] = i
		fields = append(fields, condConfig.field)
	}

	tokens, err := cfgutils.DecodeArgs(cfg.Action)
	if err != nil {
		return nil, fmt.Errorf("invalid rule syntax, failed to extract action tokens: %s", err)
	}
	for i, token := range tokens {
		if len(tokens) == (i + 1) {
			lastToken = true
		}
		if skipNext {
			skipNext = false
			continue
		}
		switch token {
		case "allow", "deny", "reserved":
			if i != 0 {
				return nil, fmt.Errorf("invalid rule syntax, %s must preceed stop/counter/log directives", token)
			}
			action = token
			if !lastToken {
				if tokens[i+1] == "any" {
					matchAny = true
					skipNext = true
				}
			}
		case "stop":
			stopEnabled = true
		case "counter":
			counterEnabled = true
		case "log":
			logEnabled = true
			if lastToken {
				logLevel = "info"
			} else {
				switch tokens[i+1] {
				case "debug", "info", "warn", "error":
					logLevel = tokens[i+1]
					skipNext = true
				default:
					logLevel = "info"
				}
			}
		case "tag":
			if lastToken {
				return nil, fmt.Errorf("invalid rule syntax, %s must be followed by value", token)
			}
			tag = tokens[i+1]
			skipNext = true
		case "and", "with":
		default:
			return nil, fmt.Errorf("invalid rule syntax, invalid %q token", token)
		}
	}

	// Action directives.
	ruleTypeName := "aclRule"
	switch action {
	case "allow":
		ruleTypeName += "Allow"
	case "deny":
		ruleTypeName += "Deny"
	case "reserved":
		ruleTypeName += "Reserved"
	}

	// Log and counter directives.
	if logEnabled || counterEnabled {
		ruleTypeName += "With"
	}
	if logEnabled {
		ruleTypeName += strings.Title(logLevel) + "Logger"
		if logger == nil {
			return nil, fmt.Errorf("invalid rule syntax, no logger found for log enabled rule: %s", ruleTypeName)
		}
	}
	if counterEnabled {
		ruleTypeName += "Counter"
	}

	switch len(conditions) {
	case 0:
		return nil, fmt.Errorf("invalid rule syntax, no match conditions found")
	case 1:
	default:
		// Matching all or any conditions.
		if matchAny {
			ruleTypeName += "MatchAny"
		} else {
			ruleTypeName += "MatchAll"
		}
	}

	// Stop on match.
	if stopEnabled {
		ruleTypeName += "Stop"
	}

	// Tagging.
	if tag == "" {
		tag = fmt.Sprintf("rule%d", ruleID)
	}

	// Build rules.
	var r aclRule
	switch ruleTypeName {
	case "aclRuleAllowMatchAnyStop":
		rule := &aclRuleAllowMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowMatchAllStop":
		rule := &aclRuleAllowMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowStop":
		rule := &aclRuleAllowStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleAllowMatchAny":
		rule := &aclRuleAllowMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowMatchAll":
		rule := &aclRuleAllowMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllow":
		rule := &aclRuleAllow{
			config: &ruleConfig{
				ruleType:       "aclRuleAllow",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerMatchAnyStop":
		rule := &aclRuleAllowWithDebugLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerMatchAnyStop":
		rule := &aclRuleAllowWithInfoLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerMatchAnyStop":
		rule := &aclRuleAllowWithWarnLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerMatchAnyStop":
		rule := &aclRuleAllowWithErrorLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerMatchAllStop":
		rule := &aclRuleAllowWithDebugLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerMatchAllStop":
		rule := &aclRuleAllowWithInfoLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerMatchAllStop":
		rule := &aclRuleAllowWithWarnLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerMatchAllStop":
		rule := &aclRuleAllowWithErrorLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerStop":
		rule := &aclRuleAllowWithDebugLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerStop":
		rule := &aclRuleAllowWithInfoLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerStop":
		rule := &aclRuleAllowWithWarnLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerStop":
		rule := &aclRuleAllowWithErrorLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerMatchAny":
		rule := &aclRuleAllowWithDebugLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerMatchAny":
		rule := &aclRuleAllowWithInfoLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerMatchAny":
		rule := &aclRuleAllowWithWarnLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerMatchAny":
		rule := &aclRuleAllowWithErrorLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerMatchAll":
		rule := &aclRuleAllowWithDebugLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerMatchAll":
		rule := &aclRuleAllowWithInfoLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerMatchAll":
		rule := &aclRuleAllowWithWarnLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerMatchAll":
		rule := &aclRuleAllowWithErrorLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLogger":
		rule := &aclRuleAllowWithDebugLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLogger":
		rule := &aclRuleAllowWithInfoLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLogger":
		rule := &aclRuleAllowWithWarnLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLogger":
		rule := &aclRuleAllowWithErrorLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithCounterMatchAnyStop":
		rule := &aclRuleAllowWithCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowWithCounterMatchAllStop":
		rule := &aclRuleAllowWithCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowWithCounterStop":
		rule := &aclRuleAllowWithCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleAllowWithCounterMatchAny":
		rule := &aclRuleAllowWithCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowWithCounterMatchAll":
		rule := &aclRuleAllowWithCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleAllowWithCounter":
		rule := &aclRuleAllowWithCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerCounterMatchAnyStop":
		rule := &aclRuleAllowWithDebugLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerCounterMatchAnyStop":
		rule := &aclRuleAllowWithInfoLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerCounterMatchAnyStop":
		rule := &aclRuleAllowWithWarnLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerCounterMatchAnyStop":
		rule := &aclRuleAllowWithErrorLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerCounterMatchAllStop":
		rule := &aclRuleAllowWithDebugLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerCounterMatchAllStop":
		rule := &aclRuleAllowWithInfoLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerCounterMatchAllStop":
		rule := &aclRuleAllowWithWarnLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerCounterMatchAllStop":
		rule := &aclRuleAllowWithErrorLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerCounterStop":
		rule := &aclRuleAllowWithDebugLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerCounterStop":
		rule := &aclRuleAllowWithInfoLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerCounterStop":
		rule := &aclRuleAllowWithWarnLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerCounterStop":
		rule := &aclRuleAllowWithErrorLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerCounterMatchAny":
		rule := &aclRuleAllowWithDebugLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerCounterMatchAny":
		rule := &aclRuleAllowWithInfoLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerCounterMatchAny":
		rule := &aclRuleAllowWithWarnLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerCounterMatchAny":
		rule := &aclRuleAllowWithErrorLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerCounterMatchAll":
		rule := &aclRuleAllowWithDebugLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerCounterMatchAll":
		rule := &aclRuleAllowWithInfoLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerCounterMatchAll":
		rule := &aclRuleAllowWithWarnLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerCounterMatchAll":
		rule := &aclRuleAllowWithErrorLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleAllowWithDebugLoggerCounter":
		rule := &aclRuleAllowWithDebugLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithDebugLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithInfoLoggerCounter":
		rule := &aclRuleAllowWithInfoLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithInfoLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithWarnLoggerCounter":
		rule := &aclRuleAllowWithWarnLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithWarnLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleAllowWithErrorLoggerCounter":
		rule := &aclRuleAllowWithErrorLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleAllowWithErrorLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionAllow,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyMatchAnyStop":
		rule := &aclRuleDenyMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyMatchAllStop":
		rule := &aclRuleDenyMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyStop":
		rule := &aclRuleDenyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleDenyMatchAny":
		rule := &aclRuleDenyMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyMatchAll":
		rule := &aclRuleDenyMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDeny":
		rule := &aclRuleDeny{
			config: &ruleConfig{
				ruleType:       "aclRuleDeny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerMatchAnyStop":
		rule := &aclRuleDenyWithDebugLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerMatchAnyStop":
		rule := &aclRuleDenyWithInfoLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerMatchAnyStop":
		rule := &aclRuleDenyWithWarnLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerMatchAnyStop":
		rule := &aclRuleDenyWithErrorLoggerMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerMatchAllStop":
		rule := &aclRuleDenyWithDebugLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerMatchAllStop":
		rule := &aclRuleDenyWithInfoLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerMatchAllStop":
		rule := &aclRuleDenyWithWarnLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerMatchAllStop":
		rule := &aclRuleDenyWithErrorLoggerMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerStop":
		rule := &aclRuleDenyWithDebugLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerStop":
		rule := &aclRuleDenyWithInfoLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerStop":
		rule := &aclRuleDenyWithWarnLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerStop":
		rule := &aclRuleDenyWithErrorLoggerStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerMatchAny":
		rule := &aclRuleDenyWithDebugLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerMatchAny":
		rule := &aclRuleDenyWithInfoLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerMatchAny":
		rule := &aclRuleDenyWithWarnLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerMatchAny":
		rule := &aclRuleDenyWithErrorLoggerMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerMatchAll":
		rule := &aclRuleDenyWithDebugLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerMatchAll":
		rule := &aclRuleDenyWithInfoLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerMatchAll":
		rule := &aclRuleDenyWithWarnLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerMatchAll":
		rule := &aclRuleDenyWithErrorLoggerMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLogger":
		rule := &aclRuleDenyWithDebugLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLogger":
		rule := &aclRuleDenyWithInfoLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLogger":
		rule := &aclRuleDenyWithWarnLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLogger":
		rule := &aclRuleDenyWithErrorLogger{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLogger",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithCounterMatchAnyStop":
		rule := &aclRuleDenyWithCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyWithCounterMatchAllStop":
		rule := &aclRuleDenyWithCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyWithCounterStop":
		rule := &aclRuleDenyWithCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleDenyWithCounterMatchAny":
		rule := &aclRuleDenyWithCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyWithCounterMatchAll":
		rule := &aclRuleDenyWithCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
		}
		r = rule
	case "aclRuleDenyWithCounter":
		rule := &aclRuleDenyWithCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerCounterMatchAnyStop":
		rule := &aclRuleDenyWithDebugLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerCounterMatchAnyStop":
		rule := &aclRuleDenyWithInfoLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerCounterMatchAnyStop":
		rule := &aclRuleDenyWithWarnLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerCounterMatchAnyStop":
		rule := &aclRuleDenyWithErrorLoggerCounterMatchAnyStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerCounterMatchAnyStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerCounterMatchAllStop":
		rule := &aclRuleDenyWithDebugLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerCounterMatchAllStop":
		rule := &aclRuleDenyWithInfoLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerCounterMatchAllStop":
		rule := &aclRuleDenyWithWarnLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerCounterMatchAllStop":
		rule := &aclRuleDenyWithErrorLoggerCounterMatchAllStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerCounterMatchAllStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerCounterStop":
		rule := &aclRuleDenyWithDebugLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerCounterStop":
		rule := &aclRuleDenyWithInfoLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerCounterStop":
		rule := &aclRuleDenyWithWarnLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerCounterStop":
		rule := &aclRuleDenyWithErrorLoggerCounterStop{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerCounterStop",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerCounterMatchAny":
		rule := &aclRuleDenyWithDebugLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerCounterMatchAny":
		rule := &aclRuleDenyWithInfoLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerCounterMatchAny":
		rule := &aclRuleDenyWithWarnLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerCounterMatchAny":
		rule := &aclRuleDenyWithErrorLoggerCounterMatchAny{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerCounterMatchAny",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerCounterMatchAll":
		rule := &aclRuleDenyWithDebugLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerCounterMatchAll":
		rule := &aclRuleDenyWithInfoLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerCounterMatchAll":
		rule := &aclRuleDenyWithWarnLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerCounterMatchAll":
		rule := &aclRuleDenyWithErrorLoggerCounterMatchAll{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerCounterMatchAll",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			conditions: conditions,
			fields:     fields,
			tag:        tag,
			logger:     logger,
		}
		r = rule
	case "aclRuleDenyWithDebugLoggerCounter":
		rule := &aclRuleDenyWithDebugLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithDebugLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithInfoLoggerCounter":
		rule := &aclRuleDenyWithInfoLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithInfoLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithWarnLoggerCounter":
		rule := &aclRuleDenyWithWarnLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithWarnLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	case "aclRuleDenyWithErrorLoggerCounter":
		rule := &aclRuleDenyWithErrorLoggerCounter{
			config: &ruleConfig{
				ruleType:       "aclRuleDenyWithErrorLoggerCounter",
				logEnabled:     logEnabled,
				counterEnabled: counterEnabled,
				comment:        cfg.Comment,
				action:         ruleActionDeny,
				tag:            tag,
				logLevel:       logLevel,
				matchAll:       true,
				conditions:     condConfigs,
				fields:         fields,
			},
			condition: conditions[0],
			field:     fields[0],
			tag:       tag,
			logger:    logger,
		}
		r = rule
	default:
		return nil, fmt.Errorf("invalid rule syntax, type %q is unsupported", ruleTypeName)
	}
	return r, nil
}

func (rule *aclRuleAllowMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		return ruleVerdictAllowStop
	}
	return ruleVerdictContinue
}

func (rule *aclRuleAllowMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		return ruleVerdictAllowStop
	}
	return ruleVerdictContinue
}

func (rule *aclRuleAllowStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		return ruleVerdictAllow
	}
	return ruleVerdictContinue
}

func (rule *aclRuleAllowMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		return ruleVerdictAllow
	}
	return ruleVerdictContinue
}

func (rule *aclRuleAllow) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithDebugLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithInfoLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithWarnLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithErrorLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithDebugLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithInfoLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithWarnLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithErrorLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllowStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithInfoLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithWarnLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithErrorLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllowStop
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithInfoLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithWarnLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithErrorLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictAllow
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleAllowWithDebugLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithInfoLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithWarnLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleAllowWithErrorLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "allow"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictAllow
}

func (rule *aclRuleDenyMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		return ruleVerdictDenyStop
	}
	return ruleVerdictContinue
}

func (rule *aclRuleDenyMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		return ruleVerdictDenyStop
	}
	return ruleVerdictContinue
}

func (rule *aclRuleDenyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		return ruleVerdictDeny
	}
	return ruleVerdictContinue
}

func (rule *aclRuleDenyMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		return ruleVerdictDeny
	}
	return ruleVerdictContinue
}

func (rule *aclRuleDeny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithDebugLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithInfoLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithWarnLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithErrorLoggerStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithDebugLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithInfoLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithWarnLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithErrorLogger) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		return ruleVerdictContinue
	}
	rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAnyStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAllStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDenyStop
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithInfoLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithWarnLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithErrorLoggerCounterStop) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDenyStop
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAny) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			continue
		}
		if !rule.conditions[i].match(ctx, v) {
			continue
		}
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithInfoLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithWarnLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithErrorLoggerCounterMatchAll) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	var matched bool
	for i, field := range rule.fields {
		v, found := data[field]
		if !found {
			return ruleVerdictContinue
		}
		if !rule.conditions[i].match(ctx, v) {
			atomic.AddUint64(&rule.counterMiss, 1)
			rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
			return ruleVerdictContinue
		}
		matched = true
	}
	if matched {
		atomic.AddUint64(&rule.counterMatch, 1)
		rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
		return ruleVerdictDeny
	}
	atomic.AddUint64(&rule.counterMiss, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "continue"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictContinue
}

func (rule *aclRuleDenyWithDebugLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Debug("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithInfoLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Info("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithWarnLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Warn("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func (rule *aclRuleDenyWithErrorLoggerCounter) eval(ctx context.Context, data map[string]interface{}) ruleVerdict {
	v, found := data[rule.field]
	if !found {
		return ruleVerdictContinue
	}
	if !rule.condition.match(ctx, v) {
		atomic.AddUint64(&rule.counterMiss, 1)
		return ruleVerdictContinue
	}
	atomic.AddUint64(&rule.counterMatch, 1)
	rule.logger.Error("acl rule hit", zap.String("action", "deny"), zap.String("tag", rule.tag), zap.Any("user", data))
	return ruleVerdictDeny
}

func getRuleVerdictName(s ruleVerdict) string {
	switch s {
	case ruleVerdictDeny:
		return "ruleVerdictDeny"
	case ruleVerdictDenyStop:
		return "ruleVerdictDenyStop"
	case ruleVerdictContinue:
		return "ruleVerdictContinue"
	case ruleVerdictAllow:
		return "ruleVerdictAllow"
	case ruleVerdictAllowStop:
		return "ruleVerdictAllowStop"
	case ruleVerdictReserved:
		return "ruleVerdictReserved"
	}
	return "ruleVerdictUnknown"
}

func getRuleActionName(s ruleAction) string {
	switch s {
	case ruleActionDeny:
		return "ruleActionDeny"
	case ruleActionAllow:
		return "ruleActionAllow"
	case ruleActionReserved:
		return "ruleActionReserved"
	}
	return "ruleActionUnknown"
}
