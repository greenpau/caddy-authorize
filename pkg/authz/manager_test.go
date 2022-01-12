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

package authz

import (
	"context"
	"github.com/greenpau/caddy-authorize/internal/tests"
	"github.com/greenpau/caddy-authorize/pkg/acl"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"go.uber.org/zap"
	"testing"
)

func newAuthorizer(isPrimaryInstance bool, loginHintValidators []string) Authorizer {
	return Authorizer{
		Name:                "theAuthorizer",
		Context:             "default",
		PrimaryInstance:     isPrimaryInstance,
		LoginHintValidators: loginHintValidators,
		logger:              zap.L(),
		AccessListRules: []*acl.RuleConfiguration{
			{
				Conditions: []string{
					"exact match roles foobar",
				},
				Action: `allow any stop log`,
			},
		},
	}
}

func TestRegisterLoginHint(t *testing.T) {
	t.Run("Validates login hint validators", func(t *testing.T) {
		mgr := NewInstanceManager()
		ctx := context.Background()

		m := newAuthorizer(true, []string{"email", "phone", "alphanumeric"})
		err := mgr.Register(ctx, &m)

		tests.EvalErrWithLog(t, err, nil, false, nil, []string{})
		tests.EvalObjectsWithLog(t, "login validators", []string{"email", "phone", "alphanumeric"}, m.LoginHintValidators, []string{})
	})

	t.Run("Login hint validators are empty if feature was disabled", func(t *testing.T) {
		mgr := NewInstanceManager()
		ctx := context.Background()

		m := newAuthorizer(true, []string{"disabled"})
		err := mgr.Register(ctx, &m)

		tests.EvalErrWithLog(t, err, nil, false, nil, []string{})
		tests.EvalObjectsWithLog(t, "login validators", []string{}, m.LoginHintValidators, []string{})
	})

	t.Run("Throws error if login hint validator is invalid", func(t *testing.T) {
		mgr := NewInstanceManager()
		ctx := context.Background()

		m := newAuthorizer(true, []string{"invalid-validator"})
		err := mgr.Register(ctx, &m)

		tests.EvalErrWithLog(t, err, nil, true, errors.ErrInvalidConfiguration.WithArgs(m.Name, "unsupported login hint invalid-validator"), []string{})
	})

	t.Run("Inherits login hint validators from primary instance", func(t *testing.T) {
		mgr := NewInstanceManager()
		ctx := context.Background()

		primaryInstance := newAuthorizer(true, []string{"email", "phone", "alphanumeric"})
		primaryInstance.Name = "primaryInstance"
		mgr.Register(ctx, &primaryInstance)

		m := newAuthorizer(false, []string{})
		err := mgr.Register(ctx, &m)

		tests.EvalErrWithLog(t, err, nil, false, nil, []string{})
		tests.EvalObjectsWithLog(t, "login validators", m.LoginHintValidators, primaryInstance.LoginHintValidators, []string{})
	})
}
