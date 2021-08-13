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

package cfgutils

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	// "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"testing"
)

func TestEncodeArgs(t *testing.T) {
	var testcases = []struct {
		name      string
		args      []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test encoder function",
			args: []string{
				"authp admin",
				"authp viewer",
				"authp editor",
			},
			want: map[string]interface{}{
				"args": `"authp admin" "authp viewer" "authp editor"`,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			encodedArgs := EncodeArgs(tc.args)
			got := make(map[string]interface{})
			got["args"] = encodedArgs
			tests.EvalObjectsWithLog(t, "encoder", tc.want, got, msgs)
		})
	}
}

func TestDecodeArgs(t *testing.T) {
	var testcases = []struct {
		name      string
		args      string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test decoder function",
			args: "foo,bar foo",
			want: map[string]interface{}{
				"args": []string{
					"foo,bar",
					"foo",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			decodedArgs, err := DecodeArgs(tc.args)
			if tests.EvalErrWithLog(t, err, "decoder", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["args"] = decodedArgs
			tests.EvalObjectsWithLog(t, "decoder", tc.want, got, msgs)
		})
	}
}
