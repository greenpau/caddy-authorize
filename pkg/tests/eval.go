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

package tests

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"testing"
)

// EvalErr evaluates whether there is an error. If there is, was it the
// expected error.
func EvalErr(t *testing.T, err error, data interface{}, shouldErr bool, expErr error) bool {
	if !shouldErr {
		if err == nil {
			return false
		}
		t.Fatalf("expected success, but got error: %s", err)
	}
	if err == nil {
		t.Fatalf("expected error, but got success: %v", data)
	}
	if expErr == nil {
		expErr = fmt.Errorf("")
	}
	if diff := cmp.Diff(expErr.Error(), err.Error()); diff != "" {
		t.Fatalf("unexpected error (-want +got):\n%s", diff)
	}
	// t.Logf("received expected error: %v", err)
	return true
}

func writeLog(t *testing.T, msgs []string) {
	if len(msgs) == 0 {
		return
	}
	for _, msg := range msgs {
		t.Logf("%s", msg)
	}
}

// EvalErrWithLog evaluates the error.
func EvalErrWithLog(t *testing.T, err error, data interface{}, shouldErr bool, expErr error, msgs []string) bool {
	if !shouldErr {
		if err == nil {
			return false
		}
		writeLog(t, msgs)
		t.Fatalf("expected success, but got error: %s", err)
	}
	if err == nil {
		writeLog(t, msgs)
		t.Fatalf("expected error, but got success: %v", data)
	}
	if expErr == nil {
		expErr = fmt.Errorf("")
	}
	if diff := cmp.Diff(expErr.Error(), err.Error()); diff != "" {
		writeLog(t, msgs)
		t.Fatalf("unexpected error (-want +got):\n%s", diff)
	}
	// t.Logf("received expected error: %v", err)
	return true
}

// EvalObjects compares two objects.
func EvalObjects(t *testing.T, name string, want, got interface{}) {
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("%s mismatch (-want +got):\n%s", name, diff)
	}
}

// EvalObjectsWithLog compares two objects and logs extra output when
// detects an error
func EvalObjectsWithLog(t *testing.T, name string, want, got interface{}, msgs []string) {
	if diff := cmp.Diff(want, got); diff != "" {
		writeLog(t, msgs)
		t.Fatalf("%s mismatch (-want +got):\n%s", name, diff)
	}
}
