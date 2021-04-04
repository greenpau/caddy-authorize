package tests

import (
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
	if err.Error() != expErr.Error() {
		t.Fatalf("unexpected error\ngot:  %v\nwant: %v", err, expErr)
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
