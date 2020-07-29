package jwt

import (
	"fmt"
	"testing"
)

type AccessListTestInput struct {
	name       string
	action     string
	claim      string
	values     []string
	shouldFail bool // Whether test should result in a failure
	shouldErr  bool // Whether parsing of a response should result in error
	err        error
}

func evalAccessListTestResults(t *testing.T, i int, test AccessListTestInput, err error) (bool, error) {
	if !test.shouldErr && err != nil {
		return true, fmt.Errorf(
			"FAIL: Test %d, input (%v): expected success, received error: %v",
			i, test, err,
		)
	}
	if test.shouldFail && err == nil {
		return true, fmt.Errorf("FAIL: Test %d: input (%v):, expected failure but passed", i, test)
	}

	if err != nil {
		if test.err == nil {
			return true, fmt.Errorf(
				"FAIL: Test %d, input (%v): test missing error definition: %v",
				i, test, err,
			)
		}
		if test.err.Error() != err.Error() {
			return true, fmt.Errorf(
				"FAIL: Test %d, input (%v): expected different error: %s (expected) vs. %s (received)",
				i, test, test.err, err,
			)
		}
	}

	t.Logf("PASS: Test %d, input: %v", i, test)
	return false, nil
}

func TestAccessListEntry(t *testing.T) {
	testFailed := 0
	for i, test := range []AccessListTestInput{
		{
			name:       "allow anonymous role",
			action:     "allow",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  false,
			err:        nil,
		},
		{
			name:       "empty claim",
			action:     "allow",
			claim:      "",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrEmptyClaim,
		},
		{
			name:       "unsupported org claim",
			action:     "allow",
			claim:      "org",
			values:     []string{"contoso"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrUnsupportedClaim.WithArgs("org"),
		},
		{
			name:       "invalid action",
			action:     "foo",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrUnsupportedACLAction.WithArgs("foo"),
		},
		{
			name:       "empty action",
			action:     "",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrEmptyACLAction,
		},
		{
			name:       "empty claim value",
			action:     "allow",
			claim:      "roles",
			values:     []string{},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrEmptyValue,
		},
	} {
		t.Logf("test: %d, %s", i, test.name)
		entry := NewAccessListEntry()

		abort, err := evalAccessListTestResults(t, i, test, entry.SetClaim(test.claim))
		if err != nil {
			t.Logf("%s", err)
			testFailed++
		}
		if abort {
			continue
		}

		abort, err = evalAccessListTestResults(t, i, test, entry.SetAction(test.action))
		if err != nil {
			t.Logf("%s", err)
			testFailed++
		}
		if abort {
			continue
		}

		abort, err = evalAccessListTestResults(t, i, test, entry.SetValue(test.values))
		if err != nil {
			t.Logf("%s", err)
			testFailed++
		}
		if abort {
			continue
		}

		if !test.shouldFail && !test.shouldErr {
			if err := entry.Validate(); err != nil {
				t.Logf("FAIL: Test %d, input (%v): %v", i, test, err)
				testFailed++
				continue
			}
		}

	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}

func TestAccessList(t *testing.T) {
	entry1 := NewAccessListEntry()
	if err := entry1.Validate(); err != nil {
		if err != ErrEmptyACLAction {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrEmptyACLAction)
		}
	} else {
		t.Fatalf("expected error validating empty action")
	}
	entry1.Action = "foo bar"
	if err := entry1.Validate(); err != nil {
		if err.Error() != ErrUnsupportedACLAction.WithArgs("foo bar").Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrUnsupportedACLAction.WithArgs("foo bar"))
		}
	} else {
		t.Fatalf("expected error validating invalid action")
	}
	entry1.Allow()

	if err := entry1.Validate(); err != nil {
		if err.Error() != ErrEmptyACLClaim.Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrEmptyACLClaim)
		}
	} else {
		t.Fatalf("expected error validating invalid claim")
	}

	if err := entry1.SetClaim("roles"); err != nil {
		t.Fatalf("failed to set claim roles: %s", err)
	}

	if err := entry1.Validate(); err != nil {
		if err.Error() != ErrNoValues.Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrNoValues)
		}
	} else {
		t.Fatalf("expected error validating empty claim value")
	}

	if err := entry1.AddValue("guest"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}
	if err := entry1.AddValue("admin"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}

	t.Logf("Entry 1: %v", entry1)

	entry2 := NewAccessListEntry()
	entry2.Deny()
	if err := entry2.SetClaim("roles"); err != nil {
		t.Fatalf("failed to set claim roles: %s", err)
	}
	if err := entry2.AddValue(""); err == nil {
		t.Fatalf("expected error adding empty value")
	}
	if err := entry2.AddValue("guest"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}

	t.Logf("Entry 2: %v", entry2)

}
