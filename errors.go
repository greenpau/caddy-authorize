package jwt

import (
	"errors"
	"fmt"
)

type strError string

func (e strError) Error() string { return string(e) }

// F captures the values for an error string formatting.
func (e strError) WithArgs(v ...interface{}) error {
	var hasErr, hasNil bool
	for _, vv := range v {
		switch err := vv.(type) {
		case error:
			if err == nil {
				return nil // we pass nill errors along
			}
			hasErr = true
		case nil:
			hasNil = true
		}
	}

	if hasNil && !hasErr {
		return nil
	}

	return fmtErr{err: fmt.Errorf("%w", e), v: v}
}

// fmtErr is for errors that will be formatted. It holds
// formatting values in a slice so they can be added when the
// error is stringfied. Otherwise the underlining error without
// formatting can be matched.
type fmtErr struct {
	err error
	v   []interface{}
}

func (e fmtErr) Error() string { return fmt.Sprintf(e.err.Error(), e.v...) }

// Unwrap is a method to help unwrap errors on the base error for go1.13+
func (e fmtErr) Unwrap() error { return errors.Unwrap(e.err) }
