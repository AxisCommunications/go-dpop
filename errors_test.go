package dpop_test

import (
	"errors"
	"testing"

	dpop "github.com/AxisCommunications/go-dpop"
)

// Helper function to control types of joined errors.
func AssertJoinedError(t *testing.T, err error, expected error) {
	ok := errors.Is(err, dpop.ErrInvalidProof)
	if !ok {
		t.Errorf("Unexpected error type: %v", err)
	}
	ok = errors.Is(err, expected)
	if !ok {
		t.Errorf("Unexpected error type: %v", err)
	}
}
