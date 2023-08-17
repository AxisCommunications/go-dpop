package dpop_test

import (
	"errors"
	"testing"

	"github.com/AxisCommunications/go-dpop"
)

// Test that the BoundAccessTokenClaims type is correctly implemented
func TestValidClaims(t *testing.T) {
	// Arrange
	underTest := dpop.BoundAccessTokenClaims{
		Confirmation: dpop.Confirmation{JWKThumbprint: "test"},
	}
	expectedValue := "test"

	// Act
	err := underTest.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	value, err := underTest.GetJWKThumbprint()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if value != expectedValue {
		t.Errorf("incorrect value: %s - expected '%s'", value, expectedValue)
	}
}

// Test that empty BoundAccessTokenClaims returns an error when validating
func TestEmptyClaims(t *testing.T) {
	// Arrange
	underTest := dpop.BoundAccessTokenClaims{}

	// Act
	err := underTest.Validate()
	if err == nil {
		t.Error("expected error")
	}

	if !errors.Is(err, dpop.ErrIncorrectAccessTokenClaimsType) {
		t.Errorf("incorrect error type: %v", err)
	}
}

// Test that custom claims can wrap BoundAccessTokenClaims correctly
func TestCustomClaims(t *testing.T) {
	// Arrange
	type customClaims struct {
		*dpop.BoundAccessTokenClaims
		myString string
	}

	expectedValue := "test"
	underTest := customClaims{
		BoundAccessTokenClaims: &dpop.BoundAccessTokenClaims{
			Confirmation: dpop.Confirmation{JWKThumbprint: expectedValue},
		},
		myString: "myTest",
	}

	// Act
	err := underTest.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	value, err := underTest.GetJWKThumbprint()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if value != expectedValue {
		t.Errorf("incorrect value: %s - expected '%s'", value, expectedValue)
	}

	if underTest.myString != "myTest" {
		t.Errorf("incorrect value: %s - expected 'myTest'", value)
	}
}
