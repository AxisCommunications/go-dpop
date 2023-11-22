package dpop_test

import (
	"crypto"
	"testing"

	"github.com/AxisCommunications/go-dpop"
)


const (
	// Arrange
	inString = "testString"
)


// Test that providing a different crypto algorithm passes
func TestHashEquals_CustomCryptoArg(t *testing.T) {
	// Arrange
	outString := `fvH592-VGGsVowC30cXqp7JYgkuxlPteYVbMtmbJPx6TPnhMJnpxed8oO4glEyY0`
	input := &dpop.HashInput{}
	input.HashFn = crypto.SHA384
	input.InString = inString
	// Act
	got, _ := dpop.HashEquals(input, outString)

	// Assert
	if got != true {
		t.Errorf("wanted %t, got %t", true, got)
	}
}

// Test an incorrect encryption string throws an error on failed match
func TestHashEquals_IncorrectEncryptedString(t *testing.T) {
	// Arrange
	outString := "this is definitely wrong : )"
	input := &dpop.HashInput{}
	input.InString = inString
	
	// Act
	got, _ := dpop.HashEquals(input, outString)

	// Assert
	if got != false {
		t.Errorf("wanted %t, got %t", false, got)
	}
}

// Test a malformed string throws an error
func TestHashUtil_BadInputString(t *testing.T) {
	// Arrange
	malformedString := ``
	want := dpop.ErrInputMalformed
	input := &dpop.HashInput{}
	input.InString = malformedString

	// Act
	_, err := dpop.HashUtil(input)

	// Assert
	if want != err {
		t.Errorf("wanted %e, got %e", want, err)
	}
}

// Test to demonstrate correct usage of  HashUtil func
func TestHashUtil_CorrectOutput(t *testing.T) {
	// Arrange
	want := "Kojtpb4GFK8jVm9Ypu74Ybg0QUbPmZRpNziC88RslUY"
	input := &dpop.HashInput{}
	input.InString = inString
	
	// Act
	got, _ := dpop.HashUtil(input)

	// Assert
	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}

// Test to determine the internal validateHashFunction sets the 
// structure's hashFn field if there is none set
func TestInternalValidate_SetsHash(t *testing.T) {
	// Arrange
	want := "Kojtpb4GFK8jVm9Ypu74Ybg0QUbPmZRpNziC88RslUY"
	input := &dpop.HashInput{}
	input.InString = inString
	
	// Act
	got, _ := dpop.HashUtil(input)

	// Assert
	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}