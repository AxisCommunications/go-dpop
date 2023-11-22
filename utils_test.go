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


func TestHashEquals_CustomCryptoArg(t *testing.T) {
	// Arrange
	outString := `fvH592-VGGsVowC30cXqp7JYgkuxlPteYVbMtmbJPx6TPnhMJnpxed8oO4glEyY0`
	input := &dpop.HashInput{}
	input.HashFn = crypto.SHA384
	input.InString = inString
	// Act
	got, _ := dpop.HashEquals(*input, outString)

	// Assert
	if got != true {
		t.Errorf("wanted %t, got %t", true, got)
	}
}

func TestHashEquals_IncorrectEncryptedString(t *testing.T) {
	// Arrange
	outString := "this is definitely wrong : )"
	input := &dpop.HashInput{}
	input.HashFn = crypto.SHA256
	input.InString = inString
	
	// Act
	got, _ := dpop.HashEquals(*input, outString)

	// Assert
	if got != false {
		t.Errorf("wanted %t, got %t", false, got)
	}
}

func TestValidateHashFunction_NoArgs(t *testing.T) {
	// Arrange
	want := crypto.SHA256
	input := &dpop.HashInput{}
	input.InString = inString
	
	// Act
	got := dpop.ValidateHashFunction(*input)

	// Assert
	if got != want {
		t.Errorf("wanted %+v, got %+v", want, got)
	}
}

func TestValidateHashFunction_OneArgs(t *testing.T) {

	// Arrange
	want := crypto.SHA384
	input := &dpop.HashInput{}
	input.HashFn = crypto.SHA384
	input.InString = inString

	// Act
	got := dpop.ValidateHashFunction(*input)

	// Assert
	if got != want {
		t.Errorf("wanted %+v, got %+v", want, got)
	}

}

func TestHashUtil_BadInputString(t *testing.T) {
	// Arrange
	malformedString := ``
	want := dpop.ErrInputMalformed
	input := &dpop.HashInput{}
	input.InString = malformedString
	input.HashFn = crypto.SHA256

	// Act
	_, err := dpop.HashUtil(*input)

	// Assert
	if want != err {
		t.Errorf("wanted %e, got %e", want, err)
	}
}

func TestHashUtil_CorrectOutput(t *testing.T) {
	// Arrange
	want := "Kojtpb4GFK8jVm9Ypu74Ybg0QUbPmZRpNziC88RslUY"
	input := &dpop.HashInput{}
	input.InString = inString
	input.HashFn = crypto.SHA256
	// Act
	got, _ := dpop.HashUtil(*input)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}