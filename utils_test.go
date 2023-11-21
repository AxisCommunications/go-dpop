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
	input := new(dpop.HashInput).New(inString)
	input.SetHashFn(crypto.SHA384)

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
	input := new(dpop.HashInput).New(inString)
	
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

	// Act
	got := dpop.ValidateHashFunction(crypto.SHA256)

	// Assert
	if got != want {
		t.Errorf("wanted %+v, got %+v", want, got)
	}
}

func TestValidateHashFunction_OneArgs(t *testing.T) {

	// Arrange
	want := crypto.SHA384

	// Act
	got := dpop.ValidateHashFunction(crypto.SHA384)

	// Assert
	if got != want {
		t.Errorf("wanted %+v, got %+v", want, got)
	}

}

func TestHashUtil_BadInputString(t *testing.T) {
	// Arrange
	malformedString := ``
	want := dpop.ErrInputMalformed
	input := new(dpop.HashInput).New(malformedString)


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
	input := new(dpop.HashInput).New(inString)

	// Act
	got, _ := dpop.HashUtil(*input)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}