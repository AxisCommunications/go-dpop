package dpop_test

import (
	"crypto"
	"testing"

	"github.com/AxisCommunications/go-dpop"
)


const (
	// Arrange
	inString = "testString"
	encryptedString = "Kojtpb4GFK8jVm9Ypu74Ybg0QUbPmZRpNziC88RslUY"
)


func TestHashEq_CustomCryptoArg(t *testing.T) {
	// Arrange
	outString := `fvH592-VGGsVowC30cXqp7JYgkuxlPteYVbMtmbJPx6TPnhMJnpxed8oO4glEyY0`
	
	// Act
	got, _ := dpop.HashEquals(inString, outString, crypto.SHA384)

	// Assert
	if got != true {
		t.Errorf("wanted %t, got %t", true, got)
	}
}

func TestHashEq_IncorrectEncryptedString(t *testing.T) {
	// Arrange
	outString := "this is definitely wrong : )"

	// Act
	got, _ := dpop.HashEquals(inString, outString)

	// Assert
	if got != false {
		t.Errorf("wanted %t, got %t", false, got)
	}
}


func TestValidateHashFunction_TooManyArgs(t *testing.T) {
	// Arrange
	want := dpop.ErrTooManyArgs
	
	// Act
	_, err := dpop.ValidateHashFunction(crypto.SHA256, crypto.SHA384)

	if err != want {
		t.Errorf("wanted %e, got %e", want, err)
	}
}

func TestValidateHashFunction_NoArgs(t *testing.T) {
	// Arrange
	want := new(crypto.Hash)
	*want = crypto.SHA256

	// Act
	got, _ := dpop.ValidateHashFunction()

	// Assert
	if *got != *want {
		t.Errorf("wanted %+v, got %+v", *want, *got)
	}
}

func TestValidateHashFunction_OneArgs(t *testing.T) {

	// Arrange
	want := new(crypto.Hash)
	*want = crypto.SHA384

	// Act
	got, _ := dpop.ValidateHashFunction(crypto.SHA384)

	// Assert
	if *got != *want {
		t.Errorf("wanted %+v, got %+v", *want, *got)
	}

}