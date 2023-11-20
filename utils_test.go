package dpop_test

import (
	"crypto"
	"testing"

	"github.com/AxisCommunications/go-dpop"
)


const (
	// Arrange
	inString = "testString"
	encryptedString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func TestHashEq_TooManyArgs(t *testing.T) {
	
	// Act
	_, err := dpop.HashEquals(inString, encryptedString, crypto.Hash(crypto.SHA224), crypto.Hash(crypto.SHA3_384))

	// Assert
	if err != dpop.ErrTooManyArgs {
		t.Errorf("wanted %e, got %e", dpop.ErrTooManyArgs, err)
	}
}

// func TestHashEq_NoArgs(t *testing.T) {
// 	// Act
// 	got, _ := dpop.HashEquals(inString, encryptedString)

// 	// Assert
// 	if got != true {
// 		t.Errorf("wanted %t, got %t", true, got)
// 	}
// }

func TestHashEq_CustomCryptoArg(t *testing.T) {
	// Arrange
	// outString := `38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b`
	outString := `MzhiMDYwYTc1MWFjOTYzODRjZDkzMjdlYjFiMWUzNmEyMWZkYjcxMTE0YmUwNzQzNGMwY2M3YmY2M2Y2ZTFkYTI3NGVkZWJmZTc2ZjY1ZmJkNTFhZDJmMTQ4OThiOTVi`
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
