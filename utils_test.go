package dpop_test

import (
	"crypto"
	"net/url"
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
	
	// Act
	got, _ := dpop.HashEquals(inString, outString, crypto.SHA384)

	// Assert
	if got != true {
		t.Errorf("wanted %t, got %t", true, got)
	}
}

func TestHashEquals_IncorrectEncryptedString(t *testing.T) {
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

	// Assert
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

func TestHashUtil_BadInputString(t *testing.T) {
	// Arrange
	malformedString := ``
	want := dpop.ErrInputMalformed

	// Act
	_, err := dpop.HashUtil(malformedString)

	// Assert
	if want != err {
		t.Errorf("wanted %e, got %e", want, err)
	}
}

func TestHashUtil_CorrectOutput(t *testing.T) {
	// Arrange
	want := "Kojtpb4GFK8jVm9Ypu74Ybg0QUbPmZRpNziC88RslUY"
	
	// Act
	got, _ := dpop.HashUtil(inString)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}

func TestStripQueryAndFragments_NoQuery(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host: "server.com",
		Path: "/path",
		Fragment: "#fragment",
	}
	want := "https://server.com/path"

	// Act
	got := dpop.StripQueryAndFragments(&httpUrl)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}

func TestStripQueryAndFragments_NoFragments(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host: "server.com",
		Path: "/path",
		RawQuery: "foo=bar",
	}
	want := "https://server.com/path"

	// Act
	got := dpop.StripQueryAndFragments(&httpUrl)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}
}

func TestStripQueryAndFragments_QueryAndFragments(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host: "server.com",
		Path: "/path",
		RawQuery: "foo=bar",
		Fragment: "#fragment",
	}
	want := "https://server.com/path"

	// Act
	got := dpop.StripQueryAndFragments(&httpUrl)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}	
}

func TestStripQueryAndFragments_BaseURL(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host: "server.com",
		Path: "/path",
	}
	want := "https://server.com/path"

	// Act
	got := dpop.StripQueryAndFragments(&httpUrl)

	if got != want {
		t.Errorf("wanted %s, got %s", want, got)
	}		
}