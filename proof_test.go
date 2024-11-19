package dpop_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/AxisCommunications/go-dpop"
	"github.com/golang-jwt/jwt/v5"
)

const (
	validProof = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaV9CYWFEY2ZlQk9LTVBmRDR5bHZsVTNLTFdPWVFORWV4OTdTMFpaMUtQZyIsInkiOiIxLTZja2pxSjRTNkdmdmRUT201ZzMzM3AtczJnVXlnLURYWm9tclhfLUFFIn19.eyJpYXQiOjE2ODc0MTI3NzQsImp0aSI6IjNLS0NHWVJYYzJZMUVjVGwxNFFPazhJNmJpWEVTXzVXcEhnMkJlR2V3WG8iLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4iLCJhdGgiOiJuNGJRZ1loTWZXV2FMLXFneFZyUUZhT19UeHNyQzRJczBWMXNGYkR3Q2dnIn0.euucMkv7XblhIJ2RFAT_kb1judzkw7nQL6vghiUZz9a9frCRYD1Ei2SCLd-Hta2Vm10fsXAFPn5oVJH4ELtTAA"
)

// Test that a valid proof and valid bound token are accepted without error
func TestValidate_WithValidProofAndBoundAccessToken(t *testing.T) {
	// Arrange
	// Create an access token hash
	accessToken := "someToken"
	h := sha256.New()
	_, err := h.Write([]byte(accessToken))
	if err != nil {
		t.Errorf("access token hashing returned error: %v", err)
	}
	ath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	h.Reset()

	// Create a jwk hash
	_, err = h.Write([]byte("\"test\""))
	if err != nil {
		t.Errorf("jwk hashing returned error: %v", err)
	}
	jwkHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Create an introspected access token
	introspectedAccessToken := &jwt.Token{
		Claims: &dpop.BoundAccessTokenClaims{
			Confirmation: dpop.Confirmation{
				JWKThumbprint: jwkHash,
			},
		},
	}

	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: &dpop.ProofTokenClaims{
				AccessTokenHash: string(ath),
			},
		},
		HashedPublicKey: jwkHash,
	}

	// Act
	err = underTest.Validate([]byte(ath), introspectedAccessToken)

	// Assert
	if err != nil {
		t.Errorf("Validate returned error: %v", err)
	}
}

// Test that parsed proof can validate as well
func TestValidate_WithParsedProof(t *testing.T) {
	// Arrange
	// Create a access token hash
	accessToken := "test"
	h := sha256.New()
	_, err := h.Write([]byte(accessToken))
	if err != nil {
		t.Errorf("access token hashing returned error: %v", err)
	}
	ath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	h.Reset()

	// Add the jwk hash of the pre-generated proof
	jwkHash := "o_6H9B3vEMm_F_zbgASaC7X14fZC4XdiM5IyNJhbhHw"

	// Create an introspected access token
	introspectedAccessToken := &jwt.Token{
		Claims: &dpop.BoundAccessTokenClaims{
			Confirmation: dpop.Confirmation{
				JWKThumbprint: jwkHash,
			},
		},
	}

	// Parse a DPoP proof to test on
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:           "",
		AllowedProofAge: &duration,
	}
	proof, err := dpop.Parse(validProof, dpop.POST, &httpUrl, opts)
	if err != nil {
		t.Errorf("Parse returned error: %v", err)
	}

	// Act
	err = proof.Validate([]byte(ath), introspectedAccessToken)

	// Assert
	if err != nil {
		t.Errorf("Validate returned error: %v", err)
	}
}

// Test that a proof with invalid claims are rejected
func TestValidate_WithIncorrectProofClaims(t *testing.T) {
	// Arrange
	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: jwt.RegisteredClaims{},
		},
	}

	// Act
	err := underTest.Validate([]byte(""), &jwt.Token{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	AssertJoinedError(t, err, dpop.ErrIncorrectClaimsType)
}

// Test that a proof with missing `ath` claim is rejected
func TestValidate_WithMissingAthClaim(t *testing.T) {
	// Arrange
	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: &dpop.ProofTokenClaims{
				AccessTokenHash: "",
			},
		},
	}

	// Act
	err := underTest.Validate([]byte(""), &jwt.Token{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	AssertJoinedError(t, err, dpop.ErrMissingAth)
}

// Test that a proof with incorrect `ath` claim is rejected
func TestValidate_WithIncorrectAthClaim(t *testing.T) {
	// Arrange
	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: &dpop.ProofTokenClaims{
				AccessTokenHash: "test",
			},
		},
	}

	// Act
	err := underTest.Validate([]byte("nottest"), &jwt.Token{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	AssertJoinedError(t, err, dpop.ErrAthMismatch)
}

// Test that a proof with missing `jwk` header is rejected
func TestValidate_WithMissingJwkHeader(t *testing.T) {
	// Arrange
	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{},
			Claims: &dpop.ProofTokenClaims{
				AccessTokenHash: "test",
			},
		},
	}

	// Act
	err := underTest.Validate([]byte("test"), &jwt.Token{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	AssertJoinedError(t, err, dpop.ErrMissingJWK)
}

// Test that a proof cannot be validated on a non-bound token
func TestValidate_WithNonBoundToken(t *testing.T) {
	// Arrange
	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: &dpop.ProofTokenClaims{
				AccessTokenHash: "test",
			},
		},
		HashedPublicKey: "jkt",
	}

	// Act
	err := underTest.Validate([]byte("test"), &jwt.Token{
		Claims: &jwt.RegisteredClaims{},
	})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	ok := errors.Is(err, dpop.ErrIncorrectAccessTokenClaimsType)
	if !ok {
		t.Errorf("Unexpected error type: %v", err)
	}
}

// Test that a proof cannot be validated when public key mismatches
func TestValidate_WithIncorrectAccessTokenClaims(t *testing.T) {
	// Arrange
	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: &dpop.ProofTokenClaims{
				AccessTokenHash: "test",
			},
		},
		HashedPublicKey: "jkt",
	}

	// Act
	err := underTest.Validate([]byte("test"), &jwt.Token{
		Claims: &dpop.BoundAccessTokenClaims{},
	})

	if err == nil {
		t.Errorf("Expected error")
	}
	AssertJoinedError(t, err, dpop.ErrJWKMismatch)
}

// Test that custom claims that wrap ProofTokenClaims works as intended
func TestValidate_WithCustomClaims(t *testing.T) {
	// Arrange
	type customClaims struct {
		*dpop.ProofTokenClaims
		myString string
	}

	// Create a access token hash
	accessToken := "someToken"
	h := sha256.New()
	_, err := h.Write([]byte(accessToken))
	if err != nil {
		t.Errorf("access token hashing returned error: %v", err)
	}
	ath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	h.Reset()

	// Create a jwk hash
	_, err = h.Write([]byte("\"test\""))
	if err != nil {
		t.Errorf("jwk hashing returned error: %v", err)
	}
	jwkHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Create an introspected access token
	introspectedAccessToken := &jwt.Token{
		Claims: &dpop.BoundAccessTokenClaims{
			Confirmation: dpop.Confirmation{
				JWKThumbprint: jwkHash,
			},
		},
	}

	// Create a DPoP proof to be tested
	underTest := dpop.Proof{
		Token: &jwt.Token{
			Header: map[string]interface{}{
				"jwk": "test",
			},
			Claims: customClaims{
				ProofTokenClaims: &dpop.ProofTokenClaims{
					AccessTokenHash: string(ath),
				},
				myString: "test",
			},
		},
		HashedPublicKey: jwkHash,
	}

	// Act
	err = underTest.Validate([]byte(ath), introspectedAccessToken)

	// Assert
	if err != nil {
		t.Errorf("Validate returned error: %v", err)
	}
}
