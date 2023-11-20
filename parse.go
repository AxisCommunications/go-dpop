package dpop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// HTTPVerb is a convenience for determining the HTTP method of a request.
// This package defines the all available HTTP verbs which can be used when calling the Parse function.
type HTTPVerb string

// HTTP method supported by the package.
const (
	GET     HTTPVerb = "GET"
	POST    HTTPVerb = "POST"
	PUT     HTTPVerb = "PUT"
	DELETE  HTTPVerb = "DELETE"
	PATCH   HTTPVerb = "PATCH"
	HEAD    HTTPVerb = "HEAD"
	OPTIONS HTTPVerb = "OPTIONS"
	TRACE   HTTPVerb = "TRACE"
	CONNECT HTTPVerb = "CONNECT"
)

const DEFAULT_TIME_WINDOW = time.Second * 30

// ParseOptions and its contents are optional for the Parse function.
type ParseOptions struct {
	// The expected nonce if the authorization server has issued a nonce.
	Nonce string

	// Used to control if the `iat` field is used to control the proof age.
	// If set to true the authorization server has to validate the nonce timestamp itself.
	NonceHasTimestamp bool

	// The allowed age of the proof. Defaults to 1 minute if not specified.
	TimeWindow *time.Duration

	// dpop_jkt parameter that is optionally sent by the client to the authorization server on token request.
	// If set the proof proof-of-possession public key needs to match or the proof is rejected.
	JKT string
}

// Parse translates a DPoP proof string into a JWT token and parses it with the jwt package (github.com/golang-jwt/jwt/v5).
// It will also validate the proof according to https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
// but not check whether the proof matches a bound access token. It also assumes point 1 is checked by the calling application.
//
// Protected resources should use the 'Validate' function on the returned proof to ensure that the proof matches any bound access token.
func Parse(
	tokenString string,
	httpMethod HTTPVerb,
	httpURL *url.URL,
	opts ParseOptions,
) (*Proof, error) {
	// Parse the token string
	// Ensure that it is a wellformed JWT, that a supported signature algorithm is used,
	// that it conatins a public key, and that the signature verifies with the public key.
	// This satisfies point 2, 5, 6 and 7 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
	var claims ProofTokenClaims
	dpopToken, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)
	if err != nil {
		return nil, errors.Join(ErrInvalidProof, err)
	}

	// Check that all claims have been populated
	// This satisfies point 3 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
	if claims.Method == "" || claims.URL == "" || claims.ID == "" || claims.IssuedAt == nil {
		return nil, errors.Join(ErrInvalidProof, ErrMissingClaims)
	}

	// Check `typ` JOSE header that it is correct
	// This satisfies point 4 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
	typeHeader := dpopToken.Header["typ"]
	if typeHeader == nil || typeHeader.(string) != "dpop+jwt" {
		return nil, errors.Join(ErrInvalidProof, ErrUnsupportedJWTType)
	}

	// Check that `htm` and `htu` claims match the HTTP method and URL of the current request.
	// This satisfies point 8 and 9 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
	httpUrlNoExtras := StripQueryAndFragments(httpURL)
	
	if httpMethod != claims.Method || httpUrlNoExtras != claims.URL {
		return nil, errors.Join(ErrInvalidProof, ErrIncorrectHTTPTarget)
	}

	// Check that `nonce` is correct
	// This satisfies point 10 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
	if opts.Nonce != "" && opts.Nonce != claims.Nonce {
		return nil, ErrIncorrectNonce
	}

	// Check that `iat` is within the acceptable window unless `nonce` contains a server managed timestamp.
	// This satisfies point 11 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
	if !opts.NonceHasTimestamp {
		// Check that `iat` is not too far into the past.
		past := DEFAULT_TIME_WINDOW
		if opts.TimeWindow != nil {
			past = *opts.TimeWindow
		}
		if claims.IssuedAt.Before(time.Now().Add(-past)) {
			return nil, errors.Join(ErrInvalidProof, ErrExpired)
		}

		// Check that `iat` is not too far into the future.
		future := DEFAULT_TIME_WINDOW
		if opts.TimeWindow != nil {
			future = *opts.TimeWindow
		}
		if claims.IssuedAt.After(time.Now().Add(future)) {
			return nil, errors.Join(ErrInvalidProof, ErrFuture)
		}
	}

	// Extract the public key from the proof and hash it.
	// This is done in order to store the public key
	// without the need for extracting and hashing it again.
	jwkHeaderJSON, err := json.Marshal(dpopToken.Header["jwk"])
	if err != nil {
		// keyFunc used with parseWithClaims should ensure that this can not happen but better safe than sorry.
		return nil, errors.Join(ErrInvalidProof, err)
	}
	h := sha256.New()
	_, err = h.Write([]byte(jwkHeaderJSON))
	if err != nil {
		return nil, errors.Join(ErrInvalidProof, err)
	}
	b64URLjwkHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Check that `dpop_jkt` is correct if supplied to the authorization server on token request.
	// This satisfies https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#name-authorization-code-binding-
	if opts.JKT != "" {
		if b64URLjwkHash != opts.JKT {
			return nil, errors.Join(ErrInvalidProof, ErrIncorrectJKT)
		}
	}

	return &Proof{
		Token:           dpopToken,
		HashedPublicKey: b64URLjwkHash,
	}, nil
}

func keyFunc(t *jwt.Token) (interface{}, error) {
	// Return the required jwkHeader header. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.2
	// Used to validate the signature of the DPoP proof.
	jwkHeader := t.Header["jwk"]
	if jwkHeader == nil {
		return nil, ErrMissingJWK
	}

	jwkMap, ok := jwkHeader.(map[string]interface{})
	if !ok {
		return nil, ErrMissingJWK
	}

	switch jwkMap["kty"].(string) {
	case "EC":
		// Decode the coordinates from Base64.
		//
		// According to RFC 7518, they are Base64 URL unsigned integers.
		// https://tools.ietf.org/html/rfc7518#section-6.3
		xCoordinate, err := base64urlTrailingPadding(jwkMap["x"].(string))
		if err != nil {
			return nil, err
		}
		yCoordinate, err := base64urlTrailingPadding(jwkMap["y"].(string))
		if err != nil {
			return nil, err
		}

		// Read the specified curve of the key.
		var curve elliptic.Curve
		switch jwkMap["crv"].(string) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, ErrUnsupportedCurve
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(xCoordinate),
			Y:     big.NewInt(0).SetBytes(yCoordinate),
		}, nil
	case "RSA":
		// Decode the exponent and modulus from Base64.
		//
		// According to RFC 7518, they are Base64 URL unsigned integers.
		// https://tools.ietf.org/html/rfc7518#section-6.3
		exponent, err := base64urlTrailingPadding(jwkMap["e"].(string))
		if err != nil {
			return nil, err
		}
		modulus, err := base64urlTrailingPadding(jwkMap["n"].(string))
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(modulus),
			E: int(big.NewInt(0).SetBytes(exponent).Uint64()),
		}, nil
	case "OKP":
		publicKey, err := base64urlTrailingPadding(jwkMap["x"].(string))
		if err != nil {
			return nil, err
		}

		return ed25519.PublicKey(publicKey), nil
	case "OCT":
		return nil, ErrUnsupportedKeyAlgorithm
	default:
		return nil, ErrUnsupportedKeyAlgorithm
	}
}

// Borrowed from MicahParks/keyfunc See: https://github.com/MicahParks/keyfunc/blob/master/keyfunc.go#L56
//
// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 Section 1.1 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
