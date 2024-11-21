package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// Creates a DPoP proof for the given claims.
//
// For custom claims it is recommended to embedd the 'ProofTokenClaims'.
func Create(method jwt.SigningMethod, claims ProofClaims, privateKey crypto.Signer) (string, error) {
	jwk, err := reflect(privateKey.Public())
	if err != nil {
		return "", err
	}

	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "dpop+jwt",
			"alg": method.Alg(),
			"jwk": jwk,
		},
		Claims: claims,
		Method: method,
	}

	return token.SignedString(privateKey)
}

type ecdsaJWK struct {
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
	Kty string `json:"kty"`
}

type rsaJWK struct {
	Exponent string `json:"e"`
	Modulus  string `json:"n"`
	Kty      string `json:"kty"`
}

type ed25519JWK struct {
	PublicKey string `json:"x"`
	Kty       string `json:"kty"`
}

func reflect(v interface{}) (interface{}, error) {
	switch v := v.(type) {
	case *ecdsa.PublicKey:
		// Calculate the size of the byte array representation of an elliptic curve coordinate
		// and ensure that the byte array representation of the key is padded correctly.
		bits := v.Curve.Params().BitSize
		keyCurveBytesSize := bits/8 + bits%8

		return &ecdsaJWK{
			X:   base64.RawURLEncoding.EncodeToString(v.X.FillBytes(make([]byte, keyCurveBytesSize))),
			Y:   base64.RawURLEncoding.EncodeToString(v.Y.FillBytes(make([]byte, keyCurveBytesSize))),
			Crv: v.Curve.Params().Name,
			Kty: "EC",
		}, nil
	case *rsa.PublicKey:
		return &rsaJWK{
			Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(v.E)).Bytes()),
			Modulus:  base64.RawURLEncoding.EncodeToString(v.N.Bytes()),
			Kty:      "RSA",
		}, nil
	case ed25519.PublicKey:
		return &ed25519JWK{
			PublicKey: base64.RawURLEncoding.EncodeToString(v),
			Kty:       "OKP",
		}, nil
	}
	return nil, ErrUnsupportedKeyAlgorithm
}
