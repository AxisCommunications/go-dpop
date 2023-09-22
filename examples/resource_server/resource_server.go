package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AxisCommunications/go-dpop"
	"github.com/golang-jwt/jwt/v5"
)

var httpClient = http.Client{}

type BoundTokenClaims struct {
	*dpop.BoundAccessTokenClaims
	Scope []string `json:"scope"`
}

type JWKSet struct {
	Keys []ECJWK `json:"keys"`
}

type ECJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	KID string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// getResource will return the resource if a valid bound access token is provided with a DPoP proof
func getResource(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Resource server - got /resource request\n")
	httpUrl, _ := url.Parse("https://server.example.com/resource")

	// read access token header
	rawAccessTokenString := r.Header.Get("authorization")
	if rawAccessTokenString == "" || !strings.HasPrefix(strings.ToLower(rawAccessTokenString), "dpop") {
		fmt.Println("Incorrect authorization")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	accessTokenString := strings.TrimPrefix(rawAccessTokenString, "dpop ")

	// read proof header
	proofString := r.Header.Get("dpop")
	if proofString == "" {
		fmt.Println("No proof")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// validate proof
	acceptedTimeWindow := time.Hour * 24 * 365 * 10
	proof, err := dpop.Parse(proofString, dpop.GET, httpUrl, dpop.ParseOptions{
		TimeWindow: &acceptedTimeWindow,
	})
	// Check the error type to determine response
	if err != nil {
		if ok := errors.Is(err, dpop.ErrInvalidProof); ok {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, err.Error())
			return
		}
	}

	// validate access token
	claims := BoundTokenClaims{}
	accessToken, err := jwt.ParseWithClaims(accessTokenString, &claims, keyFunc)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, err.Error())
		return
	}

	// hash access token
	h := sha256.New()
	_, err = h.Write([]byte(accessTokenString))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}
	b64URLath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// validate proof and token binding
	err = proof.Validate([]byte(b64URLath), accessToken)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, err.Error())
		return
	}

	// aud and scope in bound token can be checked here to determine access to resource
	// but is skipped here for simplicity.

	io.WriteString(w, "This is the resource")
}

// keyFunc will read the public keys of the authorization server from the JWKS (/keys) endpoint.
func keyFunc(t *jwt.Token) (interface{}, error) {
	res, err := httpClient.Get("http://localhost:1337/keys")
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	data := JWKSet{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	jwkMap := data.Keys[0]

	// Decode the coordinates from Base64.
	xCoordinate, err := base64urlTrailingPadding(jwkMap.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := base64urlTrailingPadding(jwkMap.Y)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(xCoordinate),
		Y:     big.NewInt(0).SetBytes(yCoordinate),
	}, nil
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

func main() {
	http.HandleFunc("/resource", getResource)

	err := http.ListenAndServe(":40000", nil)
	fmt.Println(err)
}
