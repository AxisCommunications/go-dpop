package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/AxisCommunications/go-dpop"
	"github.com/golang-jwt/jwt/v5"
)

var privateKey *ecdsa.PrivateKey

type BoundTokenClaims struct {
	*dpop.BoundAccessTokenClaims
	Scope []string `json:"scope"`
}

type ECJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	KID string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// postToken will accept requests to create a bound a token
func postToken(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Authorization server - got /token request\n")
	httpUrl, _ := url.Parse("https://server.example.com/token")

	// read proof header
	proofString := r.Header.Get("dpop")
	if proofString == "" {
		fmt.Println("No proof")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// validate proof
	acceptedTimeWindow := time.Hour * 24 * 365 * 10
	proof, err := dpop.Parse(proofString, dpop.POST, httpUrl, dpop.ParseOptions{
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

	// proof is valid, get public key to associate with access token
	jkt := proof.PublicKey()

	// The server should check credentials of calling user here to ensure that the user has access to this api
	// but is skipped here for simplicity.

	// read body
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "unreadable body")
		return
	}

	// parse body
	data := &struct {
		Resource string   `json:"resource"`
		Scope    []string `json:"scope"`
	}{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "malformed body")
		return
	}

	// It is a good idea to validate that the caller has the access that they are requesting
	// but is skipped here for simplicity.

	// create bound JWT
	claims := &BoundTokenClaims{
		BoundAccessTokenClaims: &dpop.BoundAccessTokenClaims{
			RegisteredClaims: &jwt.RegisteredClaims{
				Issuer:    "example.com",
				Subject:   "user",
				Audience:  []string{data.Resource},
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				ID:        "unique-id",
			},
			Confirmation: dpop.Confirmation{JWKThumbprint: jkt},
		},
		Scope: data.Scope,
	}
	boundToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	boundToken.Header["kid"] = "auth-key"
	boundTokenString, err := boundToken.SignedString(privateKey)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "could not create token")
		return
	}

	// return signed bound JWT
	io.WriteString(w, boundTokenString)
}

// getKeys returns a list of public keys that can be used to verify bound tokens.
func getKeys(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Authorization server - got /keys request\n")
	jwks := &struct {
		Keys []ECJWK `json:"keys"`
	}{[]ECJWK{{
		KTY: "EC",
		CRV: privateKey.PublicKey.Params().Name,
		KID: "auth-key",
		X:   base64.RawURLEncoding.Strict().EncodeToString(privateKey.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.Strict().EncodeToString(privateKey.PublicKey.Y.Bytes()),
	}}}

	response, err := json.Marshal(jwks)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	io.WriteString(w, string(response))
}

func main() {
	// generate private key that will be used to sign authorization server tokens
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	// start server
	http.HandleFunc("/token", postToken)
	http.HandleFunc("/keys", getKeys)

	err = http.ListenAndServe(":1337", nil)
	fmt.Println(err)
}
