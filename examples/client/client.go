package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AxisCommunications/go-dpop"
	"github.com/golang-jwt/jwt/v5"
)

type tokenRequestBody struct {
	Resource string   `json:"resource"`
	Scope    []string `json:"scope"`
}

func main() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a DPoP proof token in order to request a bound token from the authorization server
	claims := dpop.ProofTokenClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    "client",
			Subject:   "user",
			Audience:  jwt.ClaimStrings{"https://server.example.com/token"},
			ID:        "random_id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Method: dpop.POST,
		URL:    "https://server.example.com/token",
	}
	proof, err := dpop.Create(jwt.SigningMethodES256, &claims, privateKey)
	if err != nil {
		panic(err)
	}

	// Request a bound token from the authorization server
	fmt.Println("Client - requesting a bound token from the authorization server")
	body := tokenRequestBody{
		Resource: "https://server.example.com/resource",
		Scope:    []string{"read", "write"},
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", "http://localhost:1337/token", bytes.NewReader(jsonBody))
	if err != nil {
		panic(err)
	}
	req.Header.Add("dpop", proof)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	// Read the bound token from the response
	boundTokenString, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	res.Body.Close()
	fmt.Printf("Client - received bound token: %s\n", boundTokenString)

	// Create a bound DPoP proof token in order to access the resource server
	h := sha256.New()
	_, err = h.Write([]byte(boundTokenString))
	if err != nil {
		panic(err)
	}
	ath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	claims = dpop.ProofTokenClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    "client",
			Subject:   "user",
			Audience:  jwt.ClaimStrings{"https://server.example.com/resource"},
			ID:        "random_id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Method: dpop.GET,
		URL:    "https://server.example.com/resource",
		// This binds the proof to the bound token
		AccessTokenHash: ath,
	}
	// Sign with the same private key used to sign the proof that was sent to the authorization server
	boundProof, err := dpop.Create(jwt.SigningMethodES256, &claims, privateKey)
	if err != nil {
		panic(err)
	}

	// Access the resource server
	fmt.Println("Client - accessing the resource server")
	req, err = http.NewRequest("POST", "http://localhost:40000/resource", bytes.NewReader(jsonBody))
	if err != nil {
		panic(err)
	}
	req.Header.Add("dpop", boundProof)
	req.Header.Add("Authorization", fmt.Sprintf("dpop %s", boundTokenString))
	resourceRes, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	// Read the resource server response
	defer res.Body.Close()
	resourceBody, err := io.ReadAll(resourceRes.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Client - resource server response: %s\n", string(resourceBody))
}
