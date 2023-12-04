# go-dpop

[![Go Reference](https://pkg.go.dev/badge/github.com/AxisCommunications/go-dpop.svg)](https://pkg.go.dev/github.com/AxisCommunications/go-dpop)
[![Coverage Status](https://badge.coveralls.io/repos/github/AxisCommunications/go-dpop/badge.svg?branch=main)](https://badge.coveralls.io/github/AxisCommunications/go-dpop?branch=main)

OAuth 2.0 Demonstrating Proof of Possession (DPoP)

This package tries to implement [RFC-9449](https://datatracker.ietf.org/doc/html/rfc9449)

## Supported key algorithms

Supported:

- ES256, ES384, ES521
- RS256, PS256
- Ed25519

## How to use

### Authorization server

An authorization server needs to parse the incoming proof in order to associate the public key of the proof with the bound access token.  
It should parse the proof to ensure that the sender of the proof has access to the private key.

```go
import "github.com/AxisCommunications/go-dpop"

proof, err := dpop.Parse(proofString, dpop.POST, &httpUrl, dpop.ParseOptions{
    Nonce:      "",
    TimeWindow: &duration,
  })
// Check the error type to determine response
if err != nil {
  if ok := errors.Is(err, dpop.ErrInvalidProof); ok {
    // Return 'invalid_dpop_proof'
  }
}

// proof is valid, get public key to associate with access token
jkt := proof.PublicKey()

// Continue
```

### Resource server

Resource servers need to do the same proof validation that authorization servers do but also check that the proof and access token are bound correctly.

```go
import "github.com/AxisCommunications/go-dpop"

proof, err := dpop.Parse(proofString, dpop.POST, &httpUrl, dpop.ParseOptions{
    Nonce:      "",
    TimeWindow: &duration,
  })
// Check the error type to determine response
if err != nil {
  if ok := errors.Is(err, dpop.ErrInvalidProof); ok {
    // Return 'invalid_dpop_proof'
  }
}

// Hash the token with base64 and SHA256
// Get the access token JWT (introspect if needed)
// Parse the access token JWT and verify the signature

err = proof.Validate(accessTokenHash, accessTokenJWT)
// Check the error type to determine response
if err != nil {
  if ok := errors.Is(err, dpop.ErrInvalidProof); ok {
    // Return 'invalid_dpop_proof'
  }
  if ok := errors.Is(err, dpop.ErrIncorrectAccessTokenClaimsType); ok {
    // Return 'invalid_token'
  }
}

// Continue
```

### Client

A client can generate proofs that authorization and resource servers can validate.

```go
import "github.com/AxisCommunications/go-dpop"

// Setup the claims of the proof
claims := &dpop.ProofTokenClaims{
  RegisteredClaims: &jwt.RegisteredClaims{
    Issuer:    "test",
    Subject:   "sub",
    IssuedAt:  jwt.NewNumericDate(time.Now()),
    ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
    ID:        "id",
  },
  Method: dpop.POST,
  URL:    "https://server.example.com/token",
}

// Create a key-pair to be used for signing
privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
  ...
}

// Create a signed proof string
proofString, err := dpop.Create(jwt.SigningMethodES256, claims, privateKey)
if err != nil {
  ...
}

// Send the proof string in the 'DPoP' header to the server
```

### Note on HMAC

Although this package can in theory support symmetric keys the [DPoP draft does not allow private keys](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#name-dpop-proof-jwt-syntax) to be sent in the proof `jwk` header. As a symmetric key has no public key cryptography it can not be included in the proof, hence why it is unsupported.
