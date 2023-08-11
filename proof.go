package dpop

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// These claims contains the standard fields of a DPoP proof claim.
//
// If there is a need for custom claims this can be embedded
// in custom claims to ensure that claims are still possible to validate with the Validate function.
type ProofTokenClaims struct {
	*jwt.RegisteredClaims

	// the `htm` (HTTP Method) claim. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.2
	Method HTTPVerb `json:"htm"`

	// the `htu` (HTTP URL) claim. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.2
	URL string `json:"htu"`

	// the `ath` (Authorization Token Hash) claim. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.2
	AccessTokenHash string `json:"ath,omitempty"`

	// the `nonce` claim. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.2
	Nonce string `json:"nonce,omitempty"`
}

// Implement the ProofClaims interface.
func (p ProofTokenClaims) GetAccessTokenHash() (string, error) {
	return p.AccessTokenHash, nil
}

// This interface allows for custom claims to be used in proof tokens.
//
// As long as any custom claims extends the 'ProofTokenClaims' they will implement this interface
// and 'Validate' should handle them correctly
type ProofClaims interface {
	jwt.Claims
	GetAccessTokenHash() (string, error)
}

// Represents a DPoP proof, if acquired through the Parse function it should be a valid DPoP proof.
//
// However if a bound access token was recieved with the proof the Validate function needs be used to verify that the proof is valid for the access token.
type Proof struct {
	*jwt.Token
	HashedPublicKey string
}

// Validate takes a bound access token and validate that the token is bound correctly to this DPoP proof.
// This satisfies point 12 in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.3
//
// Validate needs to be called by a protected resource after parsing the DPoP proof.
// A bound access token needs to be introspected by the resource server in order for claims to be availabe for validation.
//
// The bound access token should be validated before calling this function
// and the claims of the introspected bound access token needs to be of the BoundAccessTokenClaims type.
//
// The access token hash needs to be a URL encoded SHA256 hash of the access token.
//
// If no error is returned the proof is valid for the supplied bound token.
func (t *Proof) Validate(accessTokenHash []byte, boundAccessTokenJWT *jwt.Token) error {
	// Make sure the proof token claims are of the correct type.
	claims, ok := t.Claims.(ProofClaims)
	if !ok {
		return errors.Join(ErrInvalidProof, ErrIncorrectClaimsType)
	}

	proofAccessTokenHash, err := claims.GetAccessTokenHash()
	if err != nil {
		return errors.Join(ErrInvalidProof, err)
	}

	// Check that proof has a bound access token
	if proofAccessTokenHash == "" {
		return errors.Join(ErrInvalidProof, ErrMissingAth)
	}

	// Control that bound token in proof matches supplied token
	if proofAccessTokenHash != string(accessTokenHash) {
		return errors.Join(ErrInvalidProof, ErrAthMismatch)
	}

	// Check that proof has a key
	b64URLjwkHash := t.PublicKey()
	if b64URLjwkHash == "" {
		return errors.Join(ErrInvalidProof, ErrMissingJWK)
	}

	// Make sure bound access token claims are of the correct type.
	boundTokenClaims, ok := (boundAccessTokenJWT.Claims).(BoundClaims)
	if !ok {
		return ErrIncorrectAccessTokenClaimsType
	}

	// Check that key in proof matches bound token key
	jkt, err := boundTokenClaims.GetJWKThumbprint()
	if err != nil {
		return errors.Join(ErrIncorrectAccessTokenClaimsType, err)
	}
	if jkt != b64URLjwkHash {
		return errors.Join(ErrInvalidProof, ErrJWKMismatch)
	}

	return nil
}

// Get the public key from the proof.
//
// The public key string is base64 and url encoded according to https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-6.1
// in order to help comparison of proof public key and 'jkt' claim of a bound access token.
//
// An authorization server can use this to get the 'jkt' value it should encode in the bound access token.
func (t *Proof) PublicKey() string {
	return t.HashedPublicKey
}
