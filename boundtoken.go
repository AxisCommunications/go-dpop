package dpop

import "github.com/golang-jwt/jwt/v5"

// These claims contains fields that are required to be present in bound access tokens.
//
// If there is a need for custom claims this can be embedded
// in custom claims to ensure that claims are still possible to validate with the Validate function.
type BoundAccessTokenClaims struct {
	*jwt.RegisteredClaims

	// the `cnf` (Confirmation) claim. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-6.1
	Confirmation Confirmation `json:"cnf"`
}

type Confirmation struct {
	// the `jkt` (JWK Thumbprint) claim. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-6.1
	JWKThumbprint string `json:"jkt"`
}

// BoundAccessTokenClaims implements the 'ClaimsValidator' interface from golang-jwt/jwt.
//
// This ensures that bound tokens has the required JWK thumbprint when parsed with 'ParseWithClaims'
func (c *BoundAccessTokenClaims) Validate() error {
	if c.Confirmation.JWKThumbprint == "" {
		return ErrIncorrectAccessTokenClaimsType
	}
	return nil
}

// Implement the BoundClaims interface.
func (c *BoundAccessTokenClaims) GetJWKThumbprint() (string, error) {
	return c.Confirmation.JWKThumbprint, nil
}

// This interface allows for custom claims to be used in bound tokens.
//
// As long as any custom claims extends the 'BoundAccessTokenClaims' they will implement this interface
// and 'Validate' should handle them correctly
type BoundClaims interface {
	jwt.Claims
	GetJWKThumbprint() (string, error)
}
