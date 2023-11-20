package dpop

import "errors"

var (
	// If proof validation failed for some reason a `ErrInvalidProof` error is returned.
	//
	// More specific reason for why validation failed will be added as a joined error on this error.
	ErrInvalidProof = errors.New("invalid_dpop_proof")

	// If the nonce was not provided a `ErrIncorrectNonce` error is returned.
	//
	// When this error is returned the the server needs to supply the client with a new nonce.
	ErrIncorrectNonce = errors.New("use_dpop_nonce")

	// The claims of the DPoP proof are invalid.
	ErrMissingClaims = errors.New("missing claims")

	// The `typ` header of the proof is invalid.
	ErrUnsupportedJWTType = errors.New("unsupported jwt type")

	// The `htm` and `htu` headers of the proof target the wrong resource.
	ErrIncorrectHTTPTarget = errors.New("incorrect http target")

	// The proof has expired.
	ErrExpired = errors.New("proof has expired")

	// The proof is issued too far into the future.
	ErrFuture = errors.New("proof is issued too far into the future")

	// The hash function is not available
	ErrHashFnNotAvailable = errors.New("provided hash function is not available, please check binaries and linker")

	// When using hash util func, errors 
	// if more than one hash is provided in variadic args
	ErrTooManyArgs = errors.New("too many arguments for function")


	// The proof claims are not of correct type
	ErrIncorrectClaimsType = errors.New("incorrect claims type")

	// The proof missing the `ath` claim
	ErrMissingAth = errors.New("missing 'ath' claim")

	// The proof 'ath' claim does not match bound access token
	ErrAthMismatch = errors.New("ath mismatch")

	// The proof is missing the `jwk` public key header
	ErrMissingJWK = errors.New("missing 'jwk' header")

	// The proof 'jwk' public header does not match supplied jkt
	ErrIncorrectJKT = errors.New("incorrect 'jkt'")

	// The bound token 'jkt' claim does not match public key in proof
	ErrJWKMismatch = errors.New("key mismatch")

	// The bound access token claims are not of correct type
	ErrIncorrectAccessTokenClaimsType = errors.New("incorrect access token claims type")

	// The proof public key has an unsupported curve
	ErrUnsupportedCurve = errors.New("unsupported curve")

	// The proof uses an unsupported key algorithm
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")
)
