package dpop

import (
	"crypto"
	"encoding/base64"
)

// Structure which bundles a string to be hashed
// with the associated hash function
// Used in utils library to ensure hash function is available to user
type HashInput struct {
	inString string
	hashFn	 crypto.Hash
}

// Internal function used to ensure hash is available and set the default
// to SHA256
func ValidateHashFunction(hashFn crypto.Hash) crypto.Hash {
	if hashFn.Available() {
		return hashFn
	}
	return crypto.SHA256
}

// Utility function to provide a default hashing utility
// for users to ensure hash values of claims match
// base64url-safe format
func HashUtil(input HashInput) (string, error) {
	hashFn := ValidateHashFunction(input.hashFn)
	hashFnInst := hashFn.HashFunc().New()
	// helped me here https://forum.golangbridge.org/t/help-with-sha256-code-solved/8210/4
	firstBytes, err := base64.RawURLEncoding.DecodeString(input.inString)
	if err != nil {
		return "", ErrInputMalformed
	}
	hashFnInst.Write(firstBytes)

	resultingHash := hashFnInst.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(resultingHash), nil
}

// Utility function to test the hashing value of an input strng
// against a provided encrypted string
func HashEquals(input HashInput, encryptedString string) (bool, error) {
	hashedInString, err := HashUtil(input)
	if err != nil {
		return false, err
	}
	return (encryptedString == hashedInString), nil
}