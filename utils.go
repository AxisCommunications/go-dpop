package dpop

import (
	"crypto"
	"encoding/base64"
)

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
func HashUtil(inString string, args ...crypto.Hash) (string, error) {
	hashFn, err := ValidateHashFunction(args...)
	if err != nil {
		return "", err
	}
	hashFnInst := (*hashFn).HashFunc().New()
	// helped me here https://forum.golangbridge.org/t/help-with-sha256-code-solved/8210/4
	firstBytes, err := base64.RawURLEncoding.DecodeString(inString)
	if err != nil {
		return "", ErrInputMalformed
	}
	hashFnInst.Write(firstBytes)

	resultingHash := hashFnInst.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(resultingHash), nil
}

// Utility function to test the hashing value of an input strng
// against a provided encrypted string
func HashEquals(inString string, encryptedString string, args ...crypto.Hash) (bool, error) {
	hashedInString, err := HashUtil(inString, args...)
	if err != nil {
		return false, err
	}
	return (encryptedString == hashedInString), nil
}