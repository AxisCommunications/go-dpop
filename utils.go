package dpop

import (
	"crypto"
	"encoding/hex"
)

func hashUtil(inString string, args ...crypto.Hash) (string, error) {
	var hashFn crypto.Hash
	if len(args) > 1 {
		return "", ErrTooManyArgs
	} else if len(args) < 1 {
		hashFn = crypto.SHA256
	} else {
		hashFn = args[0]
	}
	if !hashFn.Available() {
		return "", ErrHashFnNotAvailable
	}
	hashFnInst := hashFn.HashFunc().New()
	// helped me here https://forum.golangbridge.org/t/help-with-sha256-code-solved/8210/4
	firstBytes, err := hex.DecodeString(inString)
	if err != nil {
		return "", ErrInputMalformed
	}
	hashFnInst.Write(firstBytes)

	resultingHash := hashFnInst.Sum(nil)
	return hex.EncodeToString(resultingHash), nil
}

func HashEquals(inString string, encryptedString string, args ...crypto.Hash) (bool, error) {
	
	return (encryptedString == out), nil
}