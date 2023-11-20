package dpop

import (
	"crypto"
	"encoding/hex"
)

func HashEquals(inString string, encryptedString string, args ...crypto.Hash) (bool, error) {
	var hashFn crypto.Hash
	if len(args) > 1 {
		return false, ErrTooManyArgs
	} else if len(args) < 1 {
		hashFn = crypto.SHA256
	} else {
		hashFn = args[0]
	}
	if !hashFn.Available() {
		return false, ErrHashFnNotAvailable
	}
	hashFnInst := hashFn.HashFunc().New()
	// helped me here https://forum.golangbridge.org/t/help-with-sha256-code-solved/8210/4
	firstBytes, _ := hex.DecodeString(inString)
	hashFnInst.Write(firstBytes)

	res := hashFnInst.Sum(nil)
	out := hex.EncodeToString(res)
	return (encryptedString == out), nil
}