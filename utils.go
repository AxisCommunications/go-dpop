package dpop

import (
	"crypto"
	"encoding/hex"
)

// type MockHash struct {}

// func NewMockHash() hash.Hash {
// 	return &MockHash{}
// }

// func (m *MockHash) Write(p []byte) (n int, err error) {
// 	return 0, nil
// }

// func (m *MockHash) Sum(b []byte) []byte {
// 	return nil
// }

// func (m *MockHash) Reset() {}

// func (m *MockHash) Size() int {
// 	return 0
// }

// func (m *MockHash) BlockSize() int {
// 	return 0
// }

// func (m *MockHash) Available() bool {
// 	return false
// }

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