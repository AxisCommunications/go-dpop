package dpop_test

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/AxisCommunications/go-dpop"
)

// All proofs used in tests have been generated through the use of <https://github.com/panva/dpop>
// with slight modifications to support `ES384` and `ES512` curves (unless stated otherwise).
const (
	// Proof supplied in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-5
	validES256_proof            = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	validES384_proof            = "eyJhbGciOiJFUzM4NCIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoiSFpIaURjejQ0YkFNMVF3RG95bGhOUFBQb3VDdDJZbkRnOHk5ZXRBeUc1Ry1vY28zSEQ0M3JwazVZUW41cGdZaSIsInkiOiJ0UmlvSTY2TUFDV2x1NDVIWlN2TUdBV0xJTWxXdW9SdktPWGw0OUpGam9sRGtiTWs3cV9PWnFzSFJlMnhjcTNYIn19.eyJpYXQiOjE2ODYxNDY5MTEsImp0aSI6InhfNVJGUHpZT3BmU24yWlhSNmFSdHA3alZWQmVSbXI4VTRZLXBHbUpWb2siLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.xJVZXG69LbP1vXwI6NmpN4OkE9F3VNTHhZ5Or_tprZTU3GEVrao62DuF9jopyCjFIcq2UhHNRjubgG8XLcTGDEeLXB4UmDoAqgBColO679oaEz_uUdz-ThTDBSohPMeF"
	validES512_proof            = "eyJhbGciOiJFUzUxMiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC01MjEiLCJ4IjoiQVNlNUZUS3FlaUpQdHU5eVA2Z0pOLXZDbVhrQU9vbW1Hd0V2blRqR2JGaTlwUUJRQ3kyRFFuUS1kMWdYVENJdnhRRGVDdUdzLUF4Q1ZYc1V6cHUwU3ExXyIsInkiOiJBZmgySU5GMWRnaTlFR0VseDFqYlVtZEx6Q0F0M21pNGhobkIwMTJVWkU0SjhEdV9uOEpfQ1VxSGZIeHNPeWhSYU1oS2VHREhkRll5YjNuMFhpckFMT3ZJIn19.eyJpYXQiOjE2ODYxNDY5NTAsImp0aSI6IllzcVl1ZUh4UlpYYjZ4dkdRdUJmRGtDdVlxMFJEajNxN1RKMWtoWHlza2ciLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.AV-4ecrtReVhkKq-un0ghWpBhNnatuIqXmKvjlXKcor8_pAHlo9sLU6cbPUuw1SZdSZzwDqweNnpetjC5knae887AN3CZlfQwD2jrMd9kwCp-JEkq_dGLX1yqUc6Qt_XFe5vTSf_0ducHxh3lcnri-DqGrZAFC2GH3qUgatCNF8z8QjM"
	validRS256_proof            = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6Im9OakUxRXh5ZlV0Q2c1Y1RiQWRVOG9IdHZPQUNobnlyRVJkR2RMM0szQkpKcDBmWXFEYzN0MFlESjhLeDFJMUpnbks0VzFEQlNGbVgtVHJ4WExCWUk0c1FiZVdVcGFPRlNxSGZ5clpRQnA5UWRkTXNQaTlkRi0wNHNlajNpWUlyV2tUY3RkcERLWE8taGMxM01uVVdPLURkS3RYbnFrU0R4VGoxX0RNdEw5cXpRRXJiSW1UTS1zZGpBcHpFQWVCbzJDNmphbW1vcGNRWUxlY0FKMmlUdjhfUk80Q3lIX0hvTEd5SXp2YTRMOHFiMGtsRXpZd2VrelN4QVhXYUswbGtXNHo5YXR5czg1REY4ajlaajJzX0UwZEdDdzRaRmhqNmpIQ1hjYS1ubDNab2dmcXpPV0l6dHlwbERCNjRBa1h1VUdWVmNZVFlJZlY0MHJVbWQ1Q2hKUSJ9fQ.eyJpYXQiOjE2ODYxNDc2MjQsImp0aSI6IkFFU3pDOUNnckRPazRvZFl3Y3VVSWdkU1dvaTlXVGRzVzFzdlF4dzd6NTQiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.TXFcaC16MC0PGxqlDSMqWLkYbLauEDMeGB1whPazPVxqDoRKanacS111vWk4Vel-Z6vyMEev78It-7Vv2WP5djWp_xWsFXvhVQkUTMsHPnF4Qt_yTFJywW-WNVLfveFOQMNfaNrW0k7_8Zo5cE53_lnXwszGtmS_dhEBz5vJnMwyCZGPjC1M3MKnv-xCzJ1xJoGmpxIdRLbnCdAhuWdj1sw6SI-l68Af0NQpI4LJyfSWICtFzShytbVGw3UIzADg32Cl8xDVCiPCmb4oNTDokDkRAc4cz0mP2AlDqvtGaVX1-bW-GabqbxYFYeNfO7UjGKqB6oKeNOD0dAEj6pIOKw"
	validPS256_proof            = "eyJhbGciOiJQUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6InlRUHlNVXl0X19YYUo1UUZCQVRJYV9DeWxMLUsyTjRuWkl3RnFaNUVtdkhvbS1oRW9LeXVFa1h4LTFxZ29UV0VBdEh2dUYzTEV4NkttUl92SlJMa0dSdFNjSXVoamFKVVRXOFYwaGdUN2tjUUR6N3cybzR2R3NkQ3ZMZU1za19JS2dOb21oZGJjS1d2VjJzdjBvU2RaWVBsVWZxMlhtSnZ0cGh6b1piTVJlNFdRcVZBTUJBSktlYTdOamVoVGhhN1A5T1VPdDJMM0t0dzFwQTZZTmdNUkJobmpwN255VEtvejRvczNaVUdNLVM2Q3pLR0puNHdReEpock5tWHRJenRFWHl0ZWsyRlhpWGVGODFkbVBISHhOZjZZU18tSU1QSFF4dXVTdVpQM3RuZ0U5ZF9WNV9tTFI5QmsycGdEakJ1cl9wei1WWV8zdk4yMnE5Tk5DRE16dyJ9fQ.eyJpYXQiOjE4OTM0NTI0MDAsImp0aSI6ImpPSk1OaGVrTlZma0ttSXQtcU1scm1PQm5qUHQ4dlRxVXljWl84MWlCRE0iLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.D4VD2VseUyCu7gPzeQJduGtHBsz3EygfqrfScSfccpL7fSo0-eVaCfI7gWW9usbynqOKIrMqU9kqlMQj4tXKCN7rHxHiHQcjSdDvnMDeKrS22fp6kSfQQJtcb7bQxQZXvKzkCoqruJBvDSTgScNwW2CNcI9VhNQRtoWyXnf0ijZnDeX9uWeaD_rG1wE3hT8cnOmyKfNal1X4MLz30-rRBDmwl-ubdPIC87uvJSnUlhoRjioBXMNg1pXGowO1tDUO-TDeh-7kJEIlb9uhOJq3NiTNdjb5iDw-IuSzwZSc4mp7pYtMAEs8Amuypcoc3DzmwVjE56nDvuzWrBf2XMu0jg"
	validEd25519_proof          = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV0JfdEFJOXhBYVYxQnBBTm83MGdQdXFxYmFXdUd4Yjc4RWs4ckFndGdoTSJ9fQ.eyJpYXQiOjE2ODYyMDQ5OTcsImp0aSI6ImkxbFlVREVKVnhKbFNXQ1J3RFdqeDNpX0NfbHI5YkU5akY4M2pNNVg0c2MiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.KuJM02onLlKasjyEIsJkFMvHhwurdowJseV3JQ-8e4cwVfB0GsGLF8PAmV6PallVj9oLd9ek-T79l5j2jIFkBw"
	invalidSignature_proof      = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiNENaRmpEb1R0a3owbURiUzF0MERoSUp4Tk1JMk9LeVNxejlESTNieW1OUSIsInkiOiJoUUlTRGxWTGw4amtEa2toUjZ6RmJfU3BvdlBkSWZ1ZVNkdkZvQTRlaFd3In19.eyJpYXQiOjE2ODYxNDc1NTMsImp0aSI6ImNTQU1aTkVlaGM0b1BCMnd4UXRneGtFaUFHaHdsSmRTTEtVOTFsVFZNMWciLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.HztSUtcKbwJu4M27-TXG6CPOHVFZMJvpHiORlGKcHsDJBKwKtkJBtwP0WBM18YwMr_Z-xhV04Ow-kb6dc0pCGw"
	invalidMissingTyp_proof     = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlB1dnJLVXRYaHRWVEdfc2RGUE5yR3ZDNTZpWUV0VEt6bDhnSGtBbzdMa1kiLCJ5Ijoib2RiM2J2Y1p2bnhzbTJHMXp6M01fX1A2TW5ScjdqTVZycXFUUXdHdUxtRSJ9fQ.eyJpYXQiOjE2ODYxNDc2ODMsImp0aSI6IlNZemdKNlhyZWYzdUozSGZqYkJlZWRSVHJiSzlFZnBGUHBRZUIzd1ZCR1EiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.e3jBxBk1xrMtzubb2151xpBcur7felFkKmM55yQNNwkdzl7ZZbWeI8CwI3hASnzdTfB5GwsmnfRlcLToLyzUjA"
	invalidMissingClaims_proof  = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZkhLUWxjRzFieGFtUWpUdlB1QlFRWVh3c0ZHV1BkLXROQUcyc2hDM09MOCIsInkiOiJFV01LTkhIZWRJWHhQa0ZBUjEtRWxvYUxuLUhSbzRUZzZ1dWcwMlgxcnFVIn19.eyJpYXQiOjE2ODYxNDc3MzZ9.8_ATzwnK6As9Fy52yLqW2MKeveGXkZ5vY5GCJGSPkHKfIhjaH6g0DyUT8Gl31rHtxfz8mr-LxOgjEqTwbgPshQ"
	invalidSignedInFuture_proof = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaDdpRFh0ZEIxQ3RIc1lZcThBc3RaWkpyamhYYVB1RUljSkllRWhuaWk2VSIsInkiOiJmandBSDNBY3dWMGFKblVSVE9kOHlGU09wU09SLTBjbnhPYzhXWFhsbU93In19.eyJpYXQiOjE4OTM0NTI0MDAsImp0aSI6IjcxX2FXLTN6TW5zNkRjdU5aT1FVZS15M2FOclYtRFo2WVJlQ0tRRTBGLTgiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.DGp-Eqhqr3cICf_C66auqLvyv51tmY7fAyVhsPnrGurCGGHE8jdU5QbrZnhqMeLj3K9PLWIeoxOsdr7fySB_zw"
	malformedJWKHeader_proof    = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjoiZXJyb3IifQ.eyJpYXQiOjE2ODYxNDY0ODcsImp0aSI6InBYV0xGcXRzRjI4ZTBhNm52Y25zUHZ4bWZtV1o4VDRUZEhka3g3QUkxaFUiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.zwy1MgdrqXVQ4BHr7GaWPKAwBSJvmjHZ1p9K3bYu94pz22Ai17Op6G2HF4T0bC8Hxk0aqsGDBSjgNvGBkQXA5w"
	missingJWKHeader_proof      = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJpYXQiOjE2ODYxNDc4MzMsImp0aSI6IlRIaF82Sml3RWNFMEk4NFVGMVNPX3hOc09IY2pld29WcVpHUHhodmcycUUiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.XlZ2VbVx4qPwuuJrUHTZG5Bm7KKRGjwcdWBWuOiYdrdvEIR3W62bB2xqI9QqSU6XoyjTlb6DfY1865UDnGzbQA"
	// Currently signed by a OCT alg, needs to be changed once OCP is supported
	unsupportedKeyAlg_proof = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Im9jdCIsImtpZCI6IjBhZmVlMTQyLWEwYWYtNDQxMC1hYmNjLTlmMmQ0NGZmNDViNSIsImFsZyI6IkhTMjU2IiwiayI6IkZkRllGekVSd0MydUNCQjQ2cFpRaTRHRzg1THVqUjhvYnQtS1dSQklDVlEifX0.eyJpYXQiOjE4OTM0NTI0MDAsImp0aSI6IlZ2cTdTMTZBUUwwVEkzdWZiSWFabEtYS0FkdjU0dkVhQ3JyVjJUa0lBbDQiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20vdG9rZW4ifQ.UEIBBDOkv_NberiIX0w4TiHnwOCQ5XXXidXdyv8JjpA"
)

// Test that a malformed tokenString is rejected
func TestParse_MalformedTokenString(t *testing.T) {
	// Act
	_, err := dpop.Parse("malformed", dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		ok := errors.Is(err, dpop.ErrInvalidProof)
		if !ok {
			t.Errorf("Unexpected error type: %v", err)
		}
	}
}

// Test that a valid JWT but not valid proof is rejected
func TestParse_NonProofJWT(t *testing.T) {
	// Act
	proof, err := dpop.Parse("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc"+
		"GxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", dpop.POST,
		&url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrMissingJWK)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that proof with malformed `jwk` header is rejected
func TestParse_MalformedJWKHeader(t *testing.T) {
	// Act
	proof, err := dpop.Parse(malformedJWKHeader_proof, dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrMissingJWK)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that proof with missing `jwk` header is rejected
func TestParse_MissingJWKHeader(t *testing.T) {
	// Act
	proof, err := dpop.Parse(missingJWKHeader_proof, dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrMissingJWK)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that missing claims are rejected
func TestParse_MissingClaims(t *testing.T) {
	// Act
	proof, err := dpop.Parse(invalidMissingClaims_proof, dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrMissingClaims)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that missing `typ` header is rejected
func TestParse_MissingTypHeader(t *testing.T) {
	// Act
	proof, err := dpop.Parse(invalidMissingTyp_proof, dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrUnsupportedJWTType)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that incorrect `nonce` claim is rejected
func TestParse_IncorrectNonce(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "wrong",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		ok := errors.Is(err, dpop.ErrIncorrectNonce)
		if !ok {
			t.Errorf("Unexpected error type: %v", err)
		}
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that invalid signature is rejected
func TestParse_InvalidSignature(t *testing.T) {
	// Act
	proof, err := dpop.Parse(invalidSignature_proof, dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		ok := errors.Is(err, dpop.ErrInvalidProof)
		if !ok {
			t.Errorf("Unexpected error type: %v", err)
		}
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that incorrect `htm` claim is rejected
func TestParse_IncorrectHtm(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.GET, &httpUrl, opts)

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrIncorrectHTTPTarget)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that incorrect `htu` claim is rejected
func TestParse_IncorrectHtu(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "notFriendlyPlace",
		Path:   "/help",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrIncorrectHTTPTarget)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

func TestParse_CorrectHttpURLWithQueryFragments(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
		Fragment: "#fragment",
		RawQuery: "foo=bar",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("wanted nil, got %e", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that expired proof is rejected
func TestParse_ExpiredProof(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(1) * time.Minute
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrExpired)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that a proof signed too far into the future is rejected
func TestParse_ProofSignedTooFarIntoFuture(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(10) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(invalidSignedInFuture_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrFuture)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that a proof signed with an unsupported algorithm is rejected
func TestParse_ProofSignedWithUnsupportedAlgorithm(t *testing.T) {
	// Act
	proof, err := dpop.Parse(unsupportedKeyAlg_proof, dpop.POST, &url.URL{}, dpop.ParseOptions{})

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrUnsupportedKeyAlgorithm)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that proof supplied with a incorrect 'dpop_jkt' is rejected
func TestParse_ProofWithIncorrectDpopJkt(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
		JKT:        "incorrect",
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err == nil {
		t.Errorf("Expected error")
	}
	if err != nil {
		AssertJoinedError(t, err, dpop.ErrIncorrectJKT)
	}
	if proof != nil {
		t.Errorf("Expected nil token")
	}
}

// Test that proof supplied with a correct 'dpop_jkt' is validated correctly
func TestParse_ProofWithCorrectDpopJkt(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
		JKT:        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that a proof signed with a ES256 key is validated correctly
func TestParse_ProofWithES256(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that a proof signed with a ES384 key is validated correctly
func TestParse_ProofWithES384(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES384_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil && proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that a proof signed with a ES512 key is validated correctly
func TestParse_ProofWithES512(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validES512_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that a proof signed with a RSA-PSS key is validated correctly
func TestParse_ProofWithRS256(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validRS256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that a proof signed with a RSASSA-PKCS1-v1_5 key is validated correctly
func TestParse_ProofWithPS256(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validPS256_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}

// Test that a proof signed with a Ed25519 key is validated correctly
func TestParse_ProofWithEd25519(t *testing.T) {
	// Arrange
	httpUrl := url.URL{
		Scheme: "https",
		Host:   "server.example.com",
		Path:   "/token",
	}
	duration := time.Duration(438000) * time.Hour
	opts := dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &duration,
	}

	// Act
	proof, err := dpop.Parse(validEd25519_proof, dpop.POST, &httpUrl, opts)

	// Assert
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if proof == nil || proof.Valid != true {
		t.Errorf("Expected token to be valid")
	}
}
