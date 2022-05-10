package test


import (
	"crypto/x509"
	"crypto/ecdsa"

	"encoding/pem"

	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
  "github.com/stretchr/testify/assert"
)

var CA1 = NewTestCA("main")
var CA2 = NewTestCA("other")

func TestJWTValidPKI(t *testing.T)  {
	// Create a signed token from leaf cert in CA1
	signedToken,err := signValidJWT(CA1)
	assert.NoError(t, err)
	assert.NotEmpty(t, signedToken)

	// create token validator instance with rootCA of CA1
	rootCA1 := CA1.GetRootCert()
	tv := NewCATokenValidator(rootCA1)

	// use CATokenValidator to parse the token
	token, err := tv.ParseToken(signedToken)

	assert.NoError(t, err)
	assert.NotNil(t, token)
}

func TestJWTInValidPKI(t *testing.T)  {
	// Create a signed token from leaf cert in CA1
	signedToken,err := signValidJWT(CA1)
	assert.NoError(t, err)
	assert.NotEmpty(t, signedToken)

	// create token validator instance with rootCA of CA2
	rootCA2 := CA2.GetRootCert()
	tv := NewCATokenValidator(rootCA2)

	// use CATokenValidator to parse the token
	token, err := tv.ParseToken(signedToken)

	//expect a validation error
	assert.Error(t, err)
	assert.Nil(t, token)
}



// HELPER METHODS
func getPrivateKey(pemBytes []byte, password string) (key interface{}, err error) {
	var keyBytes []byte
	var block *pem.Block

	block, _ = pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM not parsed - %s", string(pemBytes))
	}
	keyBytes = block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	}
	pkcsKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if pkcsKey == nil {
		key, err = x509.ParseECPrivateKey(keyBytes)
	} else {
		key = pkcsKey
	}


	return key, err
}

func signValidJWT(ca *TestCA) (string, error) {
	pem, password := ca.GetLeafKey()
	privateKey, err := getPrivateKey(pem, password)
	if err != nil {
		return "", fmt.Errorf("getPrivatekey error : %s", err)
	}
	if privateKey == nil {
		return "", fmt.Errorf("Error getting private key")
	}
  // taken from golang-jwt/jwt/example_test.go
  claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "test",
			Subject:   "somebody",
		},
	}

	x5cStr := string(ca.GetLeafChain())

	var token *jwt.Token

	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
			// will work just for this showcase
			token = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		default:
			token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	}
	token.Header["x5c"] = x5cStr
	ss, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("token signing error: %s", err)
	}

	return ss, nil
}
