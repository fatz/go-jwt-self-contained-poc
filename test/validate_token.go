package test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.RegisteredClaims
}

func ParseX5CHeader(x5c string) (signingCert *pem.Block, chain []*pem.Block, err error) {
  x5cBytes := []byte(x5c)

  var blocksChain []byte
  signingCert, blocksChain = pem.Decode(x5cBytes)

  if signingCert == nil {
    return nil, nil, fmt.Errorf("No PEM Block found")
  }

  if len(blocksChain) > 0 {
    var rest []byte

    rest = blocksChain

    for len(rest) > 0 {
      var cert *pem.Block
      cert, rest = pem.Decode(rest)
      if cert == nil {
        break
      }

      chain = append(chain, cert)
    }
  }

  return signingCert, chain, nil
}

func CertPoolFromChain(certChain []*pem.Block) *x509.CertPool {
  if len(certChain) > 0 {
    pool := x509.NewCertPool()
    for _, block := range certChain {
      cert, err := x509.ParseCertificate(block.Bytes)
      if err != nil {
        continue
      }
      pool.AddCert(cert)
    }

    return pool
  }

  return nil
}

type CATokenValidator struct {
  RootCA []byte

  FallbackStaticPublicKey *x509.Certificate
}

// NewCATokenValidator takes a rootCA PEM to create a CATokenValidator instance
func NewCATokenValidator(rootCA []byte) *CATokenValidator {
  c := new(CATokenValidator)
  c.RootCA = rootCA
  c.FallbackStaticPublicKey = nil

  return c
}

// NewCATokenValidatorWithFallbackCert takes a rootCA PEM and a fallback certificate PEM to create a CATokenValidator instance
func NewCATokenValidatorWithFallbackCert(rootCA []byte, fallback []byte) (c *CATokenValidator, err error) {
  c = new(CATokenValidator)
  c.RootCA = rootCA

  block, _ := pem.Decode(fallback)
  c.FallbackStaticPublicKey, err = x509.ParseCertificate(block.Bytes)
  if err != nil {
    return nil, err
  }

  return
}

func (c *CATokenValidator) getCertPool() *x509.CertPool {
  certPool := x509.NewCertPool()

  certPool.AppendCertsFromPEM(c.RootCA)

  return certPool
}

// Verify takes the signingCert from jwt.Token x5c header and validates its chain against CATokenValidator.RootCA
func (c *CATokenValidator) Verify(signingCert *pem.Block, chain ...*pem.Block) (bool, error) {
  verifyOpts := x509.VerifyOptions{
    Roots: c.getCertPool(),
    Intermediates: CertPoolFromChain(chain),
  }

  cert, err := x509.ParseCertificate(signingCert.Bytes)
  if err != nil {
    return false, err
  }

  _, err = cert.Verify(verifyOpts)
  if err != nil {
    return false, err
  }

  return true, nil
}

// Keyfunc implements jwt.KeyFunc
func (c *CATokenValidator) Keyfunc(token *jwt.Token) (interface{}, error) {
  // Check Header and return Fallback key if possible
  var x5cStr string
  var strOK bool

  x5c, headerOK := token.Header["x5c"]
  if headerOK {

    x5cStr, strOK = x5c.(string)
    if !strOK {
      return nil, fmt.Errorf("x5c header must be str")
    }
  }

  if !headerOK || (strOK && x5cStr == "") {
    if c.FallbackStaticPublicKey == nil {
      return nil, fmt.Errorf("Token does not Contain a Public key and no Fallback key specified")
    }
    return c.FallbackStaticPublicKey, nil
  }

  signingCert, chain, err := ParseX5CHeader(x5cStr)
  if err != nil {
    return nil, fmt.Errorf("ParseX5C Header error: %s", err)
  }

  certOK, err := c.Verify(signingCert, chain...)
  if err != nil {
    return nil, fmt.Errorf("Verify error: %s", err)
  }

  if !certOK {
    return nil, fmt.Errorf("Certificate not verified")
  }
  switch token.Method.(type) {
  case *jwt.SigningMethodECDSA:
    return jwt.ParseECPublicKeyFromPEM(pem.EncodeToMemory(signingCert));
  case *jwt.SigningMethodRSA:
    return jwt.ParseRSAPublicKeyFromPEM(pem.EncodeToMemory(signingCert))
  default:
    return nil, fmt.Errorf("Unknown public key format")
  }

}

// ParseToken take a JWT and validates it against the CATokenValidator root certificate or fallback certificate
func (c *CATokenValidator) ParseToken(tokenString string) (*jwt.Token, error) {
  token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, c.Keyfunc)
  if err != nil {
    return nil, err
  }

  return token, nil
}
