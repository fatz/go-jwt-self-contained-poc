package test

import (
  "encoding/pem"
  "crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/opencoff/go-pki"
)

type TestCA struct {
  Passwd string
  Name string

  CA *pki.CA
  Intermediate *pki.CA
  LeafCert *pki.Cert

  rootCert []byte
  intermediateCert []byte

  leafCert []byte
  leafKey []byte
}

func NewTestCA(name string) *TestCA {
  testCA := new(TestCA)
  testCA.Name = name
  testCA.Passwd = name + ".password"

  pkiName := pkix.Name{
    Country: []string{"US"},
    Province: []string{"California"},
    Locality: []string{"San Francisco"},

    Organization: []string{"Example Org Inc."},
    OrganizationalUnit: []string{"Engineering"},

    CommonName: name,
  }

  cfg := &pki.Config{
    Passwd: testCA.Passwd,
    Subject: pkiName,
    Validity: 20 * 365 * 24 * time.Hour,
  }
  var err error
  // https://github.com/opencoff/go-pki/mocks_test.go is needed
  clk := newDummyClock()
  db := newRamStore(clk)
  testCA.CA, err = pki.NewWithStorage(cfg, db, true)
  if err != nil {
    return nil
  }

  intermediateName := pkiName
  intermediateName.CommonName = name+"-intermediate"
  intermediateCI := pki.CertInfo{
    Subject: intermediateName,
    Validity: 10 * 365 * 24 * time.Hour,
  }

  testCA.Intermediate, err = testCA.CA.NewIntermediateCA(&intermediateCI)
  if err != nil {
    return nil
  }

  leafName := pkiName
  leafName.CommonName = name+"-leaf"
  leafCI := pki.CertInfo{
    Subject: intermediateName,
    Validity: 1 * 365 * 24 * time.Hour,
  }

  testCA.LeafCert, err = testCA.Intermediate.NewServerCert(&leafCI, testCA.Passwd)
  testCA.leafCert, _ = testCA.LeafCert.PEM()
  if err != nil {
    return nil
  }
  leafKeyx509, err := x509.MarshalECPrivateKey(testCA.LeafCert.Key)
  if err != nil {
    return nil
  }

  testCA.leafKey  = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyx509})

  return testCA
}

func (c *TestCA) GetRootCert() []byte {
  if len(c.rootCert) <= 0 {
    c.rootCert = c.CA.PEM()
  }

  return c.rootCert

}

func (c *TestCA) GetIntermediateCert() []byte {
  if len(c.intermediateCert) <= 0 {
    c.intermediateCert = c.Intermediate.PEM()
  }

  return c.intermediateCert
}

func (c *TestCA) GetLeafCert() []byte {
  return c.leafCert
}

func (c *TestCA) GetLeafKey() ([]byte, string) {

  return c.leafKey, c.Passwd
}

func (c *TestCA) GetLeafChain() ([]byte) {
  chain := make([]byte, 0)
  nl := []byte("\n")
  chain = append(chain, c.GetLeafCert()...)
  chain = append(chain, nl...)
  chain = append(chain, c.GetIntermediateCert()...)
  chain = append(chain, nl...)
  chain = append(chain, c.GetRootCert()...)

  return chain
}
