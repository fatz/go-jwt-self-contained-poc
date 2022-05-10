package test
// https://github.com/opencoff/go-pki/blob/d21a6e876f6db8a071c381a731f756943e93080d/mocks_test.go#L250
// mocks_test.go - mock storage & time provider

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/opencoff/go-pki"
)

type clock interface {
	Now() time.Time
}


type ram struct {
	sync.Mutex
	root *pki.Cert

	serial  *big.Int
	clients map[string]*pki.Cert
	servers map[string]*pki.Cert
	ica     map[string]*pki.Cert

	revoked map[string]pki.Revoked

	clock clock
}

func newRamStore(clk clock) *ram {
	r := &ram{
		serial:  big.NewInt(0xdeadbeef),
		clock:   clk,
		clients: make(map[string]*pki.Cert),
		servers: make(map[string]*pki.Cert),
		ica:     make(map[string]*pki.Cert),
		revoked: make(map[string]pki.Revoked),
	}
	return r
}

// -- Storage interface implementation --

func (r *ram) Rekey(newpw string) error {
	return nil
}

func (r *ram) Close() error {
	return nil
}

func (r *ram) GetRootCA() (*pki.Cert, error) {
	r.Lock()
	defer r.Unlock()
	return r.root, nil
}

func (r *ram) StoreRootCA(c *pki.Cert) error {
	r.Lock()
	defer r.Unlock()

	r.root = c
	return nil
}

func (r *ram) GetSerial() *big.Int {
	r.Lock()
	defer r.Unlock()
	return r.serial
}

func (r *ram) NewSerial() (*big.Int, error) {
	r.Lock()
	defer r.Unlock()
	z := big.NewInt(1)
	r.serial.Add(r.serial, z)
	z.Set(r.serial)
	return z, nil
}

func (r *ram) GetICA(nm string) (*pki.Cert, error) {
	r.Lock()
	defer r.Unlock()
	c, ok := r.ica[nm]
	if !ok {
		return nil, pki.ErrNotFound
	}
	return c, nil
}

func (r *ram) GetClientCert(nm string, pw string) (*pki.Cert, error) {
	r.Lock()
	defer r.Unlock()
	c, ok := r.clients[nm]
	if !ok {
		return nil, pki.ErrNotFound
	}
	return c, nil
}

func (r *ram) GetServerCert(nm string, pw string) (*pki.Cert, error) {
	r.Lock()
	defer r.Unlock()
	c, ok := r.servers[nm]
	if !ok {
		return nil, pki.ErrNotFound
	}
	return c, nil
}

func (r *ram) StoreICA(c *pki.Cert) error {
	r.Lock()
	defer r.Unlock()
	r.ica[c.Subject.CommonName] = c
	return nil
}

func (r *ram) StoreClientCert(c *pki.Cert, pw string) error {
	r.Lock()
	defer r.Unlock()
	r.clients[c.Subject.CommonName] = c
	return nil
}

func (r *ram) StoreServerCert(c *pki.Cert, pw string) error {
	r.Lock()
	defer r.Unlock()
	r.servers[c.Subject.CommonName] = c
	return nil
}

func (r *ram) DeleteICA(cn string) error {
	r.Lock()
	defer r.Unlock()
	c, ok := r.ica[cn]
	if !ok {
		return pki.ErrNotFound
	}

	key := fmt.Sprintf("%x", c.SubjectKeyId)
	r.revoked[key] = pki.Revoked{c, r.clock.Now()}
	delete(r.ica, cn)
	return nil
}

func (r *ram) DeleteClientCert(cn string) error {
	r.Lock()
	defer r.Unlock()
	c, ok := r.clients[cn]
	if !ok {
		return pki.ErrNotFound
	}

	key := fmt.Sprintf("%x", c.SubjectKeyId)
	r.revoked[key] = pki.Revoked{c, r.clock.Now()}
	delete(r.clients, cn)
	return nil
}

func (r *ram) DeleteServerCert(cn string) error {
	r.Lock()
	defer r.Unlock()
	c, ok := r.servers[cn]
	if !ok {
		return pki.ErrNotFound
	}

	key := fmt.Sprintf("%x", c.SubjectKeyId)
	r.revoked[key] = pki.Revoked{c, r.clock.Now()}
	delete(r.servers, cn)
	return nil
}

func (r *ram) FindRevoked(skid []byte) (time.Time, *pki.Cert, error) {
	r.Lock()
	defer r.Unlock()

	key := fmt.Sprintf("%x", skid)
	rv, ok := r.revoked[key]
	if !ok {
		return time.Time{}, nil, pki.ErrNotFound
	}
	return rv.When, rv.Cert, nil
}

func (r *ram) MapICA(fp func(*pki.Cert) error) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.ica {
		fp(c)
	}
	return nil
}

func (r *ram) MapClientCerts(fp func(*pki.Cert) error) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.clients {
		fp(c)
	}
	return nil
}

func (r *ram) MapServerCerts(fp func(*pki.Cert) error) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.servers {
		fp(c)
	}
	return nil
}

func (r *ram) MapRevoked(fp func(time.Time, *pki.Cert)) error {
	r.Lock()
	defer r.Unlock()
	for _, c := range r.revoked {
		fp(c.When, c.Cert)
	}
	return nil
}

// XXX Fill this
func (r *ram) ExportJSON() (string, error) {
	return "", nil
}

func (r *ram) dump() {
	root := r.root
	fmt.Printf("root-CA: %x %x %s\n", root.SubjectKeyId, root.SerialNumber, root.NotAfter)
	prmap("servers", r.servers)
	prmap("clients", r.clients)
	prmap("ica", r.ica)
	prmap1("revoked", r.revoked)
}

func prmap(pref string, m map[string]*pki.Cert) {
	fmt.Printf("%s\n", pref)
	for k, v := range m {
		fmt.Printf("   %s: %x %x %s\n", k, v.SubjectKeyId, v.SerialNumber, v.NotAfter)
	}
}

func prmap1(pref string, m map[string]pki.Revoked) {
	fmt.Printf("%s\n", pref)
	for k, v := range m {
		fmt.Printf("   %s: at %s %s [%x]\n", k, v.When, v.NotAfter, v.SerialNumber)
	}
}

type dummyClock struct {
	t int64
}

func newDummyClock() *dummyClock {
	t := &dummyClock{
		t: time.Now().UTC().Unix(),
	}
	return t
}

func (d *dummyClock) Now() time.Time {
	z := time.Unix(d.t, 0).UTC()
	return z
}

func (d *dummyClock) advanceDay(n int) {
	d.t += int64(n) * 24 * 60 * 60
}

func (d *dummyClock) advanceSec(n int) {
	d.t += int64(n)
}
