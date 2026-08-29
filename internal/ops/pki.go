package ops

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type authority struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newCA() (authority, []byte, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return authority{}, nil, e
	}
	n, e := serial()
	if e != nil {
		return authority{}, nil, e
	}
	cert := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "Fyke local sensor CA", Organization: []string{"Fyke fictional infrastructure"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		return authority{}, nil, e
	}
	cert, _ = x509.ParseCertificate(der)
	return authority{cert: cert, key: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
func (a authority) issue(dir, name string, dns []string, ips []net.IP, client bool) error {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	n, e := serial()
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name, Organization: []string{"Fyke fictional infrastructure"}}, DNSNames: dns, IPAddresses: ips, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	der, e := x509.CreateCertificate(rand.Reader, cert, a.cert, pub, a.key)
	if e != nil {
		return e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600)
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
