package ops

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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

const (
	PublicHTTPSCert = "public-https.crt"
	PublicHTTPSKey  = "public-https.key"
)

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

func PublicHTTPSPaths(dir string) (string, string) {
	return filepath.Join(dir, PublicHTTPSCert), filepath.Join(dir, PublicHTTPSKey)
}

func EnsurePublicHTTPSCertificate(dir, hostname string) error {
	certFile, keyFile := PublicHTTPSPaths(dir)
	certExists, e := regularFileExists(certFile)
	if e != nil {
		return e
	}
	keyExists, e := regularFileExists(keyFile)
	if e != nil {
		return e
	}
	if certExists != keyExists {
		return fmt.Errorf("public HTTPS certificate and key must both exist or both be absent")
	}
	if certExists {
		return validatePublicHTTPSCertificate(certFile, keyFile, hostname)
	}
	if hostname == "" {
		return fmt.Errorf("public HTTPS certificate hostname is required")
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	n, e := serial()
	if e != nil {
		return e
	}
	cert := &x509.Certificate{
		SerialNumber: n,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	if e = writePair(dir, certFile, keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); e != nil {
		return e
	}
	return validatePublicHTTPSCertificate(certFile, keyFile, hostname)
}

func regularFileExists(path string) (bool, error) {
	info, e := os.Stat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	return true, nil
}

func validatePublicHTTPSCertificate(certFile, keyFile, hostname string) error {
	pair, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return fmt.Errorf("load public HTTPS certificate: %w", e)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("public HTTPS certificate is empty")
	}
	if e = privateFile(keyFile); e != nil {
		return fmt.Errorf("public HTTPS private key: %w", e)
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return fmt.Errorf("parse public HTTPS certificate: %w", e)
	}
	if cert.PublicKeyAlgorithm != x509.RSA || cert.SignatureAlgorithm != x509.SHA256WithRSA {
		return fmt.Errorf("public HTTPS certificate must use RSA with SHA256-RSA")
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() < 2048 {
		return fmt.Errorf("public HTTPS certificate must use an RSA key of at least 2048 bits")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return fmt.Errorf("public HTTPS certificate is not valid at the current time")
	}
	if e = cert.VerifyHostname(hostname); e != nil {
		return fmt.Errorf("public HTTPS certificate hostname: %w", e)
	}
	return nil
}

func writePair(dir, certFile, keyFile string, certPEM, keyPEM []byte) (e error) {
	certTemp, e := os.CreateTemp(dir, ".public-https-cert-*")
	if e != nil {
		return e
	}
	certTempName := certTemp.Name()
	defer os.Remove(certTempName)
	keyTemp, e := os.CreateTemp(dir, ".public-https-key-*")
	if e != nil {
		certTemp.Close()
		return e
	}
	keyTempName := keyTemp.Name()
	defer os.Remove(keyTempName)
	defer func() {
		certTemp.Close()
		keyTemp.Close()
	}()
	if e = certTemp.Chmod(0644); e == nil {
		_, e = certTemp.Write(certPEM)
	}
	if closeErr := certTemp.Close(); e == nil {
		e = closeErr
	}
	if e == nil {
		e = keyTemp.Chmod(0600)
	}
	if e == nil {
		_, e = keyTemp.Write(keyPEM)
	}
	if closeErr := keyTemp.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(keyTempName, keyFile); e != nil {
		return e
	}
	if e = os.Rename(certTempName, certFile); e != nil {
		os.Remove(keyFile)
		return e
	}
	return nil
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
