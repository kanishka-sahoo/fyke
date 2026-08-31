package ops

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ksahoo/fyke/internal/config"
)

func TestDoctorValidatesGeneratedDeployment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	if e := Init(root); e != nil {
		t.Fatal(e)
	}
	c, e := config.Load(filepath.Join(root, "config.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	if e = Doctor(c); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(root, "pki", "sensor-ssh.key")
	if e = os.Chmod(key, 0644); e != nil {
		t.Fatal(e)
	}
	if e = Doctor(c); e == nil {
		t.Fatal("Doctor accepted a world-readable sensor private key")
	}
}

func TestInitCreatesCompatiblePublicHTTPSCertificate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "deployment")
	if e := Init(root); e != nil {
		t.Fatal(e)
	}
	certFile := filepath.Join(root, "pki", "public-https.crt")
	keyFile := filepath.Join(root, "pki", "public-https.key")
	if _, e := tls.LoadX509KeyPair(certFile, keyFile); e != nil {
		t.Fatalf("load public HTTPS key pair: %v", e)
	}
	b, e := os.ReadFile(certFile)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("public HTTPS certificate is not PEM")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if cert.PublicKeyAlgorithm != x509.RSA || cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("public HTTPS certificate uses %s with %s; want RSA with SHA256-RSA", cert.PublicKeyAlgorithm, cert.SignatureAlgorithm)
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() < 2048 {
		t.Fatal("public HTTPS certificate does not use a 2048-bit RSA key")
	}
	if e = cert.VerifyHostname("edge-gw-01"); e != nil {
		t.Fatalf("public HTTPS certificate hostname: %v", e)
	}
}
