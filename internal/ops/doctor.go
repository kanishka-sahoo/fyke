package ops

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ksahoo/fyke/internal/config"
	"github.com/ksahoo/fyke/internal/cryptokit"
	"github.com/ksahoo/fyke/internal/persona"
	"golang.org/x/crypto/ssh"
)

func Doctor(c config.Config) error {
	if _, e := persona.Load(c.PersonaFile); e != nil {
		return fmt.Errorf("persona: %w", e)
	}
	if _, e := cryptokit.Load(c.Controller.Identity); e != nil {
		return fmt.Errorf("controller age identity: %w", e)
	}
	if e := privateFile(c.Controller.Identity); e != nil {
		return fmt.Errorf("controller age identity: %w", e)
	}
	if e := validateTLS("controller", c.Controller.TLS, "controller", x509.ExtKeyUsageServerAuth); e != nil {
		return e
	}
	for id, sensor := range c.Sensors {
		if e := validateTLS("sensor "+id, sensor.TLS, "sensor."+id, x509.ExtKeyUsageClientAuth); e != nil {
			return e
		}
		if sensor.Protocol == "ssh" {
			hostKey := filepath.Join(filepath.Dir(sensor.TLS.Cert), "ssh_host_ed25519_key")
			b, e := os.ReadFile(hostKey)
			if e != nil {
				return fmt.Errorf("SSH host key: %w", e)
			}
			if _, e = ssh.ParsePrivateKey(b); e != nil {
				return fmt.Errorf("SSH host key: %w", e)
			}
			if e = privateFile(hostKey); e != nil {
				return fmt.Errorf("SSH host key: %w", e)
			}
		}
	}
	return nil
}

func validateTLS(label string, files config.TLS, dnsName string, usage x509.ExtKeyUsage) error {
	pair, e := tls.LoadX509KeyPair(files.Cert, files.Key)
	if e != nil {
		return fmt.Errorf("%s TLS key pair: %w", label, e)
	}
	if e = privateFile(files.Key); e != nil {
		return fmt.Errorf("%s TLS private key: %w", label, e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return fmt.Errorf("%s TLS certificate: %w", label, e)
	}
	caPEM, e := os.ReadFile(files.CA)
	if e != nil {
		return fmt.Errorf("%s CA: %w", label, e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("%s CA: no certificates found", label)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{DNSName: dnsName, Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); e != nil {
		return fmt.Errorf("%s TLS certificate verification: %w", label, e)
	}
	return nil
}

func privateFile(path string) error {
	info, e := os.Stat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s permissions are %04o; expected 0600 or stricter", path, info.Mode().Perm())
	}
	return nil
}
