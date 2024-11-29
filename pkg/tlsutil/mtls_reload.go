package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
)

type TLSReloader struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	caPool   *x509.CertPool
	certPath string
	keyPath  string
	caPath   string
}

func NewTLSReloader(certPath, keyPath, caPath string) (*TLSReloader, error) {
	reloader := &TLSReloader{
		certPath: certPath,
		keyPath:  keyPath,
		caPath:   caPath,
	}
	// reload works for a first time load as well
	if err := reloader.Reload(); err != nil {
		return nil, err
	}
	return reloader, nil
}

func (t *TLSReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(t.certPath, t.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load server key pair: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPEM, err := os.ReadFile(t.caPath)
	if err != nil {
		return fmt.Errorf("failed to read client CA cert: %v", err)
	}
	if ok := caCertPool.AppendCertsFromPEM(caCertPEM); !ok {
		return fmt.Errorf("failed to parse client CA cert")
	}
	t.mu.Lock()
	t.cert = &cert
	t.caPool = caCertPool
	t.mu.Unlock()
	return nil
}

func (t *TLSReloader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.RLock()
	cert := t.cert
	t.mu.RUnlock()
	return cert, nil
}

func (t *TLSReloader) GetConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	t.mu.RLock()
	cert := t.cert
	caPool := t.caPool
	t.mu.RUnlock()
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}, nil
}
