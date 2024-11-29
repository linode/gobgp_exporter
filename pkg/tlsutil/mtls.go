package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func GetmTLSConfig(caChain string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caChain)
	if err != nil {
		return nil, fmt.Errorf("error reading server certificate: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}
