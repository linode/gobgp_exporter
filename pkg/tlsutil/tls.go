package tlsutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadCertificatePEM(filePath string) (*x509.Certificate, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	rest := content
	var block *pem.Block
	var cert *x509.Certificate
	for len(rest) > 0 {
		block, rest = pem.Decode(content)
		if block == nil {
			// no PEM data found, rest will not have been modified
			break
		}
		content = rest
		switch block.Type {
		case "CERTIFICATE":
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			return cert, err
		default:
			// not the PEM block we're looking for
			continue
		}
	}
	return nil, errors.New("no certificate PEM block found")
}

func LoadKeyPEM(filePath string) (crypto.PrivateKey, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	rest := content
	var block *pem.Block
	var key crypto.PrivateKey
	for len(rest) > 0 {
		block, rest = pem.Decode(content)
		if block == nil {
			// no PEM data found, rest will not have been modified
			break
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, err
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, err
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, err
		default:
			// not the PEM block we're looking for
			continue
		}
	}
	return nil, errors.New("no private key PEM block found")
}
