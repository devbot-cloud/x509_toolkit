// Description: x509 toolkit
package x509_toolkit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

type CertificateInfo struct {
	CommonName         string
	SubjectAltNames    []string
	NotBefore          time.Time
	NotAfter           time.Time
	SerialNumber       *big.Int
	SignatureAlgorithm string
}

// Function to generate a new RSA Key Accepts Key Length (2048,4096)
func GenerateRSAKey(keyLen ...int) (*rsa.PrivateKey, error) {
	// Set the default key length to 4096
	if len(keyLen) == 0 {
		keyLen = []int{4096}
	}
	// Generate a new RSA private key
	key, err := rsa.GenerateKey(rand.Reader, keyLen[0])
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SaveKeyToFile(key *rsa.PrivateKey, filename string) error {
	// Open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode the key in PEM format and write it to the file
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	err = pem.Encode(file, keyPEM)
	if err != nil {
		return err
	}
	return nil
}

func SavePEMToFile(pemBytes []byte, filename string) error {
	// Open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the PEM-encoded certificate to the file
	_, err = file.Write(pemBytes)
	if err != nil {
		return err
	}

	return nil
}

// This function Generates a new Root CA certificate and returns it in PEM format Accepts the Root CA key
func GenerateRootCACertificate(key *rsa.PrivateKey) ([]byte, error) {
	// Set the certificate subject information
	subject := pkix.Name{
		CommonName:         "X509-Toolkit Root CA",
		Organization:       []string{"X509-Toolkit"},
		Country:            []string{"US"},
		OrganizationalUnit: []string{"Node-U"},
	}

	// Set the certificate validity period
	notBefore := time.Now()

	// Setting the expiration date to 2 Years for the CA certificate
	notAfter := notBefore.AddDate(2, 0, 0)

	// Generate a random serial number for the certificate
	// We have no way of keeping count of the amount of certificates we've signed so far...
	// so we'll just use a random number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(999999999))
	if err != nil {
		return nil, err
	}

	// Create the x509 certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		// Set the CA flag to true
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// Generate the x509 certificate using the template and root CA key
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Encode the certificate in PEM format
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return pemBytes, nil
}

func SignClientCertificate(caCert []byte, caKey *rsa.PrivateKey, subject pkix.Name, dnsNames []string, ips []net.IP) ([]byte, error) {
	// Decode the root CA certificate from PEM format
	caBlock, _ := pem.Decode(caCert)
	if caBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Generate a new RSA key for the client certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Set the client certificate validity period
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)

	// Create a new x509 certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(999999999),
		Subject:               subject,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	// Generate the DER-encoded certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	// Encode the certificate in PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return certPEM, nil
}

//-------------------- x509_toolkit Parser --------------------

// Function to parse a PEM-encoded certificate and return the certificate information
func ParsePEMCertificate(pemBytes []byte) (*CertificateInfo, error) {
	// Decode the PEM-encoded certificate
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	// Parse the x509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Extract the Common Name from the Subject field of the certificate
	commonName := cert.Subject.CommonName

	// Extract the Subject Alternative Names from the certificate
	var subjectAltNames []string
	for _, dnsName := range cert.DNSNames {
		subjectAltNames = append(subjectAltNames, dnsName)
	}
	for _, ipAddress := range cert.IPAddresses {
		subjectAltNames = append(subjectAltNames, ipAddress.String())
	}

	return &CertificateInfo{
		CommonName:         commonName,
		SubjectAltNames:    subjectAltNames,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SerialNumber:       cert.SerialNumber,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}, nil
}
