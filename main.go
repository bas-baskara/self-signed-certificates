package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"os"
	"time"
)

const (
	certPath = "certs/server.crt"
	keyPath  = "certs/server.key"
)

func generateCertificates() {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// generate new certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Ayo Sekarang Bekarya"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 365), //valid for 365 days
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// generate new certificates
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// write new certificates to file
	certOut, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("Failed to open certificate file for writing: %v", err)
	}

	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes}); err != nil {
		log.Fatalf("Failed to write certificate to file: %v", err)
	}

	// write new private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		log.Fatalf("Failed to open private key file for writing: %v", err)
	}

	defer keyOut.Close()

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		log.Fatalf("Failed to write private key to file: %v", err)
	}
}

func checkAndOrCreateCertificates() {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		// create if not exists

		generateCertificates()

	} else {
		// check validity of certificates if exists
		// open cert
		certFile, err := os.Open(certPath)
		if err != nil {
			log.Fatalf("Failed to open certificate file: %v", err)
		}

		defer certFile.Close()

		// read cert
		certPEMBlock, err := io.ReadAll(certFile)
		if err != nil {
			log.Fatalf("Failed to read certificate file: %v", err)
		}

		// Decode PEM Encoded certificate
		block, _ := pem.Decode(certPEMBlock)
		if block == nil || block.Type != "CERTIFICATE" {
			log.Fatalf("Failed to decode PEM block containing certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate file: %v", err)
		}

		// check if certificate is expiring within 30days
		if time.Until(cert.NotAfter) <= 30*24*time.Hour {
			// renew if near 30 days expiry
			// generate private key
			generateCertificates()
		}
	}
}

func main() {
	for {
		checkAndOrCreateCertificates()
		// sllep until nextMonth
		nextMonth := time.Now().AddDate(0, 1, 0)
		nextMonth = time.Date(nextMonth.Year(), nextMonth.Month(), nextMonth.Day(), 0, 0, 0, 0, nextMonth.Location())
		time.Sleep(time.Until(nextMonth))
	}

}
