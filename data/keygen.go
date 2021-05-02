package data

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"
)

const privateKeyFileType = "HOTSTUFF PRIVATE KEY"
const publicKeyFileType = "HOTSTUFF PUBLIC KEY"

// GeneratePrivateKey returns a new public/private key pair based on ECDSA.
func GeneratePrivateKey() (pk *ecdsa.PrivateKey, err error) {
	curve := elliptic.P256()
	pk, err = ecdsa.GenerateKey(curve, rand.Reader)
	return
}

// GeneratePrivateKeyBls returns a new public/private key pair based on BLS.
func GeneratePrivateKeyBls() bls.SecretKey {
	var pk bls.SecretKey
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	pk.SetByCSPRNG()
	return pk
}

// GenerateTLSCert generates a self-signed TLS certificate for the server that is valid for the given hosts.
// These keys should be used for testing purposes only.
func GenerateTLSCert(hosts []string, privateKey *ecdsa.PrivateKey) (cert []byte, err error) {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	caTmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: "HotStuff Self-Signed Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			caTmpl.IPAddresses = append(caTmpl.IPAddresses, ip)
		} else {
			caTmpl.DNSNames = append(caTmpl.DNSNames, h)
		}
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}

	return caPEM.Bytes(), nil
}

// WritePrivateKeyFile writes a private key to the specified file
func WritePrivateKeyFile(key *ecdsa.PrivateKey, filePath string) (err error) {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	marshalled, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}

	b := &pem.Block{
		Type:  privateKeyFileType,
		Bytes: marshalled,
	}

	err = pem.Encode(f, b)
	return
}

// WritePrivateKeyFile writes a private key to the specified file
func WritePrivateKeyFileBls(key *bls.SecretKey, filePath string) (err error) {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	marshalled := key.Serialize()

	b := &pem.Block{
		Type:  privateKeyFileType,
		Bytes: marshalled,
	}

	err = pem.Encode(f, b)
	return
}

// WritePublicKeyFile writes a public key to the specified file
func WritePublicKeyFile(key *ecdsa.PublicKey, filePath string) (err error) {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	marshalled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return
	}

	b := &pem.Block{
		Type:  publicKeyFileType,
		Bytes: marshalled,
	}

	err = pem.Encode(f, b)
	return
}

// WritePublicKeyFile writes a public key to the specified file
func WritePublicKeyFileBls(key *bls.PublicKey, filePath string) (err error) {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	marshalled := key.Serialize()
	if err != nil {
		return
	}

	b := &pem.Block{
		Type:  publicKeyFileType,
		Bytes: marshalled,
	}

	err = pem.Encode(f, b)
	return
}

// WriteCertFile returns
func WriteCertFile(cert []byte, file string) (err error) {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	_, err = f.Write(cert)
	return
}

// WritePopFile returns
func WritePopFile(pop *bls.Sign, file string) (err error) {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}

	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	marshalled := pop.Serialize()
	if err != nil {
		return
	}

	b := &pem.Block{
		Type:  publicKeyFileType,
		Bytes: marshalled,
	}

	err = pem.Encode(f, b)
	return
}

// ReadPrivateKeyFile reads a private key from the specified file
func ReadPrivateKeyFile(keyFile string) (key *ecdsa.PrivateKey, err error) {
	d, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(d)
	if b == nil {
		return nil, fmt.Errorf("Failed to decode key")
	}

	if b.Type != privateKeyFileType {
		return nil, fmt.Errorf("File type did not match")
	}

	key, err = x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse key: %w", err)
	}
	return
}

// ReadPrivateKeyFile reads a private key from the specified file
func ReadPrivateKeyFileBls(keyFile string, key *bls.SecretKey) (err error) {
	d, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	b, _ := pem.Decode(d)
	if b == nil {
		return fmt.Errorf("Failed to decode key")
	}

	if b.Type != privateKeyFileType {
		return fmt.Errorf("File type did not match")
	}

	key.Deserialize(b.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse key: %w", err)
	}
	return
}

// ReadPublicKeyFile reads a public key from the specified file
func ReadPublicKeyFile(keyFile string) (key *ecdsa.PublicKey, err error) {
	d, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(d)
	if b == nil {
		return nil, fmt.Errorf("Failed to decode key")
	}

	if b.Type != publicKeyFileType {
		return nil, fmt.Errorf("File type did not match")
	}

	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse key: %w", err)
	}

	key, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Key was of wrong type")
	}

	return
}

// ReadPublicKeyFile reads a public key from the specified file
func ReadPublicKeyFileBls(keyFile string, key *bls.PublicKey) (err error) {
	d, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	b, _ := pem.Decode(d)
	if b == nil {
		return fmt.Errorf("Failed to decode key")
	}

	if b.Type != publicKeyFileType {
		return fmt.Errorf("File type did not match")
	}

	key.Deserialize(b.Bytes)
	return
}

// ReadCertFile returns
func ReadCertFile(certFile string) (cert []byte, err error) {
	return ioutil.ReadFile(certFile)
}

// ReadPublicKeyFile reads a public key from the specified file
func ReadPopFileBls(popFile string, pop *bls.Sign) (err error) {
	d, err := ioutil.ReadFile(popFile)
	if err != nil {
		return err
	}

	b, _ := pem.Decode(d)
	if b == nil {
		return fmt.Errorf("Failed to decode key")
	}

	if b.Type != publicKeyFileType {
		return fmt.Errorf("File type did not match")
	}

	pop.Deserialize(b.Bytes)
	return
}
