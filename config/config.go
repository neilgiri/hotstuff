package config

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// ReplicaID is the id of a replica
type ReplicaID uint32

// ReplicaInfo holds information about a replica
type ReplicaInfo struct {
	ID      ReplicaID
	Address string
	PubKey  *ecdsa.PublicKey
}

// ReplicaInfoBls holds information about a replica
type ReplicaInfoBls struct {
	ID             ReplicaID
	Address        string
	PubKey         *ecdsa.PublicKey
	PubKeyBLS      *bls.PublicKey
	ProofNCPubKeys []bls.PublicKey
}

// ReplicaConfig holds information needed by a replica
type ReplicaConfig struct {
	ID         ReplicaID
	PrivateKey *ecdsa.PrivateKey
	Cert       *tls.Certificate // Own certificate
	CertPool   *x509.CertPool   // Other replicas's certificates
	Replicas   map[ReplicaID]*ReplicaInfo
	QuorumSize int
	BatchSize  int
}

// ReplicaConfigBls holds information needed by a replica
type ReplicaConfigBls struct {
	ID              ReplicaID
	PrivateKey      *bls.SecretKey
	PrivateKeyCert  *ecdsa.PrivateKey
	Cert            *tls.Certificate // Own certificate
	CertPool        *x509.CertPool   // Other replicas's certificates
	Replicas        map[ReplicaID]*ReplicaInfoBls
	QuorumSize      int
	BatchSize       int
	N               int
	ProofNCPrivKeys []bls.SecretKey
}

// ReplicaConfigBls holds information needed by a replica
type ReplicaConfigFastWendy struct {
	ID              ReplicaID
	PrivateKey      *bls.SecretKey
	PrivateKeyCert  *ecdsa.PrivateKey
	Cert            *tls.Certificate // Own certificate
	CertPool        *x509.CertPool   // Other replicas's certificates
	Replicas        map[ReplicaID]*ReplicaInfoBls
	QuorumSize      int
	FastQuorumSize  int
	BatchSize       int
	N               int
	ProofNCPrivKeys []bls.SecretKey
}

// NewConfig returns a new ReplicaConfig instance
func NewConfig(id ReplicaID, privateKey *ecdsa.PrivateKey, cert *tls.Certificate) *ReplicaConfig {
	return &ReplicaConfig{
		ID:         id,
		PrivateKey: privateKey,
		Cert:       cert,
		CertPool:   x509.NewCertPool(),
		Replicas:   make(map[ReplicaID]*ReplicaInfo),
		BatchSize:  1,
	}
}

// NewConfigBls returns a new ReplicaConfig instance
func NewConfigBls(id ReplicaID, privateKey *bls.SecretKey, cert *tls.Certificate, privateKeyCert *ecdsa.PrivateKey) *ReplicaConfigBls {
	return &ReplicaConfigBls{
		ID:             id,
		PrivateKey:     privateKey,
		PrivateKeyCert: privateKeyCert,
		Cert:           cert,
		CertPool:       x509.NewCertPool(),
		Replicas:       make(map[ReplicaID]*ReplicaInfoBls),
		BatchSize:      1,
		N:              1,
	}
}
