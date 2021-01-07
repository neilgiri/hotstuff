package data

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/internal/logging"
)

var logger *log.Logger

func init() {
	logger = logging.GetLogger()
}

// SignatureCache keeps a cache of verified signatures in order to speed up verification
type SignatureCache struct {
	conf               *config.ReplicaConfig
	verifiedSignatures map[string]bool
	cache              list.List
	mut                sync.Mutex
}

// SignatureCache keeps a cache of verified signatures in order to speed up verification
type SignatureCacheBls struct {
	conf               *config.ReplicaConfigBls
	verifiedSignatures map[string]bool
	cache              list.List
	mut                sync.Mutex
}

// NewSignatureCache returns a new instance of SignatureVerifier
func NewSignatureCache(conf *config.ReplicaConfig) *SignatureCache {
	return &SignatureCache{
		conf:               conf,
		verifiedSignatures: make(map[string]bool),
	}
}

// NewSignatureCache returns a new instance of SignatureVerifier
func NewSignatureCacheBls(conf *config.ReplicaConfigBls) *SignatureCacheBls {
	return &SignatureCacheBls{
		conf:               conf,
		verifiedSignatures: make(map[string]bool),
	}
}

// CreatePartialCert creates a partial cert from a block.
func (s *SignatureCache) CreatePartialCert(id config.ReplicaID, privKey *ecdsa.PrivateKey, block *Block) (*PartialCert, error) {
	hash := block.Hash()
	R, S, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}
	sig := PartialSig{id, R, S}
	k := string(sig.ToBytes())
	s.mut.Lock()
	s.verifiedSignatures[k] = true
	s.cache.PushBack(k)
	s.mut.Unlock()
	return &PartialCert{sig, hash}, nil
}

// CreatePartialCertBls creates a partial cert from a block.
func (s *SignatureCacheBls) CreatePartialCertBls(id config.ReplicaID, privKey *bls.SecretKey, block *BlockBls) (*PartialCertBls, error) {
	hash := block.Hash()
	S := privKey.SignByte(hash[:])

	sig := PartialSigBls{id, S}
	k := string(sig.ToBytes())
	s.mut.Lock()
	s.verifiedSignatures[k] = true
	s.cache.PushBack(k)
	s.mut.Unlock()
	return &PartialCertBls{sig, hash}, nil
}

// VerifySignature verifies a partial signature
func (s *SignatureCache) VerifySignature(sig PartialSig, hash BlockHash) bool {
	k := string(sig.ToBytes())

	s.mut.Lock()
	if valid, ok := s.verifiedSignatures[k]; ok {
		s.mut.Unlock()
		return valid
	}
	s.mut.Unlock()

	info, ok := s.conf.Replicas[sig.ID]
	if !ok {
		return false
	}
	valid := ecdsa.Verify(info.PubKey, hash[:], sig.R, sig.S)

	s.mut.Lock()
	s.cache.PushBack(k)
	s.verifiedSignatures[k] = valid
	s.mut.Unlock()

	return valid
}

// VerifySignature verifies a partial signature
func (s *SignatureCacheBls) VerifySignatureBls(sig PartialSigBls, hash BlockHash) bool {
	k := string(sig.ToBytes())

	s.mut.Lock()
	if valid, ok := s.verifiedSignatures[k]; ok {
		s.mut.Unlock()
		return valid
	}
	s.mut.Unlock()

	info, ok := s.conf.Replicas[sig.ID]
	if !ok {
		return false
	}
	valid := sig.S.VerifyByte(info.PubKey, hash[:])

	s.mut.Lock()
	s.cache.PushBack(k)
	s.verifiedSignatures[k] = valid
	s.mut.Unlock()

	return valid
}

// VerifyQuorumCert verifies a quorum certificate
func (s *SignatureCache) VerifyQuorumCert(qc *QuorumCert) bool {
	if len(qc.Sigs) < s.conf.QuorumSize {
		return false
	}
	var wg sync.WaitGroup
	var numVerified uint64 = 0
	for _, psig := range qc.Sigs {
		wg.Add(1)
		go func(psig PartialSig) {
			if s.VerifySignature(psig, qc.BlockHash) {
				atomic.AddUint64(&numVerified, 1)
			}
			wg.Done()
		}(psig)
	}
	wg.Wait()
	return numVerified >= uint64(s.conf.QuorumSize)
}

// VerifyQuorumCertBls verifies a quorum certificate
func (s *SignatureCacheBls) VerifyQuorumCertBls(qc *QuorumCertBls) bool {
	return qc.Authenticator.FastAggregateVerify(qc.PublicKeys, qc.BlockHash[:])
}

// EvictOld reduces the size of the cache by removing the oldest cached results
func (s *SignatureCache) EvictOld(size int) {
	s.mut.Lock()
	for length := s.cache.Len(); length > size; length-- {
		el := s.cache.Front()
		k := s.cache.Remove(el).(string)
		delete(s.verifiedSignatures, k)
	}
	s.mut.Unlock()
}

// EvictOld reduces the size of the cache by removing the oldest cached results
func (s *SignatureCacheBls) EvictOld(size int) {
	s.mut.Lock()
	for length := s.cache.Len(); length > size; length-- {
		el := s.cache.Front()
		k := s.cache.Remove(el).(string)
		delete(s.verifiedSignatures, k)
	}
	s.mut.Unlock()
}

// PartialSig is a single replica's signature of a block.
type PartialSig struct {
	ID   config.ReplicaID
	R, S *big.Int
}

type PartialSigBls struct {
	ID config.ReplicaID
	S  *bls.Sign
}

func (psig PartialSig) ToBytes() []byte {
	r := psig.R.Bytes()
	s := psig.S.Bytes()
	b := make([]byte, 4, 4+len(r)+len(s))
	binary.LittleEndian.PutUint32(b, uint32(psig.ID))
	b = append(b, r...)
	b = append(b, s...)
	return b
}

func (psig PartialSigBls) ToBytes() []byte {
	s := psig.S.Serialize()
	b := make([]byte, 4, 4+len(s))
	binary.LittleEndian.PutUint32(b, uint32(psig.ID))
	b = append(b, s...)
	return b
}

// PartialCert is a single replica's certificate for a block.
type PartialCert struct {
	Sig       PartialSig
	BlockHash BlockHash
}

// PartialCertBls is a single replica's certificate for a block.
type PartialCertBls struct {
	Sig       PartialSigBls
	BlockHash BlockHash
}

// QuorumCert is a certificate for a block from a quorum of replicas.
type QuorumCert struct {
	Sigs      map[config.ReplicaID]PartialSig
	BlockHash BlockHash
}

// QuorumCertBls is a certificate for a block from a quorum of replicas.
type QuorumCertBls struct {
	Authenticator bls.Sign
	BlockHash     BlockHash
	PublicKeys    []bls.PublicKey
}

type QuorumCertificateBls struct {
	Sigs       map[config.ReplicaID]bls.Sign
	BlockHash  BlockHash
	PublicKeys []bls.PublicKey
}

func (qc *QuorumCert) ToBytes() []byte {
	b := make([]byte, 0, 32)
	b = append(b, qc.BlockHash[:]...)
	psigs := make([]PartialSig, 0, len(qc.Sigs))
	for _, v := range qc.Sigs {
		i := sort.Search(len(psigs), func(j int) bool {
			return v.ID < psigs[j].ID
		})
		psigs = append(psigs, PartialSig{})
		copy(psigs[i+1:], psigs[i:])
		psigs[i] = v
	}
	for i := range psigs {
		b = append(b, psigs[i].ToBytes()...)
	}
	return b
}

func (qc *QuorumCertBls) ToBytes() []byte {
	b := make([]byte, 0, 32)
	b = append(b, qc.BlockHash[:]...)
	b = append(b, qc.Authenticator.Serialize()...)
	return b
}

func (qc *QuorumCert) String() string {
	return fmt.Sprintf("QuorumCert{Sigs: %d, Hash: %.8s}", len(qc.Sigs), qc.BlockHash)
}

func (qc *QuorumCertBls) String() string {
	return fmt.Sprintf("QuorumCert{Sigs: %s, Hash: %.8s}", qc.Authenticator.GetHexString(), qc.BlockHash)
}

// AddPartial adds the partial signature to the quorum cert.
func (qc *QuorumCert) AddPartial(cert *PartialCert) error {
	// dont add a cert if there is already a signature from the same replica
	if _, exists := qc.Sigs[cert.Sig.ID]; exists {
		return fmt.Errorf("Attempt to add partial cert from same replica twice")
	}

	if !bytes.Equal(qc.BlockHash[:], cert.BlockHash[:]) {
		return fmt.Errorf("Partial cert hash does not match quorum cert")
	}

	qc.Sigs[cert.Sig.ID] = cert.Sig

	return nil
}

// AddPartial adds the partial signature to the quorum cert.
func (qc *QuorumCertificateBls) AddPartialBls(cert *PartialCertBls) error {
	// dont add a cert if there is already a signature from the same replica

	if _, exists := qc.Sigs[cert.Sig.ID]; exists {
		return fmt.Errorf("Attempt to add partial cert from same replica twice")
	}

	if !bytes.Equal(qc.BlockHash[:], cert.BlockHash[:]) {
		return fmt.Errorf("Partial cert hash does not match quorum cert")
	}

	qc.Sigs[cert.Sig.ID] = *cert.Sig.S

	return nil
}

// CreatePartialCert creates a partial cert from a block.
func CreatePartialCert(id config.ReplicaID, privKey *ecdsa.PrivateKey, block *Block) (*PartialCert, error) {
	hash := block.Hash()
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}
	sig := PartialSig{id, r, s}
	return &PartialCert{sig, hash}, nil
}

// CreatePartialCert creates a partial cert from a block.
func CreatePartialCertBls(id config.ReplicaID, privKey *bls.SecretKey, block *Block) (*PartialCertBls, error) {
	hash := block.Hash()
	s := privKey.SignByte(hash[:])
	sig := PartialSigBls{id, s}
	return &PartialCertBls{sig, hash}, nil
}

// VerifyPartialCert will verify a PartialCert from a public key stored in ReplicaConfig
func VerifyPartialCert(conf *config.ReplicaConfig, cert *PartialCert) bool {
	info, ok := conf.Replicas[cert.Sig.ID]
	if !ok {
		logger.Printf("VerifyPartialSig: got signature from replica whose ID (%d) was not in config.", cert.Sig.ID)
		return false
	}
	return ecdsa.Verify(info.PubKey, cert.BlockHash[:], cert.Sig.R, cert.Sig.S)
}

// VerifyPartialCert will verify a PartialCert from a public key stored in ReplicaConfig
func VerifyPartialCertBls(conf *config.ReplicaConfigBls, cert *PartialCertBls) bool {
	info, ok := conf.Replicas[cert.Sig.ID]

	if !ok {
		logger.Printf("VerifyPartialSig: got signature from replica whose ID (%d) was not in config.", cert.Sig.ID)
		return false
	}

	return cert.Sig.S.VerifyByte(info.PubKey, cert.BlockHash[:])
}

// CreateQuorumCert creates an empty quorum certificate for a given block
func CreateQuorumCert(block *Block) *QuorumCert {
	return &QuorumCert{BlockHash: block.Hash(), Sigs: make(map[config.ReplicaID]PartialSig)}
}

// CreateQuorumCertBls creates an empty quorum certificate for a given block
func CreateQuorumCertBls(blockHash BlockHash, cert *QuorumCertificateBls) *QuorumCertBls {
	values := make([]bls.Sign, 0, len(cert.Sigs))

	for _, v := range cert.Sigs {
		values = append(values, v)
	}

	var aggSig bls.Sign

	aggSig.Aggregate(values)
	return &QuorumCertBls{BlockHash: blockHash, Authenticator: aggSig, PublicKeys: cert.PublicKeys}
}

// CreateQuorumCertBls creates an empty quorum certificate for a given block
func CreateQuorumCertificateBls(block *BlockBls, N int) *QuorumCertificateBls {
	return &QuorumCertificateBls{Sigs: make(map[config.ReplicaID]bls.Sign), BlockHash: block.Hash(), PublicKeys: make([]bls.PublicKey, 30, 30)}
}

// CreateQuorumCertGenesis creates an empty quorum certificate for a given block
func CreateQuorumCertGenisis(blockHash BlockHash, configuration *config.ReplicaConfigBls) *QuorumCertBls {
	var aggSig bls.Sign
	return &QuorumCertBls{BlockHash: blockHash, Authenticator: aggSig, PublicKeys: make([]bls.PublicKey, configuration.N)}
}

// VerifyQuorumCert will verify a QuorumCert from public keys stored in ReplicaConfig
func VerifyQuorumCert(conf *config.ReplicaConfig, qc *QuorumCert) bool {
	if len(qc.Sigs) < conf.QuorumSize {
		return false
	}
	var wg sync.WaitGroup
	var numVerified uint64 = 0
	for _, psig := range qc.Sigs {
		info, ok := conf.Replicas[psig.ID]
		if !ok {
			logger.Printf("VerifyQuorumSig: got signature from replica whose ID (%d) was not in config.", psig.ID)
		}
		wg.Add(1)
		go func(psig PartialSig) {
			if ecdsa.Verify(info.PubKey, qc.BlockHash[:], psig.R, psig.S) {
				atomic.AddUint64(&numVerified, 1)
			}
			wg.Done()
		}(psig)
	}
	wg.Wait()
	return numVerified >= uint64(conf.QuorumSize)
}

// VerifyQuorumCert will verify a QuorumCert from public keys stored in ReplicaConfig
func VerifyQuorumCertBls(conf *config.ReplicaConfigBls, qc *QuorumCertBls) bool {
	return qc.Authenticator.FastAggregateVerify(qc.PublicKeys, qc.BlockHash[:])
}
