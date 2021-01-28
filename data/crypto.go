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

// SignatureCacheBls keeps a cache of verified signatures in order to speed up verification
type SignatureCacheBls struct {
	conf               *config.ReplicaConfigBls
	verifiedSignatures map[string]bool
	cache              list.List
	mut                sync.Mutex
}

// SignatureCacheFastWendy keeps a cache of verified signatures in order to speed up verification
type SignatureCacheFastWendy struct {
	conf               *config.ReplicaConfigFastWendy
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

// NewSignatureCacheBls returns a new instance of SignatureVerifier
func NewSignatureCacheBls(conf *config.ReplicaConfigBls) *SignatureCacheBls {
	return &SignatureCacheBls{
		conf:               conf,
		verifiedSignatures: make(map[string]bool),
	}
}

// NewSignatureCacheFastWendy returns a new instance of SignatureVerifier
func NewSignatureCacheFastWendy(conf *config.ReplicaConfigFastWendy) *SignatureCacheFastWendy {
	return &SignatureCacheFastWendy{
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

// VerifySignatureBls verifies a partial signature
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
	valid := sig.S.VerifyByte(info.PubKeyBLS, hash[:])

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
	if len(qc.I) < s.conf.QuorumSize {
		return false
	}

	i := 0
	publicKeys := make([]bls.PublicKey, len(qc.I))
	for index := range qc.I {
		publicKeys[i] = *s.conf.Replicas[index].PubKeyBLS
		i++
	}

	sig := qc.Sig[0]
	return sig.FastAggregateVerify(publicKeys, qc.BlockHash[:])
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

// PartialSigBls struct
type PartialSigBls struct {
	ID config.ReplicaID
	S  *bls.Sign
}

// ToBytes returns
func (psig PartialSig) ToBytes() []byte {
	r := psig.R.Bytes()
	s := psig.S.Bytes()
	b := make([]byte, 4, 4+len(r)+len(s))
	binary.LittleEndian.PutUint32(b, uint32(psig.ID))
	b = append(b, r...)
	b = append(b, s...)
	return b
}

// ToBytes returns
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
	Sig       []bls.Sign
	BlockHash BlockHash
	I         map[config.ReplicaID]bool
}

// ToBytes returns a serialized representation of QC
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

// ToBytes returns
func (qc *QuorumCertBls) ToBytes() []byte {
	b := make([]byte, 0, 32)
	b = append(b, qc.BlockHash[:]...)

	for i := range qc.I {
		b = append(b, byte(i))
	}

	b = append(b, qc.Sig[0].Serialize()...)

	return b
}

func (qc *QuorumCert) String() string {
	return fmt.Sprintf("QuorumCert{Sigs: %d, Hash: %.8s}", len(qc.Sigs), qc.BlockHash)
}

func (qc *QuorumCertBls) String() string {
	return fmt.Sprintf("QuorumCert{Sigs: %d, Hash: %.8s}", len(qc.I), qc.BlockHash)
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

// AddPartialBls adds the partial signature to the quorum cert.
func (qc *QuorumCertBls) AddPartialBls(cert *PartialCertBls) error {
	// dont add a cert if there is already a signature from the same replica
	if _, exists := qc.I[cert.Sig.ID]; exists {
		return fmt.Errorf("Attempt to add partial cert from same replica twice")
	}

	if !bytes.Equal(qc.BlockHash[:], cert.BlockHash[:]) {
		return fmt.Errorf("Partial cert hash does not match quorum cert")
	}

	qc.I[cert.Sig.ID] = true
	qc.Sig = append(qc.Sig, *cert.Sig.S)

	return nil
}

// AggregateCert compresses signatures into one multi-signature
func (qc *QuorumCertBls) AggregateCert() error {
	var multiSig bls.Sign
	multiSig.Aggregate(qc.Sig)
	qc.Sig = nil
	qc.Sig = append(qc.Sig, multiSig)
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

// CreatePartialCertBls creates a partial cert from a block.
func CreatePartialCertBls(id config.ReplicaID, privKey *bls.SecretKey, block *BlockBls) (*PartialCertBls, error) {
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

// VerifyPartialCertBls will verify a PartialCert from a public key stored in ReplicaConfig
func VerifyPartialCertBls(conf *config.ReplicaConfigBls, cert *PartialCertBls) bool {
	info, ok := conf.Replicas[cert.Sig.ID]

	if !ok {
		logger.Printf("VerifyPartialSig: got signature from replica whose ID (%d) was not in config.", cert.Sig.ID)
		return false
	}

	return cert.Sig.S.VerifyByte(info.PubKeyBLS, cert.BlockHash[:])
}

// CreateQuorumCert creates an empty quorum certificate for a given block
func CreateQuorumCert(block *Block) *QuorumCert {
	return &QuorumCert{BlockHash: block.Hash(), Sigs: make(map[config.ReplicaID]PartialSig)}
}

// CreateQuorumCertBls creates an empty quorum certificate for a given block
func CreateQuorumCertBls(block *BlockBls) *QuorumCertBls {
	return &QuorumCertBls{BlockHash: block.Hash(), Sig: make([]bls.Sign, 0), I: make(map[config.ReplicaID]bool)}
}

/*
// CreateQuorumCertGenesis creates an empty quorum certificate for a given block
func CreateQuorumCertGenisisFastWendy(blockHash BlockHash, configuration *config.ReplicaConfigFastWendy) *QuorumCertBls {
	var aggSig bls.Sign
	return &QuorumCertBls{BlockHash: blockHash, Sig: aggSig, I: make([]bls.PublicKey, configuration.N)}
}*/

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

// VerifyQuorumCertBls will verify a QuorumCert from public keys stored in ReplicaConfigBls
func VerifyQuorumCertBls(conf *config.ReplicaConfigBls, qc *QuorumCertBls) bool {
	if len(qc.I) < conf.QuorumSize {
		return false
	}

	i := 0
	publicKeys := make([]bls.PublicKey, len(qc.I))
	for index := range qc.I {
		publicKeys[i] = *conf.Replicas[index].PubKeyBLS
		i++
	}

	sig := qc.Sig[0]
	return sig.FastAggregateVerify(publicKeys, qc.BlockHash[:])
}
