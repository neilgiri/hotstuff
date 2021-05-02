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

// AggMessage type
type AggMessage struct {
	C string
	V string
}

// KeyAggMessagePair type
type KeyAggMessagePair struct {
	PK []bls.PublicKey
	M  AggMessage
}

// NewViewMsg type
type NewViewMsg struct {
	LockCertificate *QuorumCert
	Message         AggMessage
	Signature       bls.Sign
	ID              config.ReplicaID
}

// NewViewMsgFastWendy type
type NewViewMsgFastWendy struct {
	LockCertificate     *QuorumCert
	Message             AggMessage
	Signature           bls.Sign
	ID                  config.ReplicaID
	WeakLockCertificate *QuorumCert
	MessageWeakLock     AggMessage
	SignatureWeakLock   bls.Sign
	Vote                *PartialCert
}

// ProofNC type
type ProofNC struct {
	Messages  []KeyAggMessagePair
	Signature bls.Sign
	Hash      BlockHash
}

// NackMsg type
type NackMsg struct {
	HighLockCertificate *QuorumCert
	Hash                BlockHash
}

// AggregateSignature type
type AggregateSignature struct {
}

// KGen gets secret keys
func (AS *AggregateSignature) KGen(sk *bls.SecretKey, pk *bls.PublicKey, pop *bls.Sign) {
	sk.SetByCSPRNG()
	*pk = *sk.GetPublicKey()
	*pop = *sk.GetPop()
}

// SignShare verifies a partial signature
func (AS *AggregateSignature) SignShare(sk []bls.SecretKey, m AggMessage) bls.Sign {
	sigs := make([]bls.Sign, len(sk))
	/*i := 0
	var signature bls.Sign
	for j, _ := range m.C {
		sigs[i] = *sk[j].Sign(m.V)
		i++
	}

	signature.Aggregate(sigs)
	return signature*/

	var wg sync.WaitGroup
	var signature bls.Sign
	for j, _ := range m.C {
		wg.Add(1)
		go func(j int) {
			sigs[j] = *sk[j].Sign(m.V)
			wg.Done()
		}(j)
	}
	wg.Wait()
	signature.Aggregate(sigs)
	return signature
}

// VerifyShare verifies a partial signature
func (AS *AggregateSignature) VerifyShare(pk []bls.PublicKey, m AggMessage, sig bls.Sign) bool {
	publicKeys := make([]bls.PublicKey, len(pk))
	i := 0
	for j, _ := range m.C {
		publicKeys[i] = pk[j]
		i++
	}
	return sig.FastAggregateVerify(publicKeys, []byte(m.V))
}

// Agg aggregates signatures
func (AS *AggregateSignature) Agg(sigs []bls.Sign) bls.Sign {
	var agg bls.Sign
	agg.Aggregate(sigs)
	return agg
}

// VerifyAgg aggregates signatures
func (AS *AggregateSignature) VerifyAgg(keyMessagePairs []KeyAggMessagePair, sig bls.Sign) bool {
	i := 0
	firstPair := keyMessagePairs[0]
	//publicKeys := make([]bls.PublicKey, len(keyMessagePairs)*len(firstPair.PK))
	publicKeys := make([]bls.PublicKey, 0)

	for _, pair := range keyMessagePairs {
		for j, _ := range pair.M.C {
			firstPair = pair
			publicKeys = append(publicKeys, pair.PK[j])
			//publicKeys[i] = pair.PK[j]
			i++
		}
	}
	return sig.FastAggregateVerify(publicKeys, []byte(firstPair.M.V))
}

// SignatureCache keeps a cache of verified signatures in order to speed up verification
type SignatureCache struct {
	conf               *config.ReplicaConfig
	verifiedSignatures map[string]bool
	cache              list.List
	mut                sync.Mutex
}

// SignatureCacheWendy keeps a cache of verified signatures in order to speed up verification
type SignatureCacheWendy struct {
	conf               *config.ReplicaConfigWendy
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

// NewSignatureCacheWendy returns a new instance of SignatureVerifier
func NewSignatureCacheWendy(conf *config.ReplicaConfigWendy) *SignatureCacheWendy {
	return &SignatureCacheWendy{
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

// CreatePartialCert creates a partial cert from a block.
func (s *SignatureCacheWendy) CreatePartialCert(id config.ReplicaID, privKey *ecdsa.PrivateKey, block *Block) (*PartialCert, error) {
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

// CreatePartialCert creates a partial cert from a block.
func (s *SignatureCacheFastWendy) CreatePartialCert(id config.ReplicaID, privKey *ecdsa.PrivateKey, block *BlockFastWendy) (*PartialCert, error) {
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
func (s *SignatureCacheWendy) VerifySignature(sig PartialSig, hash BlockHash) bool {
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
func (s *SignatureCacheFastWendy) VerifySignature(sig PartialSig, hash BlockHash) bool {
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

	/*var numVerified uint64 = 0
	for _, psig := range qc.Sigs {
		if s.VerifySignature(psig, qc.BlockHash) {
			numVerified++
		}
	}
	return numVerified >= uint64(s.conf.QuorumSize)*/
}

// VerifyQuorumCert verifies a quorum certificate
func (s *SignatureCacheWendy) VerifyQuorumCert(qc *QuorumCert) bool {
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

// VerifyQuorumCert verifies a quorum certificate
func (s *SignatureCacheFastWendy) VerifyQuorumCert(qc *QuorumCert, quorumSize int) bool {
	if len(qc.Sigs) < quorumSize {
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
	return numVerified >= uint64(quorumSize)
	/*var numVerified uint64 = 0
	for _, psig := range qc.Sigs {
		if s.VerifySignature(psig, qc.BlockHash) {
			numVerified++
		}
	}
	return numVerified >= uint64(quorumSize)*/
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
func (s *SignatureCacheWendy) EvictOld(size int) {
	s.mut.Lock()
	for length := s.cache.Len(); length > size; length-- {
		el := s.cache.Front()
		k := s.cache.Remove(el).(string)
		delete(s.verifiedSignatures, k)
	}
	s.mut.Unlock()
}

// EvictOld reduces the size of the cache by removing the oldest cached results
func (s *SignatureCacheFastWendy) EvictOld(size int) {
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

// VoteMap struct
type VoteMap struct {
	VoteGroup map[string][]*PartialCert
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

// CreatePartialCert creates a partial cert from a block.
func CreatePartialCertFastWendy(id config.ReplicaID, privKey *ecdsa.PrivateKey, block *BlockFastWendy) (*PartialCert, error) {
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

// VerifyPartialCertFastWendy will verify a PartialCert from a public key stored in ReplicaConfig
func VerifyPartialCertFastWendy(conf *config.ReplicaConfigFastWendy, cert *PartialCert) bool {
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

// CreateQuorumCertFastWendy creates an empty quorum certificate for a given block
func CreateQuorumCertFastWendy(block *BlockFastWendy) *QuorumCert {
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

// VerifyQuorumCertFastWendy will verify a QuorumCert from public keys stored in ReplicaConfig
func VerifyQuorumCertFastWendy(conf *config.ReplicaConfig, qc *QuorumCert, quorumSize int) bool {
	if len(qc.Sigs) < quorumSize {
		return false
	}
	var wg sync.WaitGroup
	var numVerified uint64 = 0
	for i := 0; i < quorumSize; i++ {
		psig := qc.Sigs[config.ReplicaID(i)]
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
