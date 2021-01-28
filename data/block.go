package data

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
)

// Command is the client data that is processed by HotStuff
type Command string

// BlockStorage provides a means to store a block based on its hash
type BlockStorage interface {
	Put(*Block)
	Get(BlockHash) (*Block, bool)
	BlockOf(*QuorumCert) (*Block, bool)
	ParentOf(*Block) (*Block, bool)
	GarbageCollectBlocks(int)
}

// BlockStorageBls provides a means to store a block based on its hash
type BlockStorageBls interface {
	Put(*BlockBls)
	Get(BlockHash) (*BlockBls, bool)
	BlockOf(*QuorumCertBls) (*BlockBls, bool)
	ParentOf(*BlockBls) (*BlockBls, bool)
	GarbageCollectBlocks(int)
}

// BlockHash represents a SHA256 hashsum of a Block
type BlockHash [32]byte

func (h BlockHash) String() string {
	return hex.EncodeToString(h[:])
}

// Block represents a block in the tree of commands
type Block struct {
	hash       *BlockHash
	Proposer   config.ReplicaID
	ParentHash BlockHash
	Commands   []Command
	Justify    *QuorumCert
	Height     int
	Committed  bool
}

// BlockBls represents a block in the tree of commands
type BlockBls struct {
	hash       *BlockHash
	Proposer   config.ReplicaID
	ParentHash BlockHash
	Commands   []Command
	Justify    *QuorumCertBls
	Height     int
	Committed  bool
}

// BlockFastWendy represents a block in the tree of commands
type BlockFastWendy struct {
	hash           *BlockHash
	Proposer       config.ReplicaID
	ParentHash     BlockHash
	Commands       []Command
	Justify        *QuorumCertBls
	Height         int
	Committed      bool
	publicKeysLock []bls.PublicKey
	publicWeakLock []bls.PublicKey
	aggSigLock     bls.Sign
	aggSigWeakLock bls.Sign
}

func (n Block) String() string {
	return fmt.Sprintf("Block{Parent: %.8s, Justify: %s, Height: %d, Committed: %v}",
		n.ParentHash, n.Justify, n.Height, n.Committed)
}

func (n BlockBls) String() string {
	return fmt.Sprintf("BlockBls{Parent: %.8s, Justify: %s, Height: %d, Committed: %v}",
		n.ParentHash, n.Justify, n.Height, n.Committed)
}

// Hash returns a hash digest of the block.
func (n Block) Hash() BlockHash {
	// return cached hash if available
	if n.hash != nil {
		return *n.hash
	}

	s256 := sha256.New()

	s256.Write(n.ParentHash[:])

	height := make([]byte, 8)
	binary.LittleEndian.PutUint64(height, uint64(n.Height))
	s256.Write(height[:])

	if n.Justify != nil {
		s256.Write(n.Justify.ToBytes())
	}

	for _, cmd := range n.Commands {
		s256.Write([]byte(cmd))
	}

	n.hash = new(BlockHash)
	sum := s256.Sum(nil)
	copy(n.hash[:], sum)

	return *n.hash
}

// Hash returns a hash digest of the block.
func (n BlockBls) Hash() BlockHash {
	// return cached hash if available
	if n.hash != nil {
		return *n.hash
	}

	s256 := sha256.New()

	s256.Write(n.ParentHash[:])

	height := make([]byte, 8)
	binary.LittleEndian.PutUint64(height, uint64(n.Height))
	s256.Write(height[:])

	if n.Justify != nil {
		s256.Write(n.Justify.ToBytes())
	}

	for _, cmd := range n.Commands {
		s256.Write([]byte(cmd))
	}

	n.hash = new(BlockHash)
	sum := s256.Sum(nil)
	copy(n.hash[:], sum)

	return *n.hash
}

// MapStorage is a simple implementation of BlockStorage that uses a concurrent map.
type MapStorage struct {
	// TODO: Experiment with RWMutex
	mut    sync.Mutex
	blocks map[BlockHash]*Block
}

// MapStorageBls is a simple implementation of BlockStorage that uses a concurrent map.
type MapStorageBls struct {
	// TODO: Experiment with RWMutex
	mut    sync.Mutex
	blocks map[BlockHash]*BlockBls
}

// NewMapStorage returns a new instance of MapStorage
func NewMapStorage() *MapStorage {
	return &MapStorage{
		blocks: make(map[BlockHash]*Block),
	}
}

// NewMapStorageBls returns a new instance of MapStorage
func NewMapStorageBls() *MapStorageBls {
	return &MapStorageBls{
		blocks: make(map[BlockHash]*BlockBls),
	}
}

// Put inserts a block into the map
func (s *MapStorage) Put(block *Block) {
	s.mut.Lock()
	defer s.mut.Unlock()

	hash := block.Hash()
	if _, ok := s.blocks[hash]; !ok {
		s.blocks[hash] = block
	}
}

// Put inserts a block into the map
func (s *MapStorageBls) Put(block *BlockBls) {
	s.mut.Lock()
	defer s.mut.Unlock()

	hash := block.Hash()
	if _, ok := s.blocks[hash]; !ok {
		s.blocks[hash] = block
	}
}

// Get gets a block from the map based on its hash.
func (s *MapStorage) Get(hash BlockHash) (block *Block, ok bool) {
	s.mut.Lock()
	defer s.mut.Unlock()

	block, ok = s.blocks[hash]
	return
}

// Get gets a block from the map based on its hash.
func (s *MapStorageBls) Get(hash BlockHash) (block *BlockBls, ok bool) {
	s.mut.Lock()
	defer s.mut.Unlock()

	block, ok = s.blocks[hash]
	return
}

// BlockOf returns the block associated with the quorum cert
func (s *MapStorage) BlockOf(qc *QuorumCert) (block *Block, ok bool) {
	s.mut.Lock()
	defer s.mut.Unlock()

	block, ok = s.blocks[qc.BlockHash]
	return
}

// BlockOf returns the block associated with the quorum cert
func (s *MapStorageBls) BlockOf(qc *QuorumCertBls) (block *BlockBls, ok bool) {
	s.mut.Lock()
	defer s.mut.Unlock()

	block, ok = s.blocks[qc.BlockHash]
	return
}

// ParentOf returns the parent of the given Block
func (s *MapStorage) ParentOf(child *Block) (parent *Block, ok bool) {
	s.mut.Lock()
	defer s.mut.Unlock()

	parent, ok = s.blocks[child.ParentHash]
	return
}

// ParentOf returns the parent of the given Block
func (s *MapStorageBls) ParentOf(child *BlockBls) (parent *BlockBls, ok bool) {
	s.mut.Lock()
	defer s.mut.Unlock()

	parent, ok = s.blocks[child.ParentHash]
	return
}

// GarbageCollectBlocks dereferences old Blocks that are no longer needed
func (s *MapStorage) GarbageCollectBlocks(currentVeiwHeigth int) {
	s.mut.Lock()
	defer s.mut.Unlock()

	var deleteAncestors func(block *Block)

	deleteAncestors = func(block *Block) {
		parent, ok := s.blocks[block.ParentHash]
		if ok {
			deleteAncestors(parent)
		}
		delete(s.blocks, block.Hash())
	}

	for _, n := range s.blocks {
		if n.Height+50 < currentVeiwHeigth {
			deleteAncestors(n)
		}
	}
}

// GarbageCollectBlocks dereferences old Blocks that are no longer needed
func (s *MapStorageBls) GarbageCollectBlocks(currentVeiwHeigth int) {
	s.mut.Lock()
	defer s.mut.Unlock()

	var deleteAncestors func(block *BlockBls)

	deleteAncestors = func(block *BlockBls) {
		parent, ok := s.blocks[block.ParentHash]
		if ok {
			deleteAncestors(parent)
		}
		delete(s.blocks, block.Hash())
	}

	for _, n := range s.blocks {
		if n.Height+50 < currentVeiwHeigth {
			deleteAncestors(n)
		}
	}
}
