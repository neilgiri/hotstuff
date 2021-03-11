package consensus

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
	"github.com/relab/hotstuff/internal/logging"
)

var logger *log.Logger

func init() {
	logger = logging.GetLogger()
}

// EventType is the type of notification sent to pacemaker
type EventType uint8

// These are the types of events that can be sent to pacemaker
const (
	QCFinish EventType = iota
	ReceiveProposal
	ReceiveVote
	HQCUpdate
	ReceiveNewView
)

// Event is sent to the pacemaker to allow it to observe the protocol.
type Event struct {
	Type    EventType
	QC      *data.QuorumCert
	Block   *data.Block
	Replica config.ReplicaID
}

// EventBls is sent to the pacemaker to allow it to observe the protocol.
type EventBls struct {
	Type    EventType
	QC      *data.QuorumCertBls
	Block   *data.BlockBls
	Replica config.ReplicaID
}

// HotStuffCore is the safety core of the HotStuffCore protocol
type HotStuffCore struct {
	mut sync.Mutex

	// Contains the commands that are waiting to be proposed
	cmdCache *data.CommandSet
	Config   *config.ReplicaConfig
	Blocks   data.BlockStorage
	SigCache *data.SignatureCache

	// protocol data
	vHeight    int
	genesis    *data.Block
	bLock      *data.Block
	bExec      *data.Block
	bLeaf      *data.Block
	qcHigh     *data.QuorumCert
	pendingQCs map[data.BlockHash]*data.QuorumCert

	waitProposal *sync.Cond

	pendingUpdates chan *data.Block

	eventChannels []chan Event

	// stops any goroutines started by HotStuff
	cancel context.CancelFunc

	exec chan []data.Command
}

// AddCommand adds command to block
func (hs *HotStuffCore) AddCommand(command data.Command) {
	hs.cmdCache.Add(command)
}

// GetHeight returns the height of the tree
func (hs *HotStuffCore) GetHeight() int {
	return hs.bLeaf.Height
}

// GetVotedHeight returns the height that was last voted at
func (hs *HotStuffCore) GetVotedHeight() int {
	return hs.vHeight
}

// GetLeaf returns the current leaf node of the tree
func (hs *HotStuffCore) GetLeaf() *data.Block {
	hs.mut.Lock()
	defer hs.mut.Unlock()
	return hs.bLeaf
}

// SetLeaf sets the leaf node of the tree
func (hs *HotStuffCore) SetLeaf(block *data.Block) {
	hs.mut.Lock()
	defer hs.mut.Unlock()
	hs.bLeaf = block
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (hs *HotStuffCore) GetQCHigh() *data.QuorumCert {
	hs.mut.Lock()
	defer hs.mut.Unlock()
	return hs.qcHigh
}

// GetEvents returns HotStuff events
func (hs *HotStuffCore) GetEvents() chan Event {
	c := make(chan Event)
	hs.eventChannels = append(hs.eventChannels, c)
	return c
}

// GetExec returns executed command
func (hs *HotStuffCore) GetExec() chan []data.Command {
	return hs.exec
}

// New creates a new Hotstuff instance
func New(conf *config.ReplicaConfig) *HotStuffCore {
	logger.SetPrefix(fmt.Sprintf("hs(id %d): ", conf.ID))
	genesis := &data.Block{
		Committed: true,
	}
	qcForGenesis := data.CreateQuorumCert(genesis)
	blocks := data.NewMapStorage()
	blocks.Put(genesis)

	ctx, cancel := context.WithCancel(context.Background())

	hs := &HotStuffCore{
		Config:         conf,
		genesis:        genesis,
		bLock:          genesis,
		bExec:          genesis,
		bLeaf:          genesis,
		qcHigh:         qcForGenesis,
		Blocks:         blocks,
		pendingQCs:     make(map[data.BlockHash]*data.QuorumCert),
		cancel:         cancel,
		SigCache:       data.NewSignatureCache(conf),
		cmdCache:       data.NewCommandSet(),
		pendingUpdates: make(chan *data.Block, 1),
		exec:           make(chan []data.Command, 1),
	}

	hs.waitProposal = sync.NewCond(&hs.mut)

	go hs.updateAsync(ctx)

	return hs
}

// expectBlock looks for a block with the given Hash, or waits for the next proposal to arrive
// hs.mut must be locked when calling this function
func (hs *HotStuffCore) expectBlock(hash data.BlockHash) (*data.Block, bool) {
	if block, ok := hs.Blocks.Get(hash); ok {
		return block, true
	}
	hs.waitProposal.Wait()
	return hs.Blocks.Get(hash)
}

func (hs *HotStuffCore) emitEvent(event Event) {
	for _, c := range hs.eventChannels {
		c <- event
	}
}

// UpdateQCHigh updates the qc held by the paceMaker, to the newest qc.
func (hs *HotStuffCore) UpdateQCHigh(qc *data.QuorumCert) bool {
	if !hs.SigCache.VerifyQuorumCert(qc) {
		logger.Println("QC not verified!:", qc)
		return false
	}

	logger.Println("UpdateQCHigh")

	newQCHighBlock, ok := hs.expectBlock(qc.BlockHash)
	if !ok {
		logger.Println("Could not find block of new QC!")
		return false
	}

	oldQCHighBlock, ok := hs.Blocks.BlockOf(hs.qcHigh)
	if !ok {
		panic(fmt.Errorf("Block from the old qcHigh missing from storage"))
	}

	if newQCHighBlock.Height > oldQCHighBlock.Height {
		hs.qcHigh = qc
		hs.bLeaf = newQCHighBlock
		hs.emitEvent(Event{Type: HQCUpdate, QC: hs.qcHigh, Block: hs.bLeaf})
		return true
	}

	logger.Println("UpdateQCHigh Failed")
	return false
}

// OnReceiveProposal handles a replica's response to the Proposal from the leader
func (hs *HotStuffCore) OnReceiveProposal(block *data.Block) (*data.PartialCert, error) {
	logger.Println("OnReceiveProposal:", block)
	hs.Blocks.Put(block)

	hs.mut.Lock()
	qcBlock, nExists := hs.expectBlock(block.Justify.BlockHash)

	if block.Height <= hs.vHeight {
		hs.mut.Unlock()
		logger.Println("OnReceiveProposal: Block height less than vHeight")
		return nil, fmt.Errorf("Block was not accepted")
	}

	safe := false
	if nExists && qcBlock.Height > hs.bLock.Height {
		safe = true
	} else {
		logger.Println("OnReceiveProposal: liveness condition failed")
		// check if block extends bLock
		b := block
		ok := true
		for ok && b.Height > hs.bLock.Height+1 {
			b, ok = hs.Blocks.Get(b.ParentHash)
		}
		if ok && b.ParentHash == hs.bLock.Hash() {
			safe = true
		} else {
			logger.Println("OnReceiveProposal: safety condition failed")
		}
	}

	if !safe {
		hs.mut.Unlock()
		logger.Println("OnReceiveProposal: Block not safe")
		return nil, fmt.Errorf("Block was not accepted")
	}

	logger.Println("OnReceiveProposal: Accepted block")
	hs.vHeight = block.Height
	hs.cmdCache.MarkProposed(block.Commands...)
	hs.mut.Unlock()

	hs.waitProposal.Broadcast()
	hs.emitEvent(Event{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

	// queue block for update
	hs.pendingUpdates <- block

	pc, err := hs.SigCache.CreatePartialCert(hs.Config.ID, hs.Config.PrivateKey, block)
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// OnReceiveVote handles an incoming vote from a replica
func (hs *HotStuffCore) OnReceiveVote(cert *data.PartialCert) {
	if !hs.SigCache.VerifySignature(cert.Sig, cert.BlockHash) {
		logger.Println("OnReceiveVote: signature not verified!")
		return
	}

	logger.Printf("OnReceiveVote: %.8s\n", cert.BlockHash)
	hs.emitEvent(Event{Type: ReceiveVote, Replica: cert.Sig.ID})

	hs.mut.Lock()
	defer hs.mut.Unlock()

	qc, ok := hs.pendingQCs[cert.BlockHash]
	if !ok {
		b, ok := hs.expectBlock(cert.BlockHash)
		if !ok {
			logger.Println("OnReceiveVote: could not find block for certificate.")
			return
		}
		if b.Height <= hs.bLeaf.Height {
			// too old, don't care
			return
		}
		// need to check again in case a qc was created while we waited for the block
		qc, ok = hs.pendingQCs[cert.BlockHash]
		if !ok {
			qc = data.CreateQuorumCert(b)
			hs.pendingQCs[cert.BlockHash] = qc
		}
	}

	err := qc.AddPartial(cert)
	if err != nil {
		logger.Println("OnReceiveVote: could not add partial signature to QC:", err)
	}

	if len(qc.Sigs) >= hs.Config.QuorumSize {
		delete(hs.pendingQCs, cert.BlockHash)
		logger.Println("OnReceiveVote: Created QC")
		hs.UpdateQCHigh(qc)
		hs.emitEvent(Event{Type: QCFinish, QC: qc})
	}

	// delete any pending QCs with lower height than bLeaf
	for k := range hs.pendingQCs {
		if b, ok := hs.Blocks.Get(k); ok {
			if b.Height <= hs.bLeaf.Height {
				delete(hs.pendingQCs, k)
			}
		} else {
			delete(hs.pendingQCs, k)
		}
	}
}

// OnReceiveNewView handles the leader's response to receiving a NewView rpc from a replica
func (hs *HotStuffCore) OnReceiveNewView(qc *data.QuorumCert) {
	hs.mut.Lock()
	defer hs.mut.Unlock()
	logger.Println("OnReceiveNewView")
	hs.emitEvent(Event{Type: ReceiveNewView, QC: qc})
	hs.UpdateQCHigh(qc)
}

func (hs *HotStuffCore) updateAsync(ctx context.Context) {
	for {
		select {
		case n := <-hs.pendingUpdates:
			hs.update(n)
		case <-ctx.Done():
			return
		}
	}
}

func (hs *HotStuffCore) update(block *data.Block) {
	// block1 = b'', block2 = b', block3 = b
	block1, ok := hs.Blocks.BlockOf(block.Justify)
	if !ok || block1.Committed {
		return
	}

	hs.mut.Lock()
	defer hs.mut.Unlock()

	logger.Println("PRE COMMIT:", block1)
	// PRE-COMMIT on block1
	hs.UpdateQCHigh(block.Justify)

	block2, ok := hs.Blocks.BlockOf(block1.Justify)
	if !ok || block2.Committed {
		return
	}

	if block2.Height > hs.bLock.Height {
		hs.bLock = block2 // COMMIT on block2
		logger.Println("COMMIT:", block2)
	}

	block3, ok := hs.Blocks.BlockOf(block2.Justify)
	if !ok || block3.Committed {
		return
	}

	if block1.ParentHash == block2.Hash() && block2.ParentHash == block3.Hash() {
		logger.Println("DECIDE", block3)
		hs.commit(block3)
		hs.bExec = block3 // DECIDE on block3
	}

	// Free up space by deleting old data
	hs.Blocks.GarbageCollectBlocks(hs.GetVotedHeight())
	hs.cmdCache.TrimToLen(hs.Config.BatchSize * 5)
	hs.SigCache.EvictOld(hs.Config.QuorumSize * 5)
}

func (hs *HotStuffCore) commit(block *data.Block) {
	// only called from within update. Thus covered by its mutex lock.
	if hs.bExec.Height < block.Height {
		if parent, ok := hs.Blocks.ParentOf(block); ok {
			hs.commit(parent)
		}
		block.Committed = true
		logger.Println("EXEC", block)
		//fmt.Printf("%s\n", block.String())
		hs.exec <- block.Commands
	}
}

// CreateProposal creates a new proposal
func (hs *HotStuffCore) CreateProposal() *data.Block {
	batch := hs.cmdCache.GetFirst(hs.Config.BatchSize)
	hs.mut.Lock()
	b := CreateLeaf(hs.bLeaf, batch, hs.qcHigh, hs.bLeaf.Height+1)
	hs.mut.Unlock()
	b.Proposer = hs.Config.ID
	hs.Blocks.Put(b)
	return b
}

// Close frees resources held by HotStuff and closes backend connections
func (hs *HotStuffCore) Close() {
	hs.cancel()
}

// CreateLeaf returns a new block that extends the parent.
func CreateLeaf(parent *data.Block, cmds []data.Command, qc *data.QuorumCert, height int) *data.Block {
	return &data.Block{
		ParentHash: parent.Hash(),
		Commands:   cmds,
		Justify:    qc,
		Height:     height,
	}
}

// WendyCoreEC is the safety core of the HotStuffCore protocol
type WendyCoreEC struct {
	mut sync.Mutex

	// Contains the commands that are waiting to be proposed
	cmdCache *data.CommandSet
	Config   *config.ReplicaConfigWendy
	Blocks   data.BlockStorage
	SigCache *data.SignatureCacheWendy

	// protocol data
	vHeight        int
	genesis        *data.Block
	bLock          *data.Block
	bExec          *data.Block
	bLeaf          *data.Block
	qcHigh         *data.QuorumCert
	pendingQCs     map[data.BlockHash]*data.QuorumCert
	viewChangeMsgs map[string][]data.NewViewMsg

	waitProposal *sync.Cond

	pendingUpdates chan *data.Block

	eventChannels []chan Event

	// stops any goroutines started by HotStuff
	cancel context.CancelFunc

	exec chan []data.Command
}

// AddCommand adds command to block
func (wendyEC *WendyCoreEC) AddCommand(command data.Command) {
	wendyEC.cmdCache.Add(command)
}

// GetHeight returns the height of the tree
func (wendyEC *WendyCoreEC) GetHeight() int {
	return wendyEC.bLeaf.Height
}

// GetVotedHeight returns the height that was last voted at
func (wendyEC *WendyCoreEC) GetVotedHeight() int {
	return wendyEC.vHeight
}

// GetLock returns the height that was last voted at
func (wendyEC *WendyCoreEC) GetLock() *data.Block {
	return wendyEC.bLock
}

// GetLeaf returns the current leaf node of the tree
func (wendyEC *WendyCoreEC) GetLeaf() *data.Block {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	return wendyEC.bLeaf
}

// SetLeaf sets the leaf node of the tree
func (wendyEC *WendyCoreEC) SetLeaf(block *data.Block) {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	wendyEC.bLeaf = block
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (wendyEC *WendyCoreEC) GetQCHigh() *data.QuorumCert {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	return wendyEC.qcHigh
}

// GetEvents returns HotStuff events
func (wendyEC *WendyCoreEC) GetEvents() chan Event {
	c := make(chan Event)
	wendyEC.eventChannels = append(wendyEC.eventChannels, c)
	return c
}

// GetExec returns executed command
func (wendyEC *WendyCoreEC) GetExec() chan []data.Command {
	return wendyEC.exec
}

// NewWendyEC creates a new Hotstuff instance
func NewWendyEC(conf *config.ReplicaConfigWendy) *WendyCoreEC {
	logger.SetPrefix(fmt.Sprintf("wendyec(id %d): ", conf.ID))
	genesis := &data.Block{
		Committed: true,
	}
	qcForGenesis := data.CreateQuorumCert(genesis)
	blocks := data.NewMapStorage()
	blocks.Put(genesis)

	ctx, cancel := context.WithCancel(context.Background())

	wendyEC := &WendyCoreEC{
		Config:         conf,
		genesis:        genesis,
		bLock:          genesis,
		bExec:          genesis,
		bLeaf:          genesis,
		qcHigh:         qcForGenesis,
		Blocks:         blocks,
		pendingQCs:     make(map[data.BlockHash]*data.QuorumCert),
		viewChangeMsgs: make(map[string][]data.NewViewMsg),
		cancel:         cancel,
		SigCache:       data.NewSignatureCacheWendy(conf),
		cmdCache:       data.NewCommandSet(),
		pendingUpdates: make(chan *data.Block, 1),
		exec:           make(chan []data.Command, 1),
	}

	wendyEC.waitProposal = sync.NewCond(&wendyEC.mut)

	go wendyEC.updateAsync(ctx)

	return wendyEC
}

// expectBlock looks for a block with the given Hash, or waits for the next proposal to arrive
// hs.mut must be locked when calling this function
func (wendyEC *WendyCoreEC) expectBlock(hash data.BlockHash) (*data.Block, bool) {
	if block, ok := wendyEC.Blocks.Get(hash); ok {
		return block, true
	}
	wendyEC.waitProposal.Wait()
	return wendyEC.Blocks.Get(hash)
}

func (wendyEC *WendyCoreEC) emitEvent(event Event) {
	for _, c := range wendyEC.eventChannels {
		c <- event
	}
}

// UpdateQCHigh updates the qc held by the paceMaker, to the newest qc.
func (wendyEC *WendyCoreEC) UpdateQCHigh(qc *data.QuorumCert) bool {
	if !wendyEC.SigCache.VerifyQuorumCert(qc) {
		logger.Println("QC not verified!:", qc)
		return false
	}

	logger.Println("UpdateQCHigh")

	newQCHighBlock, ok := wendyEC.expectBlock(qc.BlockHash)
	if !ok {
		logger.Println("Could not find block of new QC!")
		return false
	}

	oldQCHighBlock, ok := wendyEC.Blocks.BlockOf(wendyEC.qcHigh)
	if !ok {
		panic(fmt.Errorf("Block from the old qcHigh missing from storage"))
	}

	if newQCHighBlock.Height > oldQCHighBlock.Height {
		wendyEC.qcHigh = qc
		wendyEC.bLeaf = newQCHighBlock
		wendyEC.emitEvent(Event{Type: HQCUpdate, QC: wendyEC.qcHigh, Block: wendyEC.bLeaf})
		return true
	}

	logger.Println("UpdateQCHigh Failed")
	return false
}

// OnReceiveProposal handles a replica's response to the Proposal from the leader
func (wendyEC *WendyCoreEC) OnReceiveProposal(block *data.Block) (*data.PartialCert, *data.NackMsg, error) {
	logger.Println("OnReceiveProposal:", block)
	wendyEC.Blocks.Put(block)

	wendyEC.mut.Lock()
	qcBlock, nExists := wendyEC.expectBlock(block.Justify.BlockHash)

	if block.Height <= wendyEC.vHeight {
		wendyEC.mut.Unlock()
		logger.Println("OnReceiveProposal: Block height less than vHeight")
		return nil, nil, fmt.Errorf("Block was not accepted")
	}

	safe := false
	if nExists && qcBlock.Height > wendyEC.bLock.Height {
		safe = true
	} else {
		logger.Println("OnReceiveProposal: liveness condition failed")
		// check if block extends bLock
		b := block
		ok := true
		for ok && b.Height > wendyEC.bLock.Height+1 {
			b, ok = wendyEC.Blocks.Get(b.ParentHash)
		}
		if ok && b.ParentHash == wendyEC.bLock.Hash() {
			safe = true
		} else {
			logger.Println("OnReceiveProposal: safety condition failed")
		}
	}

	if !safe {
		wendyEC.mut.Unlock()
		logger.Println("OnReceiveProposal: Block not safe")
		return nil, &data.NackMsg{HighLockCertificate: wendyEC.GetQCHigh(), Hash: block.Hash()}, fmt.Errorf("Block was not accepted")
	}

	logger.Println("OnReceiveProposal: Accepted block")
	wendyEC.vHeight = block.Height
	wendyEC.cmdCache.MarkProposed(block.Commands...)
	wendyEC.mut.Unlock()

	wendyEC.waitProposal.Broadcast()
	wendyEC.emitEvent(Event{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

	// queue block for update
	wendyEC.pendingUpdates <- block

	pc, err := wendyEC.SigCache.CreatePartialCert(wendyEC.Config.ID, wendyEC.Config.PrivateKey, block)
	if err != nil {
		return nil, nil, err
	}
	return pc, nil, nil
}

// OnReceiveVote handles an incoming vote from a replica
func (wendyEC *WendyCoreEC) OnReceiveVote(cert *data.PartialCert) {
	if !wendyEC.SigCache.VerifySignature(cert.Sig, cert.BlockHash) {
		logger.Println("OnReceiveVote: signature not verified!")
		return
	}

	logger.Printf("OnReceiveVote: %.8s\n", cert.BlockHash)
	wendyEC.emitEvent(Event{Type: ReceiveVote, Replica: cert.Sig.ID})

	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()

	qc, ok := wendyEC.pendingQCs[cert.BlockHash]
	if !ok {
		b, ok := wendyEC.expectBlock(cert.BlockHash)
		if !ok {
			logger.Println("OnReceiveVote: could not find block for certificate.")
			return
		}
		if b.Height <= wendyEC.bLeaf.Height {
			// too old, don't care
			return
		}
		// need to check again in case a qc was created while we waited for the block
		qc, ok = wendyEC.pendingQCs[cert.BlockHash]
		if !ok {
			qc = data.CreateQuorumCert(b)
			wendyEC.pendingQCs[cert.BlockHash] = qc
		}
	}

	err := qc.AddPartial(cert)
	if err != nil {
		logger.Println("OnReceiveVote: could not add partial signature to QC:", err)
	}

	if len(qc.Sigs) >= wendyEC.Config.QuorumSize {
		delete(wendyEC.pendingQCs, cert.BlockHash)
		logger.Println("OnReceiveVote: Created QC")
		wendyEC.UpdateQCHigh(qc)
		wendyEC.emitEvent(Event{Type: QCFinish, QC: qc})
	}

	// delete any pending QCs with lower height than bLeaf
	for k := range wendyEC.pendingQCs {
		if b, ok := wendyEC.Blocks.Get(k); ok {
			if b.Height <= wendyEC.bLeaf.Height {
				delete(wendyEC.pendingQCs, k)
			}
		} else {
			delete(wendyEC.pendingQCs, k)
		}
	}
}

// OnReceiveNewView handles the leader's response to receiving a NewView rpc from a replica
func (wendyEC *WendyCoreEC) OnReceiveNewView(newViewMsg *data.NewViewMsg) {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	logger.Println("OnReceiveNewView")
	wendyEC.emitEvent(Event{Type: ReceiveNewView, QC: newViewMsg.LockCertificate})
	wendyEC.UpdateQCHigh(newViewMsg.LockCertificate)

	if _, ok := wendyEC.viewChangeMsgs[newViewMsg.Message.V]; ok {
		wendyEC.viewChangeMsgs[newViewMsg.Message.V][newViewMsg.ID] = *newViewMsg
	} else {
		wendyEC.viewChangeMsgs[newViewMsg.Message.V] = make([]data.NewViewMsg, len(wendyEC.Config.Replicas))
	}
}

// OnReceiveNack handles the leader's response to receiving a Nack rpc from a replica
func (wendyEC *WendyCoreEC) OnReceiveNack(nackMsg *data.NackMsg) data.ProofNC {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	logger.Println("OnReceiveNack")

	targetView := strconv.FormatInt(int64(wendyEC.GetHeight()), 2)

	var AS data.AggregateSignature
	msgs := wendyEC.viewChangeMsgs[targetView]
	numEntries := len(msgs)

	sigs := make([]bls.Sign, numEntries)
	for i := 0; i < numEntries; i++ {
		sigs[i] = msgs[i].Signature
	}

	aggSig := AS.Agg(sigs)

	pairs := make([]data.KeyAggMessagePair, numEntries)
	for i := 0; i < numEntries; i++ {
		pairs[i] = data.KeyAggMessagePair{PK: wendyEC.Config.Replicas[msgs[i].ID].ProofPubKeys, M: msgs[i].Message}
	}

	proof := data.ProofNC{Messages: pairs, Signature: aggSig, Hash: nackMsg.Hash}
	return proof
}

// OnReceiveProofNC handles the replica's response to receiving a ProofNC rpc from a replica
func (wendyEC *WendyCoreEC) OnReceiveProofNC(proof *data.ProofNC) (*data.PartialCert, error) {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	logger.Println("OnReceiveProofNC")

	var AS data.AggregateSignature
	block, _ := wendyEC.expectBlock(proof.Hash)
	if AS.VerifyAgg(proof.Messages, proof.Signature) {
		logger.Println("OnReceiveProofNC: Accepted block")
		wendyEC.vHeight = block.Height
		wendyEC.cmdCache.MarkProposed(block.Commands...)
		wendyEC.mut.Unlock()

		wendyEC.waitProposal.Broadcast()
		wendyEC.emitEvent(Event{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

		// queue block for update
		wendyEC.pendingUpdates <- block

		pc, err := wendyEC.SigCache.CreatePartialCert(wendyEC.Config.ID, wendyEC.Config.PrivateKey, block)
		if err != nil {
			return nil, err
		}
		return pc, nil
	}
	return nil, nil
}

func (wendyEC *WendyCoreEC) updateAsync(ctx context.Context) {
	for {
		select {
		case n := <-wendyEC.pendingUpdates:
			wendyEC.update(n)
		case <-ctx.Done():
			return
		}
	}
}

func (wendyEC *WendyCoreEC) update(block *data.Block) {
	// block1 = b'', block2 = b', block3 = b
	block1, ok := wendyEC.Blocks.BlockOf(block.Justify)
	if !ok || block1.Committed {
		return
	}

	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()

	// Lock on block1
	logger.Println("LOCK:", block1)
	// Lock on block1
	wendyEC.UpdateQCHigh(block.Justify)

	if !ok || block1.Committed {
		return
	}

	if block1.Height > wendyEC.bLock.Height {
		wendyEC.bLock = block1 // Lock on block1
		logger.Println("LOCK:", block1)
	}

	block2, ok := wendyEC.Blocks.BlockOf(block1.Justify)
	if !ok || block2.Committed {
		return
	}

	if block.ParentHash == block1.Hash() && block1.ParentHash == block2.Hash() {
		logger.Println("DECIDE", block2)
		wendyEC.commit(block2)
		wendyEC.bExec = block2 // DECIDE on block2
	}

	// Free up space by deleting old data
	wendyEC.Blocks.GarbageCollectBlocks(wendyEC.GetVotedHeight())
	wendyEC.cmdCache.TrimToLen(wendyEC.Config.BatchSize * 5)
	wendyEC.SigCache.EvictOld(wendyEC.Config.QuorumSize * 5)
}

func (wendyEC *WendyCoreEC) commit(block *data.Block) {
	// only called from within update. Thus covered by its mutex lock.
	if wendyEC.bExec.Height < block.Height {
		if parent, ok := wendyEC.Blocks.ParentOf(block); ok {
			wendyEC.commit(parent)
		}
		block.Committed = true
		logger.Println("EXEC", block)
		//fmt.Printf("%s\n", block.String())
		wendyEC.exec <- block.Commands
	}
}

// CreateProposal creates a new proposal
func (wendyEC *WendyCoreEC) CreateProposal() *data.Block {
	batch := wendyEC.cmdCache.GetFirst(wendyEC.Config.BatchSize)
	wendyEC.mut.Lock()
	b := CreateLeaf(wendyEC.bLeaf, batch, wendyEC.qcHigh, wendyEC.bLeaf.Height+1)
	wendyEC.mut.Unlock()
	b.Proposer = wendyEC.Config.ID
	wendyEC.Blocks.Put(b)
	return b
}

// Close frees resources held by HotStuff and closes backend connections
func (wendyEC *WendyCoreEC) Close() {
	wendyEC.cancel()
}

// WendyCore is the safety core of the WendyCore protocol
type WendyCore struct {
	mut sync.Mutex

	// Contains the commands that are waiting to be proposed
	cmdCache *data.CommandSet
	Config   *config.ReplicaConfigBls
	Blocks   data.BlockStorageBls
	SigCache *data.SignatureCacheBls

	// protocol data
	vHeight    int
	genesis    *data.BlockBls
	bLock      *data.BlockBls
	bExec      *data.BlockBls
	bLeaf      *data.BlockBls
	qcHigh     *data.QuorumCertBls
	pendingQCs map[data.BlockHash]*data.QuorumCertBls

	waitProposal *sync.Cond

	pendingUpdates chan *data.BlockBls

	eventChannels []chan EventBls

	// stops any goroutines started by Wendy
	cancel context.CancelFunc

	exec chan []data.Command
}

// AddCommand adds a command
func (wc *WendyCore) AddCommand(command data.Command) {
	wc.cmdCache.Add(command)
}

// GetHeight returns the height of the tree
func (wc *WendyCore) GetHeight() int {
	return wc.bLeaf.Height
}

// GetVotedHeight returns the height that was last voted at
func (wc *WendyCore) GetVotedHeight() int {
	return wc.vHeight
}

// GetLeaf returns the current leaf node of the tree
func (wc *WendyCore) GetLeaf() *data.BlockBls {
	wc.mut.Lock()
	defer wc.mut.Unlock()
	return wc.bLeaf
}

// SetLeaf sets the leaf node of the tree
func (wc *WendyCore) SetLeaf(block *data.BlockBls) {
	wc.mut.Lock()
	defer wc.mut.Unlock()
	wc.bLeaf = block
}

// GetQCHigh returns the highest valid Quorum Certificate known to the wendy instance.
func (wc *WendyCore) GetQCHigh() *data.QuorumCertBls {
	wc.mut.Lock()
	defer wc.mut.Unlock()
	return wc.qcHigh
}

// GetEvents returns the events
func (wc *WendyCore) GetEvents() chan EventBls {
	c := make(chan EventBls)
	wc.eventChannels = append(wc.eventChannels, c)
	return c
}

// GetExec returns the executed block
func (wc *WendyCore) GetExec() chan []data.Command {
	return wc.exec
}

// GetLockViewSig returns a multisignature representing the view of the highest lock certificate known to this wendy instance
func (wc *WendyCore) GetLockViewSig() (*data.PartialSigBls, []bool) {
	wc.mut.Lock()
	defer wc.mut.Unlock()
	lockCertView := wc.bLock.Height
	bitsStr := strconv.FormatInt(int64(lockCertView), 2)
	bitVector := make([]bool, len(bitsStr))
	signatures := make([]bls.Sign, len(bitsStr))
	targetView := wc.GetHeight() + 1

	signatureIndex := 0
	for i, character := range bitsStr {
		if string(character) == "1" {
			bitVector[i] = true
			signatures[signatureIndex] = *wc.Config.ProofNCPrivKeys[i].Sign(strconv.Itoa(targetView))
			signatureIndex++
		} else {
			bitVector[i] = false
		}
	}

	var aggSig *bls.Sign
	aggSig.Aggregate(signatures)
	partialSig := data.PartialSigBls{ID: wc.Config.ID, S: aggSig}
	return &partialSig, bitVector
}

// NewWendy creates a new Wendy instance
func NewWendy(conf *config.ReplicaConfigBls) *WendyCore {
	logger.SetPrefix(fmt.Sprintf("wc(id %d): ", conf.ID))
	genesis := &data.BlockBls{
		Committed: true,
	}
	qcForGenesis := data.CreateQuorumCertBls(genesis)
	blocks := data.NewMapStorageBls()
	blocks.Put(genesis)

	ctx, cancel := context.WithCancel(context.Background())

	wc := &WendyCore{
		Config:         conf,
		genesis:        genesis,
		bLock:          genesis,
		bExec:          genesis,
		bLeaf:          genesis,
		qcHigh:         qcForGenesis,
		Blocks:         blocks,
		pendingQCs:     make(map[data.BlockHash]*data.QuorumCertBls),
		cancel:         cancel,
		SigCache:       data.NewSignatureCacheBls(conf),
		cmdCache:       data.NewCommandSet(),
		pendingUpdates: make(chan *data.BlockBls, 1),
		exec:           make(chan []data.Command, 1),
	}

	wc.waitProposal = sync.NewCond(&wc.mut)

	go wc.updateAsync(ctx)

	return wc
}

// expectBlock looks for a block with the given Hash, or waits for the next proposal to arrive
// wc.mut must be locked when calling this function
func (wc *WendyCore) expectBlock(hash data.BlockHash) (*data.BlockBls, bool) {
	if block, ok := wc.Blocks.Get(hash); ok {
		return block, true
	}
	wc.waitProposal.Wait()
	return wc.Blocks.Get(hash)
}

func (wc *WendyCore) emitEvent(event EventBls) {
	for _, c := range wc.eventChannels {
		c <- event
	}
}

// UpdateQCHigh updates the qc held by the paceMaker, to the newest qc.
func (wc *WendyCore) UpdateQCHigh(qc *data.QuorumCertBls) bool {
	if !wc.SigCache.VerifyQuorumCertBls(qc) {
		logger.Println("QC not verified!:", qc)
		return false
	}

	logger.Println("UpdateQCHigh")

	newQCHighBlock, ok := wc.expectBlock(qc.BlockHash)
	if !ok {
		logger.Println("Could not find block of new QC!")
		return false
	}

	oldQCHighBlock, ok := wc.Blocks.BlockOf(wc.qcHigh)
	if !ok {
		panic(fmt.Errorf("Block from the old qcHigh missing from storage"))
	}

	if newQCHighBlock.Height > oldQCHighBlock.Height {
		wc.qcHigh = qc
		wc.bLeaf = newQCHighBlock
		wc.emitEvent(EventBls{Type: HQCUpdate, QC: wc.qcHigh, Block: wc.bLeaf})
		return true
	}

	logger.Println("UpdateQCHigh Failed")
	return false
}

// OnReceiveProposal handles a replica's response to the Proposal from the leader
func (wc *WendyCore) OnReceiveProposal(block *data.BlockBls) (*data.PartialCertBls, error) {
	logger.Println("OnReceiveProposal:", block)
	wc.Blocks.Put(block)

	wc.mut.Lock()
	qcBlock, nExists := wc.expectBlock(block.Justify.BlockHash)

	if block.Height <= wc.vHeight {
		wc.mut.Unlock()
		logger.Println("OnReceiveProposal: Block height less than vHeight")
		return nil, fmt.Errorf("Block was not accepted")
	}

	safe := false
	if nExists && qcBlock.Height > wc.bLock.Height {
		safe = true
	} else {
		logger.Println("OnReceiveProposal: liveness condition failed")
		// check if block extends bLock
		b := block
		ok := true
		for ok && b.Height > wc.bLock.Height+1 {
			b, ok = wc.Blocks.Get(b.ParentHash)
		}
		if ok && b.ParentHash == wc.bLock.Hash() {
			safe = true
		} else {
			logger.Println("OnReceiveProposal: safety condition failed")
		}
	}

	if !safe {
		wc.mut.Unlock()
		logger.Println("OnReceiveProposal: Block not safe")
		return nil, fmt.Errorf("Block was not accepted")
	}

	logger.Println("OnReceiveProposal: Accepted block")
	wc.vHeight = block.Height
	wc.cmdCache.MarkProposed(block.Commands...)
	wc.mut.Unlock()

	wc.waitProposal.Broadcast()
	wc.emitEvent(EventBls{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

	// queue block for update
	wc.pendingUpdates <- block

	pc, err := wc.SigCache.CreatePartialCertBls(wc.Config.ID, wc.Config.PrivateKey, block)
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// OnReceiveVote handles an incoming vote from a replica
func (wc *WendyCore) OnReceiveVote(cert *data.PartialCertBls) {
	if !wc.SigCache.VerifySignatureBls(cert.Sig, cert.BlockHash) {
		logger.Println("OnReceiveVote: signature not verified!")
		return
	}

	logger.Printf("OnReceiveVote: %.8s\n", cert.BlockHash)
	wc.emitEvent(EventBls{Type: ReceiveVote, Replica: cert.Sig.ID})

	wc.mut.Lock()
	defer wc.mut.Unlock()

	qc, ok := wc.pendingQCs[cert.BlockHash]
	if !ok {
		b, ok := wc.expectBlock(cert.BlockHash)
		if !ok {
			logger.Println("OnReceiveVote: could not find block for certificate.")
			return
		}
		if b.Height <= wc.bLeaf.Height {
			// too old, don't care
			return
		}
		// need to check again in case a qc was created while we waited for the block
		qc, ok = wc.pendingQCs[cert.BlockHash]
		if !ok {
			qc = data.CreateQuorumCertBls(b)
			wc.pendingQCs[cert.BlockHash] = qc
		}
	}

	err := qc.AddPartialBls(cert)
	if err != nil {
		logger.Println("OnReceiveVote: could not add partial signature to QC:", err)
	}

	if len(qc.I) >= wc.Config.QuorumSize {
		delete(wc.pendingQCs, cert.BlockHash)
		logger.Println("OnReceiveVote: Created QC")
		qc.AggregateCert()
		wc.UpdateQCHigh(qc)
		wc.emitEvent(EventBls{Type: QCFinish, QC: qc})
	}

	// delete any pending QCs with lower height than bLeaf
	for k := range wc.pendingQCs {
		if b, ok := wc.Blocks.Get(k); ok {
			if b.Height <= wc.bLeaf.Height {
				delete(wc.pendingQCs, k)
			}
		} else {
			delete(wc.pendingQCs, k)
		}
	}
}

// OnReceiveNewView handles the leader's response to receiving a NewView rpc from a replica
func (wc *WendyCore) OnReceiveNewView(qc *data.QuorumCertBls) {
	wc.mut.Lock()
	defer wc.mut.Unlock()
	logger.Println("OnReceiveNewView")
	wc.emitEvent(EventBls{Type: ReceiveNewView, QC: qc})
	wc.UpdateQCHigh(qc)
}

func (wc *WendyCore) updateAsync(ctx context.Context) {
	for {
		select {
		case n := <-wc.pendingUpdates:
			wc.update(n)
		case <-ctx.Done():
			return
		}
	}
}

func (wc *WendyCore) update(block *data.BlockBls) {
	// block1 = b'', block2 = b', block3 = b
	block1, ok := wc.Blocks.BlockOf(block.Justify)
	if !ok || block1.Committed {
		return
	}

	wc.mut.Lock()
	defer wc.mut.Unlock()

	logger.Println("LOCK:", block1)
	// Lock on block1
	wc.UpdateQCHigh(block.Justify)

	if !ok || block1.Committed {
		return
	}

	if block1.Height > wc.bLock.Height {
		wc.bLock = block1 // LOCK on block1
		logger.Println("LOCK:", block1)
	}

	block2, ok := wc.Blocks.BlockOf(block1.Justify)

	if !ok || block2.Committed {
		return
	}

	if block.ParentHash == block1.Hash() && block1.ParentHash == block2.Hash() {
		logger.Println("DECIDE", block2)
		wc.commit(block2)
		wc.bExec = block2 // DECIDE on block2
	}

	// Free up space by deleting old data
	wc.Blocks.GarbageCollectBlocks(wc.GetVotedHeight())
	wc.cmdCache.TrimToLen(wc.Config.BatchSize * 5)
	wc.SigCache.EvictOld(wc.Config.QuorumSize * 5)
}

func (wc *WendyCore) commit(block *data.BlockBls) {
	// only called from within update. Thus covered by its mutex lock.
	if wc.bExec.Height < block.Height {
		if parent, ok := wc.Blocks.ParentOf(block); ok {
			wc.commit(parent)
		}
		block.Committed = true
		logger.Println("EXEC", block)
		wc.exec <- block.Commands
	}
}

// CreateProposal creates a new proposal
func (wc *WendyCore) CreateProposal() *data.BlockBls {
	batch := wc.cmdCache.GetFirst(wc.Config.BatchSize)
	wc.mut.Lock()
	b := CreateLeafBls(wc.bLeaf, batch, wc.qcHigh, wc.bLeaf.Height+1)
	wc.mut.Unlock()
	b.Proposer = wc.Config.ID
	wc.Blocks.Put(b)
	return b
}

// Close frees resources held by HotStuff and closes backend connections
func (wc *WendyCore) Close() {
	wc.cancel()
}

// CreateLeafBls returns a new block that extends the parent.
func CreateLeafBls(parent *data.BlockBls, cmds []data.Command, qc *data.QuorumCertBls, height int) *data.BlockBls {
	return &data.BlockBls{
		ParentHash: parent.Hash(),
		Commands:   cmds,
		Justify:    qc,
		Height:     height,
	}
}

// FastWendyCoreEC is the safety core of the HotStuffCore protocol
type FastWendyCoreEC struct {
	mut sync.Mutex

	// Contains the commands that are waiting to be proposed
	cmdCache *data.CommandSet
	Config   *config.ReplicaConfigWendy
	Blocks   data.BlockStorage
	SigCache *data.SignatureCacheWendy

	// protocol data
	vHeight        int
	genesis        *data.Block
	bLock          *data.Block
	bExec          *data.Block
	bLeaf          *data.Block
	qcHigh         *data.QuorumCert
	pendingQCs     map[data.BlockHash]*data.QuorumCert
	viewChangeMsgs map[string][]data.NewViewMsg

	waitProposal *sync.Cond

	pendingUpdates chan *data.Block

	eventChannels []chan Event

	// stops any goroutines started by HotStuff
	cancel context.CancelFunc

	exec chan []data.Command
}

// AddCommand adds command to block
func (wendyEC *FastWendyCoreEC) AddCommand(command data.Command) {
	wendyEC.cmdCache.Add(command)
}

// GetHeight returns the height of the tree
func (wendyEC *FastWendyCoreEC) GetHeight() int {
	return wendyEC.bLeaf.Height
}

// GetVotedHeight returns the height that was last voted at
func (wendyEC *FastWendyCoreEC) GetVotedHeight() int {
	return wendyEC.vHeight
}

// GetLock returns the height that was last voted at
func (wendyEC *FastWendyCoreEC) GetLock() *data.Block {
	return wendyEC.bLock
}

// GetLeaf returns the current leaf node of the tree
func (wendyEC *FastWendyCoreEC) GetLeaf() *data.Block {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	return wendyEC.bLeaf
}

// SetLeaf sets the leaf node of the tree
func (wendyEC *FastWendyCoreEC) SetLeaf(block *data.Block) {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	wendyEC.bLeaf = block
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (wendyEC *FastWendyCoreEC) GetQCHigh() *data.QuorumCert {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	return wendyEC.qcHigh
}

// GetEvents returns HotStuff events
func (wendyEC *FastWendyCoreEC) GetEvents() chan Event {
	c := make(chan Event)
	wendyEC.eventChannels = append(wendyEC.eventChannels, c)
	return c
}

// GetExec returns executed command
func (wendyEC *FastWendyCoreEC) GetExec() chan []data.Command {
	return wendyEC.exec
}

// NewFastWendyEC creates a new Hotstuff instance
func NewFastWendyEC(conf *config.ReplicaConfigWendy) *FastWendyCoreEC {
	logger.SetPrefix(fmt.Sprintf("wendyec(id %d): ", conf.ID))
	genesis := &data.Block{
		Committed: true,
	}
	qcForGenesis := data.CreateQuorumCert(genesis)
	blocks := data.NewMapStorage()
	blocks.Put(genesis)

	ctx, cancel := context.WithCancel(context.Background())

	wendyEC := &FastWendyCoreEC{
		Config:         conf,
		genesis:        genesis,
		bLock:          genesis,
		bExec:          genesis,
		bLeaf:          genesis,
		qcHigh:         qcForGenesis,
		Blocks:         blocks,
		pendingQCs:     make(map[data.BlockHash]*data.QuorumCert),
		viewChangeMsgs: make(map[string][]data.NewViewMsg),
		cancel:         cancel,
		SigCache:       data.NewSignatureCacheWendy(conf),
		cmdCache:       data.NewCommandSet(),
		pendingUpdates: make(chan *data.Block, 1),
		exec:           make(chan []data.Command, 1),
	}

	wendyEC.waitProposal = sync.NewCond(&wendyEC.mut)

	go wendyEC.updateAsync(ctx)

	return wendyEC
}

// expectBlock looks for a block with the given Hash, or waits for the next proposal to arrive
// hs.mut must be locked when calling this function
func (wendyEC *FastWendyCoreEC) expectBlock(hash data.BlockHash) (*data.Block, bool) {
	if block, ok := wendyEC.Blocks.Get(hash); ok {
		return block, true
	}
	wendyEC.waitProposal.Wait()
	return wendyEC.Blocks.Get(hash)
}

func (wendyEC *FastWendyCoreEC) emitEvent(event Event) {
	for _, c := range wendyEC.eventChannels {
		c <- event
	}
}

// UpdateQCHigh updates the qc held by the paceMaker, to the newest qc.
func (wendyEC *FastWendyCoreEC) UpdateQCHigh(qc *data.QuorumCert) bool {
	if !wendyEC.SigCache.VerifyQuorumCert(qc) {
		logger.Println("QC not verified!:", qc)
		return false
	}

	logger.Println("UpdateQCHigh")

	newQCHighBlock, ok := wendyEC.expectBlock(qc.BlockHash)
	if !ok {
		logger.Println("Could not find block of new QC!")
		return false
	}

	oldQCHighBlock, ok := wendyEC.Blocks.BlockOf(wendyEC.qcHigh)
	if !ok {
		panic(fmt.Errorf("Block from the old qcHigh missing from storage"))
	}

	if newQCHighBlock.Height > oldQCHighBlock.Height {
		wendyEC.qcHigh = qc
		wendyEC.bLeaf = newQCHighBlock
		wendyEC.emitEvent(Event{Type: HQCUpdate, QC: wendyEC.qcHigh, Block: wendyEC.bLeaf})
		return true
	}

	logger.Println("UpdateQCHigh Failed")
	return false
}

// OnReceiveProposal handles a replica's response to the Proposal from the leader
func (wendyEC *FastWendyCoreEC) OnReceiveProposal(block *data.Block) (*data.PartialCert, *data.NackMsg, error) {
	logger.Println("OnReceiveProposal:", block)
	wendyEC.Blocks.Put(block)

	wendyEC.mut.Lock()
	qcBlock, nExists := wendyEC.expectBlock(block.Justify.BlockHash)

	if block.Height <= wendyEC.vHeight {
		wendyEC.mut.Unlock()
		logger.Println("OnReceiveProposal: Block height less than vHeight")
		return nil, nil, fmt.Errorf("Block was not accepted")
	}

	safe := false
	if nExists && qcBlock.Height > wendyEC.bLock.Height {
		safe = true
	} else {
		logger.Println("OnReceiveProposal: liveness condition failed")
		// check if block extends bLock
		b := block
		ok := true
		for ok && b.Height > wendyEC.bLock.Height+1 {
			b, ok = wendyEC.Blocks.Get(b.ParentHash)
		}
		if ok && b.ParentHash == wendyEC.bLock.Hash() {
			safe = true
		} else {
			logger.Println("OnReceiveProposal: safety condition failed")
		}
	}

	if !safe {
		wendyEC.mut.Unlock()
		logger.Println("OnReceiveProposal: Block not safe")
		return nil, &data.NackMsg{HighLockCertificate: wendyEC.GetQCHigh(), Hash: block.Hash()}, fmt.Errorf("Block was not accepted")
	}

	logger.Println("OnReceiveProposal: Accepted block")
	wendyEC.vHeight = block.Height
	wendyEC.cmdCache.MarkProposed(block.Commands...)
	wendyEC.mut.Unlock()

	wendyEC.waitProposal.Broadcast()
	wendyEC.emitEvent(Event{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

	// queue block for update
	wendyEC.pendingUpdates <- block

	pc, err := wendyEC.SigCache.CreatePartialCert(wendyEC.Config.ID, wendyEC.Config.PrivateKey, block)
	if err != nil {
		return nil, nil, err
	}
	return pc, nil, nil
}

// OnReceiveVote handles an incoming vote from a replica
func (wendyEC *FastWendyCoreEC) OnReceiveVote(cert *data.PartialCert) {
	if !wendyEC.SigCache.VerifySignature(cert.Sig, cert.BlockHash) {
		logger.Println("OnReceiveVote: signature not verified!")
		return
	}

	logger.Printf("OnReceiveVote: %.8s\n", cert.BlockHash)
	wendyEC.emitEvent(Event{Type: ReceiveVote, Replica: cert.Sig.ID})

	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()

	qc, ok := wendyEC.pendingQCs[cert.BlockHash]
	if !ok {
		b, ok := wendyEC.expectBlock(cert.BlockHash)
		if !ok {
			logger.Println("OnReceiveVote: could not find block for certificate.")
			return
		}
		if b.Height <= wendyEC.bLeaf.Height {
			// too old, don't care
			return
		}
		// need to check again in case a qc was created while we waited for the block
		qc, ok = wendyEC.pendingQCs[cert.BlockHash]
		if !ok {
			qc = data.CreateQuorumCert(b)
			wendyEC.pendingQCs[cert.BlockHash] = qc
		}
	}

	err := qc.AddPartial(cert)
	if err != nil {
		logger.Println("OnReceiveVote: could not add partial signature to QC:", err)
	}

	if len(qc.Sigs) >= wendyEC.Config.QuorumSize {
		delete(wendyEC.pendingQCs, cert.BlockHash)
		logger.Println("OnReceiveVote: Created QC")
		wendyEC.UpdateQCHigh(qc)
		wendyEC.emitEvent(Event{Type: QCFinish, QC: qc})
	}

	// delete any pending QCs with lower height than bLeaf
	for k := range wendyEC.pendingQCs {
		if b, ok := wendyEC.Blocks.Get(k); ok {
			if b.Height <= wendyEC.bLeaf.Height {
				delete(wendyEC.pendingQCs, k)
			}
		} else {
			delete(wendyEC.pendingQCs, k)
		}
	}
}

// OnReceiveNewView handles the leader's response to receiving a NewView rpc from a replica
func (wendyEC *FastWendyCoreEC) OnReceiveNewView(newViewMsg *data.NewViewMsg) {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	logger.Println("OnReceiveNewView")
	wendyEC.emitEvent(Event{Type: ReceiveNewView, QC: newViewMsg.LockCertificate})
	wendyEC.UpdateQCHigh(newViewMsg.LockCertificate)

	if _, ok := wendyEC.viewChangeMsgs[newViewMsg.Message.V]; ok {
		wendyEC.viewChangeMsgs[newViewMsg.Message.V][newViewMsg.ID] = *newViewMsg
	} else {
		wendyEC.viewChangeMsgs[newViewMsg.Message.V] = make([]data.NewViewMsg, len(wendyEC.Config.Replicas))
	}
}

// OnReceiveNack handles the leader's response to receiving a Nack rpc from a replica
func (wendyEC *FastWendyCoreEC) OnReceiveNack(nackMsg *data.NackMsg) data.ProofNC {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	logger.Println("OnReceiveNack")

	targetView := strconv.FormatInt(int64(wendyEC.GetHeight()), 2)

	var AS data.AggregateSignature
	msgs := wendyEC.viewChangeMsgs[targetView]
	numEntries := len(msgs)

	sigs := make([]bls.Sign, numEntries)
	for i := 0; i < numEntries; i++ {
		sigs[i] = msgs[i].Signature
	}

	aggSig := AS.Agg(sigs)

	pairs := make([]data.KeyAggMessagePair, numEntries)
	for i := 0; i < numEntries; i++ {
		pairs[i] = data.KeyAggMessagePair{PK: wendyEC.Config.Replicas[msgs[i].ID].ProofPubKeys, M: msgs[i].Message}
	}

	proof := data.ProofNC{Messages: pairs, Signature: aggSig, Hash: nackMsg.Hash}
	return proof
}

// OnReceiveProofNC handles the replica's response to receiving a ProofNC rpc from a replica
func (wendyEC *FastWendyCoreEC) OnReceiveProofNC(proof *data.ProofNC) (*data.PartialCert, error) {
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()
	logger.Println("OnReceiveProofNC")

	var AS data.AggregateSignature
	block, _ := wendyEC.expectBlock(proof.Hash)
	if AS.VerifyAgg(proof.Messages, proof.Signature) {
		logger.Println("OnReceiveProofNC: Accepted block")
		wendyEC.vHeight = block.Height
		wendyEC.cmdCache.MarkProposed(block.Commands...)
		wendyEC.mut.Unlock()

		wendyEC.waitProposal.Broadcast()
		wendyEC.emitEvent(Event{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

		// queue block for update
		wendyEC.pendingUpdates <- block

		pc, err := wendyEC.SigCache.CreatePartialCert(wendyEC.Config.ID, wendyEC.Config.PrivateKey, block)
		if err != nil {
			return nil, err
		}
		return pc, nil
	}
	return nil, nil
}

func (wendyEC *FastWendyCoreEC) updateAsync(ctx context.Context) {
	for {
		select {
		case n := <-wendyEC.pendingUpdates:
			wendyEC.update(n)
		case <-ctx.Done():
			return
		}
	}
}

func (wendyEC *FastWendyCoreEC) update(block *data.Block) {
	// block1 = b'', block2 = b', block3 = b

	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()

	block1, ok := wendyEC.Blocks.BlockOf(block.Justify)
	wendyEC.UpdateQCHigh(block.Justify)
	if !ok || block1.Committed {
		return
	}

	if block.ParentHash == block1.Hash() {
		logger.Println("DECIDE", block1)
		wendyEC.commit(block1)
		wendyEC.bExec = block1 // DECIDE on block2
	}

	// Free up space by deleting old data
	wendyEC.Blocks.GarbageCollectBlocks(wendyEC.GetVotedHeight())
	wendyEC.cmdCache.TrimToLen(wendyEC.Config.BatchSize * 5)
	wendyEC.SigCache.EvictOld(wendyEC.Config.QuorumSize * 5)
}

func (wendyEC *FastWendyCoreEC) commit(block *data.Block) {
	// only called from within update. Thus covered by its mutex lock.
	if wendyEC.bExec.Height < block.Height {
		if parent, ok := wendyEC.Blocks.ParentOf(block); ok {
			wendyEC.commit(parent)
		}
		block.Committed = true
		logger.Println("EXEC", block)
		//fmt.Printf("%s\n", block.String())
		wendyEC.exec <- block.Commands
	}
}

// CreateProposal creates a new proposal
func (wendyEC *FastWendyCoreEC) CreateProposal() *data.Block {
	batch := wendyEC.cmdCache.GetFirst(wendyEC.Config.BatchSize)
	wendyEC.mut.Lock()
	b := CreateLeaf(wendyEC.bLeaf, batch, wendyEC.qcHigh, wendyEC.bLeaf.Height+1)
	wendyEC.mut.Unlock()
	b.Proposer = wendyEC.Config.ID
	wendyEC.Blocks.Put(b)
	return b
}

// Close frees resources held by HotStuff and closes backend connections
func (wendyEC *FastWendyCoreEC) Close() {
	wendyEC.cancel()
}

// FastWendyCore is the safety core of the FastWendyCore protocol
/*type FastWendyCore struct {
	mut sync.Mutex

	// Contains the commands that are waiting to be proposed
	cmdCache *data.CommandSet
	Config   *config.ReplicaConfigFastWendy
	Blocks   data.BlockStorageBls
	SigCache *data.SignatureCacheFastWendy

	// protocol data
	vHeight      int
	genesis      *data.BlockBls
	bLock        *data.BlockBls
	bExec        *data.BlockBls
	bLeaf        *data.BlockBls
	qcHigh       *data.QuorumCertBls
	highVote     *data.QuorumCertBls
	highWeakLock *data.QuorumCertBls
	highLock     *data.QuorumCertBls
	pendingQCs   map[data.BlockHash]*data.QuorumCertificateBls

	waitProposal *sync.Cond

	pendingUpdates chan *data.BlockBls

	eventChannels []chan EventBls

	// stops any goroutines started by HotStuff
	cancel context.CancelFunc

	exec chan []data.Command
}

// AddCommand adds a command
func (fwc *FastWendyCore) AddCommand(command data.Command) {
	fwc.cmdCache.Add(command)
}

// GetHeight returns the height of the tree
func (fwc *FastWendyCore) GetHeight() int {
	return fwc.bLeaf.Height
}

// GetVotedHeight returns the height that was last voted at
func (fwc *FastWendyCore) GetVotedHeight() int {
	return fwc.vHeight
}

// GetLeaf returns the current leaf node of the tree
func (fwc *FastWendyCore) GetLeaf() *data.BlockBls {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	return fwc.bLeaf
}

// SetLeaf sets the leaf node of the tree
func (fwc *FastWendyCore) SetLeaf(block *data.BlockBls) {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	fwc.bLeaf = block
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (fwc *FastWendyCore) GetQCHigh() *data.QuorumCertBls {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	return fwc.qcHigh
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (fwc *FastWendyCore) GetHighVote() *data.QuorumCertBls {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	return fwc.highVote
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (fwc *FastWendyCore) GetHighWeakLock() *data.QuorumCertBls {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	return fwc.highWeakLock
}

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (fwc *FastWendyCore) GetHighLock() *data.QuorumCertBls {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	return fwc.highLock
}

func (fwc *FastWendyCore) GetEvents() chan EventBls {
	c := make(chan EventBls)
	fwc.eventChannels = append(fwc.eventChannels, c)
	return c
}

func (fwc *FastWendyCore) GetExec() chan []data.Command {
	return fwc.exec
}

// New creates a new FastWendy instance
func NewFastWendy(conf *config.ReplicaConfigFastWendy) *FastWendyCore {
	logger.SetPrefix(fmt.Sprintf("wc(id %d): ", conf.ID))
	genesis := &data.BlockBls{
		Committed: true,
	}
	qcForGenesis := data.CreateQuorumCertGenisisFastWendy(genesis.Hash(), conf)
	blocks := data.NewMapStorageBls()
	blocks.Put(genesis)

	ctx, cancel := context.WithCancel(context.Background())

	fwc := &FastWendyCore{
		Config:         conf,
		genesis:        genesis,
		bLock:          genesis,
		bExec:          genesis,
		bLeaf:          genesis,
		qcHigh:         qcForGenesis,
		Blocks:         blocks,
		pendingQCs:     make(map[data.BlockHash]*data.QuorumCertificateBls),
		cancel:         cancel,
		SigCache:       data.NewSignatureCacheFastWendy(conf),
		cmdCache:       data.NewCommandSet(),
		pendingUpdates: make(chan *data.BlockBls, 1),
		exec:           make(chan []data.Command, 1),
	}

	fwc.waitProposal = sync.NewCond(&fwc.mut)

	go fwc.updateAsync(ctx)

	return fwc
}

// expectBlock looks for a block with the given Hash, or waits for the next proposal to arrive
// hs.mut must be locked when calling this function
func (fwc *FastWendyCore) expectBlock(hash data.BlockHash) (*data.BlockBls, bool) {
	if block, ok := fwc.Blocks.Get(hash); ok {
		return block, true
	}
	fwc.waitProposal.Wait()
	return fwc.Blocks.Get(hash)
}

func (fwc *FastWendyCore) emitEvent(event EventBls) {
	for _, c := range fwc.eventChannels {
		c <- event
	}
}

// UpdateQCHigh updates the qc held by the paceMaker, to the newest qc.
func (fwc *FastWendyCore) UpdateQCHigh(qc *data.QuorumCertBls) bool {
	if !fwc.SigCache.VerifyQuorumCertBls(qc) {
		logger.Println("QC not verified!:", qc)
		return false
	}

	logger.Println("UpdateQCHigh")

	newQCHighBlock, ok := fwc.expectBlock(qc.BlockHash)
	if !ok {
		logger.Println("Could not find block of new QC!")
		return false
	}

	oldQCHighBlock, ok := fwc.Blocks.BlockOf(fwc.qcHigh)
	if !ok {
		panic(fmt.Errorf("Block from the old qcHigh missing from storage"))
	}

	if newQCHighBlock.Height > oldQCHighBlock.Height {
		fwc.qcHigh = qc
		fwc.bLeaf = newQCHighBlock
		fwc.emitEvent(EventBls{Type: HQCUpdate, QC: fwc.qcHigh, Block: fwc.bLeaf})
		return true
	}

	logger.Println("UpdateQCHigh Failed")
	return false
}*/

/*
genesis -> block1 -> block2a | qc -> block3 | qc means block1 is committed
				  -> block2b | fast commit-cert means block1 is committed
f+1 votes in view change weak qc

optimistic case - fast path succeeds, leader assembles a fast commit certificate and attaches it to a new proposal, when a replica receives
the proposal it executes the fast commit certificate and votes on the proposal without needing to verify proofs/unlock/lock
the reason is that the fast commit certificate indicates the end of the view
for safety replica needs to check whether block extends the highest fast commit certificate
1 -> 2 -> 3 FCC
  -> 4 -> 5 FCC

pesimisstic case - 1) fast path fails and slow path succeeds, leader assembles a slow quorum certificate and attahces it to a new proposal
after a 2-chain can commit
2) fast path fails and slow path fails, leader attaches highest Lock and Weak lock and proofs to the new proposal

design fast blocks and slow blocks
pipeline
FastQC begins Decide phase for previous block and Pre-Prepare phase for current block
when a slow block (containing a normal QC) follows a fast block then the pipeline breaks - this slow QC begins the Lock phase of the previous
block and the Pre-Prepare phase of the current block, a fast block after begins the Decide phase of the previous previous block, the
Decide phase of the previous block, and Pre-Prepare phase of the current block
if instead a slow block follows then that begins the Decide phase of the previous previous block, the Lock phase of the previous block, and the
Pre-Prepare phase of the current block

for fast block safety follows from just voting on proposal with highest view
for slow block need to compute bit vectors and aggregate signatures etc. verify proofs

*/
// OnReceiveProposal handles a replica's response to the Proposal from the leader
/*func (fwc *FastWendyCore) OnReceiveProposal(block *data.BlockFastWendy) (*data.PartialCertBls, error) {
	logger.Println("OnReceiveProposal:", block)
	fwc.Blocks.Put(block)

	fwc.mut.Lock()
	qcBlock, nExists := fwc.expectBlock(block.Justify.BlockHash)
	highLockBlock, existsHL := fwc.expectBlock(fwc.highLock.BlockHash)
	highWeakLockBlock, existsWL := fwc.expectBlock(fwc.highWeakLock.BlockHash)

	if block.Height <= fwc.vHeight {
		fwc.mut.Unlock()
		logger.Println("OnReceiveProposal: Block height less than vHeight")
		return nil, fmt.Errorf("Block was not accepted")
	}

	locked := true
	weakLocked := true

	if !existsHL || (nExists && qcBlock.Height > highLockBlock.Height) {
		locked = false
	}

	if !existsWL || (nExists && qcBlock.Height > highWeakLockBlock.Height) {
		weakLocked = false
	}

	// if lock is higher than the qc check if qc is for the same value
	if locked {
		b := block
		// check if block extends highLockBlock
		ok := true
		for ok && b.Height > highLockBlock.Height+1 {
			b, ok = fwc.Blocks.Get(b.ParentHash)
		}

		if ok && b.ParentHash == fwc.bLock.Hash() {
			locked = false
		}
	}

	// if weak lock is higher than the qc chek if qc is for the same value
	if weakLocked {
		b := block
		// check if block extends highLockBlock/highWeakBlock
		ok := true
		for ok && b.Height > highWeakLockBlock.Height+1 {
			b, ok = fwc.Blocks.Get(b.ParentHash)
		}

		if ok && b.ParentHash == fwc.bLock.Hash() {
			weakLocked = false
		}
	}

	safe := false
	if !locked && !weakLocked {
		safe = true
	} else {
		// check proof of no commit for locks
		if locked {

		}

		// check proof of no commit for weak locks
		if weakLocked {

		}
	}

	if !safe {
		fwc.mut.Unlock()
		logger.Println("OnReceiveProposal: Block not safe")
		return nil, fmt.Errorf("Block was not accepted")
	}

	logger.Println("OnReceiveProposal: Accepted block")
	fwc.vHeight = block.Height
	fwc.cmdCache.MarkProposed(block.Commands...)
	fwc.mut.Unlock()

	fwc.waitProposal.Broadcast()
	fwc.emitEvent(EventBls{Type: ReceiveProposal, Block: block, Replica: block.Proposer})

	// queue block for update
	fwc.pendingUpdates <- block

	pc, err := fwc.SigCache.CreatePartialCertBls(fwc.Config.ID, fwc.Config.PrivateKey, block)
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// OnReceiveVote handles an incoming vote from a replica
func (fwc *FastWendyCore) OnReceiveVote(cert *data.PartialCertBls) {
	if !fwc.SigCache.VerifySignatureBls(cert.Sig, cert.BlockHash) {
		logger.Println("OnReceiveVote: signature not verified!")
		return
	}

	logger.Printf("OnReceiveVote: %.8s\n", cert.BlockHash)
	fwc.emitEvent(EventBls{Type: ReceiveVote, Replica: cert.Sig.ID})

	fwc.mut.Lock()
	defer fwc.mut.Unlock()

	qc, ok := fwc.pendingQCs[cert.BlockHash]
	if !ok {
		b, ok := fwc.expectBlock(cert.BlockHash)
		if !ok {
			logger.Println("OnReceiveVote: could not find block for certificate.")
			return
		}
		if b.Height <= fwc.bLeaf.Height {
			// too old, don't care
			return
		}
		// need to check again in case a qc was created while we waited for the block
		qc, ok = fwc.pendingQCs[cert.BlockHash]
		if !ok {
			qc = data.CreateQuorumCertificateBls(b, fwc.Config.N)
			fwc.pendingQCs[cert.BlockHash] = qc
		}
	}

	err := qc.AddPartialBls(cert)
	if err != nil {
		logger.Println("OnReceiveVote: could not add partial signature to QC:", err)
	}

	if len(qc.Sigs) >= fwc.Config.QuorumSize {
		delete(fwc.pendingQCs, cert.BlockHash)
		logger.Println("OnReceiveVote: Created QC")
		qCert := data.CreateQuorumCertBls(cert.BlockHash, qc)
		fwc.UpdateQCHigh(qCert)
		fwc.emitEvent(EventBls{Type: QCFinish, QC: qCert})
	}

	// delete any pending QCs with lower height than bLeaf
	for k := range fwc.pendingQCs {
		if b, ok := fwc.Blocks.Get(k); ok {
			if b.Height <= fwc.bLeaf.Height {
				delete(fwc.pendingQCs, k)
			}
		} else {
			delete(fwc.pendingQCs, k)
		}
	}
}

// OnReceiveNewView handles the leader's response to receiving a NewView rpc from a replica
func (fwc *FastWendyCore) OnReceiveNewView(qc *data.QuorumCertBls) {
	fwc.mut.Lock()
	defer fwc.mut.Unlock()
	logger.Println("OnReceiveNewView")
	fwc.emitEvent(EventBls{Type: ReceiveNewView, QC: qc})
	fwc.UpdateQCHigh(qc)
}

func (fwc *FastWendyCore) updateAsync(ctx context.Context) {
	for {
		select {
		case n := <-fwc.pendingUpdates:
			fwc.update(n)
		case <-ctx.Done():
			return
		}
	}
}

func (fwc *FastWendyCore) update(block *data.BlockBls) {
	// block1 = b'', block2 = b', block3 = b
	block1, ok := fwc.Blocks.BlockOf(block.Justify)
	if !ok || block1.Committed {
		return
	}

	fwc.mut.Lock()
	defer fwc.mut.Unlock()

	logger.Println("LOCK:", block1)
	// Lock on block1
	fwc.UpdateQCHigh(block.Justify)

	if !ok || block1.Committed {
		return
	}

	if block1.Height > fwc.bLock.Height {
		fwc.bLock = block1 // LOCK on block1
		logger.Println("LOCK:", block1)
	}

	block2, ok := fwc.Blocks.BlockOf(block1.Justify)

	//block3, ok := wc.Blocks.BlockOf(block2.Justify)
	if !ok || block2.Committed {
		return
	}

	if block.ParentHash == block1.Hash() && block1.ParentHash == block2.Hash() {
		logger.Println("DECIDE", block2)
		fwc.commit(block2)
		fwc.bExec = block2 // DECIDE on block2
	}

	// Free up space by deleting old data
	fwc.Blocks.GarbageCollectBlocks(fwc.GetVotedHeight())
	fwc.cmdCache.TrimToLen(fwc.Config.BatchSize * 5)
	fwc.SigCache.EvictOld(fwc.Config.QuorumSize * 5)
}

func (fwc *FastWendyCore) commit(block *data.BlockBls) {
	// only called from within update. Thus covered by its mutex lock.
	if fwc.bExec.Height < block.Height {
		if parent, ok := fwc.Blocks.ParentOf(block); ok {
			fwc.commit(parent)
		}
		block.Committed = true
		logger.Println("EXEC", block)
		fwc.exec <- block.Commands
	}
}

// CreateProposal creates a new proposal
func (fwc *FastWendyCore) CreateProposal() *data.BlockBls {
	batch := fwc.cmdCache.GetFirst(fwc.Config.BatchSize)
	fwc.mut.Lock()
	b := CreateLeafBls(fwc.bLeaf, batch, fwc.qcHigh, fwc.bLeaf.Height+1)
	fwc.mut.Unlock()
	b.Proposer = fwc.Config.ID
	fwc.Blocks.Put(b)
	return b
}

// Close frees resources held by HotStuff and closes backend connections
func (fwc *FastWendyCore) Close() {
	fwc.cancel()
}*/

// CreateLeaf returns a new block that extends the parent.
/*func CreateLeafBls(parent *data.BlockBls, cmds []data.Command, qc *data.QuorumCertBls, height int) *data.BlockBls {
	return &data.BlockBls{
		ParentHash: parent.Hash(),
		Commands:   cmds,
		Justify:    qc,
		Height:     height,
	}
}*/
