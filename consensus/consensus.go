package consensus

import (
	"context"
	"fmt"
	"log"
	"sync"

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

// Event is sent to the pacemaker to allow it to observe the protocol.
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

func (hs *HotStuffCore) GetEvents() chan Event {
	c := make(chan Event)
	hs.eventChannels = append(hs.eventChannels, c)
	return c
}

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
	pendingQCs map[data.BlockHash]*data.QuorumCertificateBls

	waitProposal *sync.Cond

	pendingUpdates chan *data.BlockBls

	eventChannels []chan EventBls

	// stops any goroutines started by HotStuff
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

// GetQCHigh returns the highest valid Quorum Certificate known to the hotstuff instance.
func (wc *WendyCore) GetQCHigh() *data.QuorumCertBls {
	wc.mut.Lock()
	defer wc.mut.Unlock()
	return wc.qcHigh
}

func (wc *WendyCore) GetEvents() chan EventBls {
	c := make(chan EventBls)
	wc.eventChannels = append(wc.eventChannels, c)
	return c
}

func (wc *WendyCore) GetExec() chan []data.Command {
	return wc.exec
}

// New creates a new Wendy instance
func NewWendy(conf *config.ReplicaConfigBls) *WendyCore {
	logger.SetPrefix(fmt.Sprintf("wc(id %d): ", conf.ID))
	genesis := &data.BlockBls{
		Committed: true,
	}
	qcForGenesis := data.CreateQuorumCertGenisis(genesis.Hash(), conf)
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
		pendingQCs:     make(map[data.BlockHash]*data.QuorumCertificateBls),
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
// hs.mut must be locked when calling this function
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
			qc = data.CreateQuorumCertificateBls(b, wc.Config.N)
			wc.pendingQCs[cert.BlockHash] = qc
		}
	}

	err := qc.AddPartialBls(cert)
	if err != nil {
		logger.Println("OnReceiveVote: could not add partial signature to QC:", err)
	}

	if len(qc.Sigs) >= wc.Config.QuorumSize {
		delete(wc.pendingQCs, cert.BlockHash)
		logger.Println("OnReceiveVote: Created QC")
		qCert := data.CreateQuorumCertBls(cert.BlockHash, qc)
		wc.UpdateQCHigh(qCert)
		wc.emitEvent(EventBls{Type: QCFinish, QC: qCert})
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

	//block3, ok := wc.Blocks.BlockOf(block2.Justify)
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

// CreateLeaf returns a new block that extends the parent.
func CreateLeafBls(parent *data.BlockBls, cmds []data.Command, qc *data.QuorumCertBls, height int) *data.BlockBls {
	return &data.BlockBls{
		ParentHash: parent.Hash(),
		Commands:   cmds,
		Justify:    qc,
		Height:     height,
	}
}
