package consensus

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"

	. "github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
	. "github.com/relab/hotstuff/data"
)

/* func TestSafeNode(t *testing.T) {
	key, _ := GeneratePrivateKey()
	hs := New(1, key, NewConfig(), &stubBackend{}, 10*time.Millisecond, nil)

	n1 := CreateLeaf(hs.genesis, []Command{Command("n1")}, hs.qcHigh, hs.genesis.Height+1)
	hs.nodes.Put(n1)
	n2 := CreateLeaf(n1, []Command{Command("n2")}, CreateQuorumCert(n1), n1.Height+1)
	hs.nodes.Put(n2)

	if !hs.safeNode(n2) {
		t.Error("SafeNode rejected node, but both rules should have passed it.")
	}

	hs.bLock = n2

	n3 := CreateLeaf(n1, []Command{Command("n3")}, CreateQuorumCert(n1), n2.Height+1)
	hs.nodes.Put(n3)
	n4 := CreateLeaf(n3, []Command{Command("n4")}, CreateQuorumCert(n3), n3.Height+1)
	hs.nodes.Put(n4)

	if !hs.safeNode(n4) {
		t.Error("SafeNode rejected node, but liveness rule should have passed it.")
	}

	n5 := CreateLeaf(n2, []Command{Command("n5")}, CreateQuorumCert(n2), n2.Height+1)
	hs.nodes.Put(n5)
	n6 := CreateLeaf(n5, []Command{Command("n6")}, CreateQuorumCert(n5), n5.Height+1)
	hs.nodes.Put(n6)
	// intentionally violates liveness rule
	n7 := CreateLeaf(n6, []Command{Command("n7")}, CreateQuorumCert(n6), 1)
	hs.nodes.Put(n7)

	if !hs.safeNode(n7) {
		t.Error("SafeNode rejected node, but safety rule should have passed it.")
	}

	bad := CreateLeaf(hs.genesis, []Command{Command("bad")}, CreateQuorumCert(hs.genesis), hs.genesis.Height+1)
	hs.nodes.Put(bad)

	if hs.safeNode(bad) {
		t.Error("SafeNode accepted node, but none of the rules should have passed it.")
	}
} */

func TestUpdateQCHigh(t *testing.T) {
	key, _ := GeneratePrivateKey()
	hs := New(NewConfig(1, key, nil))
	block1 := CreateLeaf(hs.genesis, []Command{Command("command1")}, hs.qcHigh, hs.genesis.Height+1)
	hs.Blocks.Put(block1)
	qc1 := CreateQuorumCert(block1)

	if hs.UpdateQCHigh(qc1) {
		if hs.bLeaf.Hash() != block1.Hash() {
			t.Error("UpdateQCHigh failed to update the leaf block")
		}
		if !bytes.Equal(hs.qcHigh.ToBytes(), qc1.ToBytes()) {
			t.Error("UpdateQCHigh failed to update qcHigh")
		}

	} else {
		t.Error("UpdateQCHigh failed to complete")
	}

	block2 := CreateLeaf(block1, []Command{Command("command2")}, qc1, block1.Height+1)
	hs.Blocks.Put(block2)
	qc2 := CreateQuorumCert(block2)
	hs.UpdateQCHigh(qc2)

	if hs.UpdateQCHigh(qc1) {
		t.Error("UpdateQCHigh updated with outdated state given as input.")
	}
}

func TestUpdateQCHighWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewWendyEC(NewConfigWendy(1, key, nil))
	block1 := CreateLeaf(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	wendy.Blocks.Put(block1)
	qc1 := CreateQuorumCert(block1)

	if wendy.UpdateQCHigh(qc1) {
		if wendy.bLeaf.Hash() != block1.Hash() {
			t.Error("UpdateQCHigh failed to update the leaf block")
		}
		if !bytes.Equal(wendy.qcHigh.ToBytes(), qc1.ToBytes()) {
			t.Error("UpdateQCHigh failed to update qcHigh")
		}

	} else {
		t.Error("UpdateQCHigh failed to complete")
	}

	block2 := CreateLeaf(block1, []Command{Command("command2")}, qc1, block1.Height+1)
	wendy.Blocks.Put(block2)
	qc2 := CreateQuorumCert(block2)
	wendy.UpdateQCHigh(qc2)

	if wendy.UpdateQCHigh(qc1) {
		t.Error("UpdateQCHigh updated with outdated state given as input.")
	}
}

func TestUpdateQCHighFastWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewFastWendyEC(NewConfigFastWendy(1, key, nil))
	block1 := CreateLeafFastWendy(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	wendy.Blocks.Put(block1)
	qc1 := CreateQuorumCertFastWendy(block1)
	wendy.Config.FastQuorumSize = 0

	if wendy.UpdateQCHigh(qc1, 0) {
		if wendy.bLeaf.Hash() != block1.Hash() {
			t.Error("UpdateQCHigh failed to update the leaf block")
		}
		if !bytes.Equal(wendy.qcHigh.ToBytes(), qc1.ToBytes()) {
			t.Error("UpdateQCHigh failed to update qcHigh")
		}

	} else {
		t.Error("UpdateQCHigh failed to complete")
	}

	block2 := CreateLeafFastWendy(block1, []Command{Command("command2")}, qc1, block1.Height+1)
	wendy.Blocks.Put(block2)
	qc2 := CreateQuorumCertFastWendy(block2)
	wendy.UpdateQCHigh(qc2, 0)

	if wendy.UpdateQCHigh(qc1, 0) {
		t.Error("UpdateQCHigh updated with outdated state given as input.")
	}
}

func TestUpdate(t *testing.T) {
	key, _ := GeneratePrivateKey()
	hs := New(NewConfig(1, key, nil))
	hs.Config.QuorumSize = 0 // this accepts all QCs

	n1 := CreateLeaf(hs.genesis, []Command{Command("n1")}, hs.qcHigh, hs.genesis.Height+1)
	hs.Blocks.Put(n1)
	n2 := CreateLeaf(n1, []Command{Command("n2")}, CreateQuorumCert(n1), n1.Height+1)
	hs.Blocks.Put(n2)
	n3 := CreateLeaf(n2, []Command{Command("n3")}, CreateQuorumCert(n2), n2.Height+1)
	hs.Blocks.Put(n3)
	n4 := CreateLeaf(n3, []Command{Command("n4")}, CreateQuorumCert(n3), n3.Height+1)
	hs.Blocks.Put(n4)

	// PROPOSE on n1
	hs.update(n1)

	// PRECOMMIT on n1, PROPOSE on n2
	hs.update(n2)
	// check that QCHigh and bLeaf updated
	if hs.bLeaf != n1 || hs.qcHigh != n2.Justify {
		t.Error("PRECOMMIT failed")
	}

	// COMMIT on n1, PRECOMMIT on n2, PROPOSE on n3
	hs.update(n3)
	// check that bLock got updated
	if hs.bLock != n1 {
		t.Error("COMMIT failed")
	}

	// DECIDE on n1, COMMIT on n2, PRECOMIT on n3, PROPOSE on n4
	hs.update(n4)
	// check that bExec got updated and n1 got executed
	success := true
	if hs.bExec != n1 {
		success = false
	}

	select {
	case b := <-hs.GetExec():
		if b[0] != n1.Commands[0] {
			success = false
		}
	case <-time.After(time.Second):
		success = false
	}

	if !success {
		t.Error("DECIDE failed")
	}
}

func TestUpdateWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewWendyEC(NewConfigWendy(1, key, nil))
	wendy.Config.QuorumSize = 0 // this accepts all QCs

	n1 := CreateLeaf(wendy.genesis, []Command{Command("n1")}, wendy.qcHigh, wendy.genesis.Height+1)
	wendy.Blocks.Put(n1)
	n2 := CreateLeaf(n1, []Command{Command("n2")}, CreateQuorumCert(n1), n1.Height+1)
	wendy.Blocks.Put(n2)
	n3 := CreateLeaf(n2, []Command{Command("n3")}, CreateQuorumCert(n2), n2.Height+1)
	wendy.Blocks.Put(n3)
	n4 := CreateLeaf(n3, []Command{Command("n4")}, CreateQuorumCert(n3), n3.Height+1)
	wendy.Blocks.Put(n4)

	// Prepare on n1
	wendy.update(n1)

	// Lock on n1, Prepare on n2
	wendy.update(n2)
	// check that QCHigh and bLeaf updated
	if wendy.bLeaf != n1 || wendy.qcHigh != n2.Justify {
		t.Error("Lock failed")
	}

	// Decide on n1, Lock on n2, Prepare on n3
	wendy.update(n3)
	// check that bLock got updated
	if wendy.bLock != n2 {
		t.Error("Lock failed")
	}

	// check that bExec got updated and n1 got executed
	success := true
	if wendy.bExec != n1 {
		success = false
	}

	select {
	case b := <-wendy.GetExec():
		if b[0] != n1.Commands[0] {
			success = false
		}
	case <-time.After(time.Second):
		success = false
	}

	if !success {
		t.Error("DECIDE failed")
	}

	// DECIDE on n2, Lock on n3, Prepare on n4
	wendy.update(n4)
	success = true
	if wendy.bExec != n2 {
		success = false
	}

	select {
	case b := <-wendy.GetExec():
		if b[0] != n2.Commands[0] {
			success = false
		}
	case <-time.After(time.Second):
		success = false
	}

	if !success {
		t.Error("DECIDE failed")
	}
}

func TestUpdateFastWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewFastWendyEC(NewConfigFastWendy(1, key, nil))
	wendy.Config.QuorumSize = -1 // this accepts all QCs
	wendy.Config.FastQuorumSize = 0

	n1 := CreateLeafFastWendy(wendy.genesis, []Command{Command("n1")}, wendy.qcHigh, wendy.genesis.Height+1)
	wendy.Blocks.Put(n1)
	n2 := CreateLeafFastWendy(n1, []Command{Command("n2")}, CreateQuorumCertFastWendy(n1), n1.Height+1)
	wendy.Blocks.Put(n2)
	n3 := CreateLeafFastWendy(n2, []Command{Command("n3")}, CreateQuorumCertFastWendy(n2), n2.Height+1)
	wendy.Blocks.Put(n3)
	n4 := CreateLeafFastWendy(n3, []Command{Command("n4")}, CreateQuorumCertFastWendy(n3), n3.Height+1)
	wendy.Blocks.Put(n4)

	// Prepare on n1
	wendy.update(n1)

	// Decide on n1, Prepare on n2
	wendy.update(n2)

	// check that QCHigh and bLeaf updated
	if wendy.bLeaf != n1 || wendy.qcHigh != n2.Justify {
		t.Error("bLeaf and QC high failed")
	}

	// Decide on n1, Lock on n2, Prepare on n3
	//wendy.update(n3)
	// check that bLock got updated
	//if wendy.bLock != n2 {
	//t.Error("Lock failed")
	//}

	// check that bExec got updated and n1 got executed
	success := true
	if wendy.bExec != n1 {
		success = false
	}

	select {
	case b := <-wendy.GetExec():
		if b[0] != n1.Commands[0] {
			success = false
		}
	case <-time.After(time.Second):
		success = false
	}

	if !success {
		t.Error("DECIDE failed")
	}

	// DECIDE on n2, Lock on n3, Prepare on n4
	wendy.update(n3)
	success = true
	if wendy.bExec != n2 {
		success = false
	}

	select {
	case b := <-wendy.GetExec():
		if b[0] != n2.Commands[0] {
			success = false
		}
	case <-time.After(time.Second):
		success = false
	}

	if !success {
		t.Error("DECIDE failed")
	}
}

func TestOnReciveProposal(t *testing.T) {
	key, _ := GeneratePrivateKey()
	hs := New(NewConfig(1, key, nil))
	block1 := CreateLeaf(hs.genesis, []Command{Command("command1")}, hs.qcHigh, hs.genesis.Height+1)
	qc := CreateQuorumCert(block1)

	pc, err := hs.OnReceiveProposal(block1)

	if err != nil {
		t.Errorf("onReciveProposal failed with error: %w", err)
	}

	if pc == nil {
		t.Error("onReciveProposal failed to complete")
	} else {
		if _, ok := hs.Blocks.Get(block1.Hash()); !ok {
			t.Error("onReciveProposal failed to place the new block in BlockStorage")
		}
		if hs.vHeight != block1.Height {
			t.Error("onReciveProposal failed to update the heigt of the replica")
		}
	}

	block2 := CreateLeaf(block1, []Command{Command("command2")}, qc, block1.Height+1)

	hs.OnReceiveProposal(block2)
	pc, err = hs.OnReceiveProposal(block1)

	if err == nil {
		t.Error("Block got accepted, expected rejection.")
	}
	if pc != nil {
		t.Errorf("Expected nil got: %v", pc)
	}
}

func TestOnReciveProposalWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewWendyEC(NewConfigWendy(1, key, nil))
	block1 := CreateLeaf(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	qc := CreateQuorumCert(block1)

	pc, _, err := wendy.OnReceiveProposal(block1)

	if err != nil {
		t.Errorf("onReciveProposal failed with error: %w", err)
	}

	if pc == nil {
		t.Error("onReciveProposal failed to complete")
	} else {
		if _, ok := wendy.Blocks.Get(block1.Hash()); !ok {
			t.Error("onReciveProposal failed to place the new block in BlockStorage")
		}
		if wendy.vHeight != block1.Height {
			t.Error("onReciveProposal failed to update the heigt of the replica")
		}
	}

	block2 := CreateLeaf(block1, []Command{Command("command2")}, qc, block1.Height+1)

	wendy.OnReceiveProposal(block2)
	pc, _, err = wendy.OnReceiveProposal(block1)

	if err == nil {
		t.Error("Block got accepted, expected rejection.")
	}
	if pc != nil {
		t.Errorf("Expected nil got: %v", pc)
	}
}

func TestOnReciveProposalFastWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewFastWendyEC(NewConfigFastWendy(1, key, nil))
	block1 := CreateLeafFastWendy(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	qc := CreateQuorumCertFastWendy(block1)

	pc, _, err := wendy.OnReceiveProposal(block1)

	if err != nil {
		t.Errorf("onReciveProposal failed with error: %w", err)
	}

	if pc == nil {
		t.Error("onReciveProposal failed to complete")
	} else {
		if _, ok := wendy.Blocks.Get(block1.Hash()); !ok {
			t.Error("onReciveProposal failed to place the new block in BlockStorage")
		}
		if wendy.vHeight != block1.Height {
			t.Error("onReciveProposal failed to update the heigt of the replica")
		}
	}

	block2 := CreateLeafFastWendy(block1, []Command{Command("command2")}, qc, block1.Height+1)

	wendy.OnReceiveProposal(block2)
	pc, _, err = wendy.OnReceiveProposal(block1)

	if err == nil {
		t.Error("Block got accepted, expected rejection.")
	}
	if pc != nil {
		t.Errorf("Expected nil got: %v", pc)
	}
}

func TestExpectBlock(t *testing.T) {
	key, _ := GeneratePrivateKey()
	hs := New(NewConfig(1, key, nil))
	block := CreateLeaf(hs.genesis, []Command{Command("test")}, hs.qcHigh, 1)
	qc := CreateQuorumCert(block)

	go func() {
		time.Sleep(100 * time.Millisecond)
		hs.OnReceiveProposal(block)
	}()

	hs.mut.Lock()
	n, ok := hs.expectBlock(qc.BlockHash)
	hs.mut.Unlock()

	if !ok && n == nil {
		t.Fail()
	}
}

func TestExpectBlockWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewWendyEC(NewConfigWendy(1, key, nil))
	block := CreateLeaf(wendy.genesis, []Command{Command("test")}, wendy.qcHigh, 1)
	qc := CreateQuorumCert(block)

	go func() {
		time.Sleep(100 * time.Millisecond)
		wendy.OnReceiveProposal(block)
	}()

	wendy.mut.Lock()
	n, ok := wendy.expectBlock(qc.BlockHash)
	wendy.mut.Unlock()

	if !ok && n == nil {
		t.Fail()
	}
}

func TestExpectBlockFastWendyEC(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewFastWendyEC(NewConfigFastWendy(1, key, nil))
	block := CreateLeafFastWendy(wendy.genesis, []Command{Command("test")}, wendy.qcHigh, 1)
	qc := CreateQuorumCertFastWendy(block)

	go func() {
		time.Sleep(100 * time.Millisecond)
		wendy.OnReceiveProposal(block)
	}()

	wendy.mut.Lock()
	n, ok := wendy.expectBlock(qc.BlockHash)
	wendy.mut.Unlock()

	if !ok && n == nil {
		t.Fail()
	}
}

func TestOnReciveProposalWendyECNack(t *testing.T) {
	key, _ := GeneratePrivateKey()
	wendy := NewWendyEC(NewConfigWendy(1, key, nil))
	block1 := CreateLeaf(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	block11 := CreateLeaf(wendy.genesis, []Command{Command("command11")}, wendy.qcHigh, wendy.genesis.Height+1)
	qc := CreateQuorumCert(block1)
	block2 := CreateLeaf(block11, []Command{Command("command2")}, qc, block11.Height+1)
	qc2 := CreateQuorumCert(block2)
	wendy.qcHigh = qc2
	wendy.bLock = block2

	_, nack, _ := wendy.OnReceiveProposal(block1)

	if nack == nil {
		t.Error("Block got accepted, expected rejection.")
	}
}

func TestOnReciveViewChangeWendyECNack(t *testing.T) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	key, _ := GeneratePrivateKey()
	cfg := NewConfigWendy(1, key, nil)
	cfg.QuorumSize = 0

	numKeys := 4
	secretKeys := make([]bls.SecretKey, numKeys)
	secretKeys2 := make([]bls.SecretKey, numKeys)
	publicKeys := make([]bls.PublicKey, numKeys)
	publicKeys2 := make([]bls.PublicKey, numKeys)

	for i := 0; i < numKeys; i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG()
		pk := sk.GetPublicKey()
		secretKeys[i] = sk
		publicKeys[i] = *pk

		var sk2 bls.SecretKey
		sk2.SetByCSPRNG()
		pk2 := sk2.GetPublicKey()
		secretKeys2[i] = sk2
		publicKeys2[i] = *pk2
	}

	cfg.Replicas[1] = &ReplicaInfoWendy{ID: 1,
		Address:      "123",
		PubKey:       &key.PublicKey,
		ProofPubKeys: publicKeys}
	cfg.Replicas[2] = &ReplicaInfoWendy{ID: 2,
		Address:      "124",
		PubKey:       &key.PublicKey,
		ProofPubKeys: publicKeys2}

	wendy := NewWendyEC(cfg)
	block1 := CreateLeaf(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	//wendy.OnReceiveProposal(block1)
	wendy.Blocks.Put(block1)

	block11 := CreateLeaf(wendy.genesis, []Command{Command("command11")}, wendy.qcHigh, wendy.genesis.Height+1)
	//wendy.OnReceiveProposal(block11)
	qc := CreateQuorumCert(block1)
	block2 := CreateLeaf(block11, []Command{Command("command2")}, qc, block11.Height+1)
	//wendy.OnReceiveProposal(block2)
	wendy.Blocks.Put(block11)
	wendy.Blocks.Put(block2)
	qc2 := CreateQuorumCert(block2)
	wendy.qcHigh = qc2
	wendy.bLock = block2

	var AS AggregateSignature

	targetView := block1.Height + 1

	//aggMessage1 := AggMessage{C: strconv.FormatInt(int64(targetView-wendy.genesis.Height), 2), V: strconv.FormatInt(int64(targetView), 2)}
	aggMessage2 := AggMessage{C: strconv.FormatInt(int64(targetView-1), 2), V: strconv.FormatInt(int64(targetView), 2)}

	newView1 := NewViewMsg{LockCertificate: qc,
		Message: aggMessage2, Signature: AS.SignShare(secretKeys, aggMessage2), ID: 1}
	newView2 := NewViewMsg{LockCertificate: qc,
		Message: aggMessage2, Signature: AS.SignShare(secretKeys2, aggMessage2), ID: 2}

	wendy.OnReceiveNewView(&newView1)
	wendy.OnReceiveNewView(&newView2)

	_, nack, _ := wendy.OnReceiveProposal(block1)

	if nack == nil {
		t.Error("Block got accepted, expected rejection.")
	}

	wendy.bLeaf = CreateLeaf(block1, []Command{Command("commandnewheight")}, qc, block1.Height+1)
	//t.Error(wendy.viewChangeMsgs[strconv.FormatInt(int64(targetView), 2)][2].Message)
	proofNC := wendy.OnReceiveNack(nack)
	pc, err := wendy.OnReceiveProofNC(&proofNC)

	if pc == nil && err != nil {
		t.Error("Expected proofNC to be accepted")
	}
	wendy.OnReceiveVote(pc)
}

func TestCheckViewChangeFastWendyEC(t *testing.T) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	key, _ := GeneratePrivateKey()
	cfg := NewConfigFastWendy(1, key, nil)
	cfg.QuorumSize = 0
	cfg.BatchSize = 1

	numKeys := 4
	secretKeys := make([]bls.SecretKey, numKeys)
	secretKeys2 := make([]bls.SecretKey, numKeys)
	publicKeys := make([]bls.PublicKey, numKeys)
	publicKeys2 := make([]bls.PublicKey, numKeys)

	for i := 0; i < numKeys; i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG()
		pk := sk.GetPublicKey()
		secretKeys[i] = sk
		publicKeys[i] = *pk

		var sk2 bls.SecretKey
		sk2.SetByCSPRNG()
		pk2 := sk2.GetPublicKey()
		secretKeys2[i] = sk2
		publicKeys2[i] = *pk2
	}

	cfg.Replicas[1] = &ReplicaInfoWendy{ID: 1,
		Address:      "123",
		PubKey:       &key.PublicKey,
		ProofPubKeys: publicKeys}
	cfg.Replicas[2] = &ReplicaInfoWendy{ID: 2,
		Address:      "124",
		PubKey:       &key.PublicKey,
		ProofPubKeys: publicKeys2}

	wendy := NewFastWendyEC(cfg)
	block1 := CreateLeafFastWendy(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	wendy.Blocks.Put(block1)
	qcBlock1 := CreateQuorumCertFastWendy(block1)
	wendy.OnReceiveProposal(block1)

	block2 := CreateLeafFastWendy(block1, nil, nil, block1.Height+1)
	wendy.Blocks.Put(block2)
	var AS data.AggregateSignature

	msg := data.AggMessage{C: strconv.FormatInt(2, 2), V: strconv.FormatInt(int64(block2.Height+1), 2)}
	sig := AS.SignShare(secretKeys, msg)

	weakLock := CreateQuorumCertFastWendy(block1)
	vote, _ := CreatePartialCertFastWendy(1, key, block1)
	msg1 := data.AggMessage{C: strconv.FormatInt(2, 2), V: strconv.FormatInt(int64(block2.Height+1), 2)}
	sig1 := AS.SignShare(secretKeys, msg1)

	newViewMsg := data.NewViewMsgFastWendy{LockCertificate: qcBlock1, Message: msg, Signature: sig, ID: 1,
		WeakLockCertificate: weakLock, MessageWeakLock: msg1, SignatureWeakLock: sig1, Vote: vote}
	wendy.viewChangeMsgs[strconv.FormatInt(int64(block2.Height+1), 2)] = make([]NewViewMsgFastWendy, 1)
	wendy.viewChangeMsgs[strconv.FormatInt(int64(block2.Height+1), 2)][0] = newViewMsg

	wendy.cmdCache.Add(Command("command3"))
	wendy.bLeaf = block2
	block3 := wendy.CreateProposal()
	wendy.Blocks.Put(block3)

	if !wendy.CheckViewChange(block3) {
		t.Errorf("Check VC failed")
	}
}
func TestCheckViewChange2FastWendyEC(t *testing.T) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	key, _ := GeneratePrivateKey()
	cfg := NewConfigFastWendy(1, key, nil)
	cfg.QuorumSize = 0
	cfg.BatchSize = 1

	numKeys := 4
	secretKeys := make([]bls.SecretKey, numKeys)
	secretKeys2 := make([]bls.SecretKey, numKeys)
	publicKeys := make([]bls.PublicKey, numKeys)
	publicKeys2 := make([]bls.PublicKey, numKeys)

	for i := 0; i < numKeys; i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG()
		pk := sk.GetPublicKey()
		secretKeys[i] = sk
		publicKeys[i] = *pk

		var sk2 bls.SecretKey
		sk2.SetByCSPRNG()
		pk2 := sk2.GetPublicKey()
		secretKeys2[i] = sk2
		publicKeys2[i] = *pk2
	}

	cfg.Replicas[1] = &ReplicaInfoWendy{ID: 1,
		Address:      "123",
		PubKey:       &key.PublicKey,
		ProofPubKeys: publicKeys}
	cfg.Replicas[2] = &ReplicaInfoWendy{ID: 2,
		Address:      "124",
		PubKey:       &key.PublicKey,
		ProofPubKeys: publicKeys2}

	wendy := NewFastWendyEC(cfg)
	block1 := CreateLeafFastWendy(wendy.genesis, []Command{Command("command1")}, wendy.qcHigh, wendy.genesis.Height+1)
	wendy.Blocks.Put(block1)
	qcBlock1 := CreateQuorumCertFastWendy(block1)
	wendy.OnReceiveProposal(block1)

	block2 := CreateLeafFastWendy(block1, nil, nil, block1.Height+1)
	wendy.Blocks.Put(block2)
	var AS data.AggregateSignature

	msg := data.AggMessage{C: strconv.FormatInt(2, 2), V: strconv.FormatInt(int64(block2.Height+1), 2)}
	sig := AS.SignShare(secretKeys, msg)

	weakLock := CreateQuorumCertFastWendy(block1)
	vote, _ := CreatePartialCertFastWendy(1, key, block1)
	msg1 := data.AggMessage{C: strconv.FormatInt(2, 2), V: strconv.FormatInt(int64(block2.Height+1), 2)}
	sig1 := AS.SignShare(secretKeys, msg1)

	newViewMsg := data.NewViewMsgFastWendy{LockCertificate: qcBlock1, Message: msg, Signature: sig, ID: 1,
		WeakLockCertificate: weakLock, MessageWeakLock: msg1, SignatureWeakLock: sig1, Vote: vote}
	wendy.viewChangeMsgs[strconv.FormatInt(int64(block2.Height+1), 2)] = make([]NewViewMsgFastWendy, 1)
	wendy.viewChangeMsgs[strconv.FormatInt(int64(block2.Height+1), 2)][0] = newViewMsg

	wendy.cmdCache.Add(Command("command3"))
	wendy.bLeaf = block2
	block3 := wendy.CreateProposal()
	wendy.Blocks.Put(block3)

	if !wendy.CheckViewChange(block3) {
		t.Errorf("Check VC failed")
	}
}
