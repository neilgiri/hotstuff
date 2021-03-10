package proto

import (
	"math/big"
	"reflect"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
)

// PartialSigToProto returns
func PartialSigToProto(p *data.PartialSig) *PartialSig {
	r := p.R.Bytes()
	s := p.S.Bytes()
	return &PartialSig{
		ReplicaID: int32(p.ID),
		R:         r,
		S:         s,
	}
}

// FromProto returns
func (pps *PartialSig) FromProto() *data.PartialSig {
	r := big.NewInt(0)
	s := big.NewInt(0)
	r.SetBytes(pps.GetR())
	s.SetBytes(pps.GetS())
	return &data.PartialSig{
		ID: config.ReplicaID(pps.GetReplicaID()),
		R:  r,
		S:  s,
	}
}

// PartialCertToProto returns
func PartialCertToProto(p *data.PartialCert) *PartialCert {
	return &PartialCert{
		Sig:  PartialSigToProto(&p.Sig),
		Hash: p.BlockHash[:],
	}
}

// FromProto returns
func (ppc *PartialCert) FromProto() *data.PartialCert {
	pc := &data.PartialCert{
		Sig: *ppc.GetSig().FromProto(),
	}
	copy(pc.BlockHash[:], ppc.GetHash())
	return pc
}

// QuorumCertToProto returns
func QuorumCertToProto(qc *data.QuorumCert) *QuorumCert {
	sigs := make([]*PartialSig, 0, len(qc.Sigs))
	for _, psig := range qc.Sigs {
		sigs = append(sigs, PartialSigToProto(&psig))
	}
	return &QuorumCert{
		Sigs: sigs,
		Hash: qc.BlockHash[:],
	}
}

// FromProto returns
func (pqc *QuorumCert) FromProto() *data.QuorumCert {
	qc := &data.QuorumCert{
		Sigs: make(map[config.ReplicaID]data.PartialSig),
	}
	copy(qc.BlockHash[:], pqc.GetHash())
	for _, ppsig := range pqc.GetSigs() {
		psig := ppsig.FromProto()
		qc.Sigs[psig.ID] = *psig
	}
	return qc
}

// BlockToProto returns
func BlockToProto(n *data.Block) *Block {
	commands := make([]*Command, 0, len(n.Commands))
	for _, cmd := range n.Commands {
		commands = append(commands, CommandToProto(cmd))
	}
	return &Block{
		ParentHash: n.ParentHash[:],
		Commands:   commands,
		QC:         QuorumCertToProto(n.Justify),
		Height:     int64(n.Height),
	}
}

// FromProto returns
func (pn *Block) FromProto() *data.Block {
	commands := make([]data.Command, 0, len(pn.GetCommands()))
	for _, cmd := range pn.GetCommands() {
		commands = append(commands, cmd.FromProto())
	}
	n := &data.Block{
		Justify:  pn.GetQC().FromProto(),
		Height:   int(pn.Height),
		Commands: commands,
	}
	copy(n.ParentHash[:], pn.GetParentHash())
	return n
}

// CommandToProto returns
func CommandToProto(cmd data.Command) *Command {
	return &Command{Data: []byte(cmd)}
}

// FromProto returns
func (cmd *Command) FromProto() data.Command {
	return data.Command(cmd.GetData())
}

// AggMessageToProto returns
func AggMessageToProto(message data.AggMessage) *AggMessage {
	return &AggMessage{C: []byte(message.C), V: []byte(message.V)}
}

// FromProto returns
func (message *AggMessage) FromProto() data.AggMessage {
	return data.AggMessage{C: string(message.C), V: string(message.V)}
}

// KeyAggMessagePairToProto returns
func KeyAggMessagePairToProto(message data.KeyAggMessagePair) *KeyAggMessagePair {
	publicKeys := make([][]byte, len(message.PK))
	publicKeySize := 48
	for i := 0; i < len(message.PK); i++ {
		publicKeys[i] = make([]byte, publicKeySize)
		publicKeys[i] = message.PK[i].Serialize()
	}
	return &KeyAggMessagePair{PK: publicKeys, M: AggMessageToProto(message.M)}
}

// FromProto returns
func (keyAggMessagePair *KeyAggMessagePair) FromProto() data.KeyAggMessagePair {
	publicKeys := make([]bls.PublicKey, len(keyAggMessagePair.PK))
	for i := 0; i < len(keyAggMessagePair.PK); i++ {
		var pk bls.PublicKey
		pk.Deserialize(keyAggMessagePair.PK[i])
		publicKeys[i] = pk
	}
	return data.KeyAggMessagePair{PK: publicKeys,
		M: keyAggMessagePair.M.FromProto()}
}

// NewViewMsgToProto returns
func NewViewMsgToProto(message data.NewViewMsg) *NewViewMsg {
	return &NewViewMsg{LockCertificate: QuorumCertToProto(message.LockCertificate),
		Message: AggMessageToProto(message.Message), Signature: message.Signature.Serialize(), ReplicaID: int32(message.ID)}
}

// FromProto returns
func (newViewMsg *NewViewMsg) FromProto() data.NewViewMsg {
	var sig bls.Sign
	sig.Deserialize(newViewMsg.Signature)
	return data.NewViewMsg{LockCertificate: newViewMsg.LockCertificate.FromProto(),
		Message: newViewMsg.Message.FromProto(), Signature: sig, ID: config.ReplicaID(newViewMsg.ReplicaID)}
}

// ProofNCToProto returns
func ProofNCToProto(message data.ProofNC) *ProofNC {
	messages := make([]*KeyAggMessagePair, len(message.Messages))
	for i := 0; i < len(message.Messages); i++ {
		messages[i] = KeyAggMessagePairToProto(message.Messages[i])
	}
	ref := reflect.ValueOf(message.Hash)
	return &ProofNC{MessagePairs: messages, Signature: message.Signature.Serialize(), Hash: ref.Bytes()}
}

// FromProto returns
func (proofNC *ProofNC) FromProto() data.ProofNC {
	messages := make([]data.KeyAggMessagePair, len(proofNC.MessagePairs))
	for i := 0; i < len(proofNC.MessagePairs); i++ {
		messages[i] = proofNC.MessagePairs[i].FromProto()
	}
	var sig bls.Sign
	sig.Deserialize(proofNC.Signature)
	h := new(data.BlockHash)
	copy(h[:], proofNC.Hash)
	return data.ProofNC{Messages: messages, Signature: sig, Hash: *h}
}

// NackMsgToProto returns
func NackMsgToProto(message data.NackMsg) *NackMsg {
	ref := reflect.ValueOf(message.Hash)
	return &NackMsg{QC: QuorumCertToProto(message.HighLockCertificate), Hash: ref.Bytes()}
}

// FromProto returns
func (nack *NackMsg) FromProto() data.NackMsg {
	h := new(data.BlockHash)
	copy(h[:], nack.Hash)
	return data.NackMsg{HighLockCertificate: nack.QC.FromProto(), Hash: *h}
}
