package proto

import (
	"math/big"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
	"github.com/relab/hotstuff/internal/proto/wendy"
)

func PartialSigBlsToProto(p *data.PartialSigBls) *wendy.PartialSigBls {
	s := p.S.Serialize()
	return &PartialSigBls{
		ReplicaID: int32(p.ID),
		S:         s,
	}
}

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

func (pps *PartialSigBls) FromProto() *data.PartialSigBls {
	var s bls.Sign
	s.Deserialize(pps.S)
	return &data.PartialSigBls{
		ID: config.ReplicaID(pps.GetReplicaID()),
		S:  &s,
	}
}

func PartialCertToProto(p *data.PartialCert) *PartialCert {
	return &PartialCert{
		Sig:  PartialSigToProto(&p.Sig),
		Hash: p.BlockHash[:],
	}
}

func PartialCertBlsToProto(p *data.PartialCertBls) *PartialCertBls {
	return &PartialCertBls{
		Sig:  PartialSigBlsToProto(&p.Sig),
		Hash: p.BlockHash[:],
	}
}

func (ppc *PartialCert) FromProto() *data.PartialCert {
	pc := &data.PartialCert{
		Sig: *ppc.GetSig().FromProto(),
	}
	copy(pc.BlockHash[:], ppc.GetHash())
	return pc
}

func (ppc *PartialCertBls) FromProto() *data.PartialCertBls {
	pc := &data.PartialCertBls{
		Sig: *ppc.GetSig().FromProto(),
	}
	copy(pc.BlockHash[:], ppc.GetHash())
	return pc
}

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

func QuorumCertBlsToProto(qc *data.QuorumCertBls) *QuorumCertBls {
	sig := data.PartialSigBls{0, &qc.Sig}

	return &QuorumCertBls{
		MultiSig: PartialSigBlsToProto(&sig),
		Hash:     qc.BlockHash[:],
	}
}

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

func (pqc *QuorumCertBls) FromProto() *data.QuorumCertBls {
	qc := &data.QuorumCertBls{
		Sig: *pqc.GetMultiSig().FromProto().S,
	}
	copy(qc.BlockHash[:], pqc.GetHash())

	return qc
}

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

func BlockBlsToProto(n *data.BlockBls) *BlockBls {
	commands := make([]*Command, 0, len(n.Commands))
	for _, cmd := range n.Commands {
		commands = append(commands, CommandToProto(cmd))
	}
	return &BlockBls{
		ParentHash: n.ParentHash[:],
		Commands:   commands,
		QC:         QuorumCertBlsToProto(n.Justify),
		Height:     int64(n.Height),
	}
}

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

func (pn *BlockBls) FromProto() *data.BlockBls {
	commands := make([]data.Command, 0, len(pn.GetCommands()))
	for _, cmd := range pn.GetCommands() {
		commands = append(commands, cmd.FromProto())
	}
	n := &data.BlockBls{
		Justify:  pn.GetQC().FromProto(),
		Height:   int(pn.Height),
		Commands: commands,
	}
	copy(n.ParentHash[:], pn.GetParentHash())
	return n
}

func CommandToProto(cmd data.Command) *Command {
	return &Command{Data: []byte(cmd)}
}

func (cmd *Command) FromProto() data.Command {
	return data.Command(cmd.GetData())
}
