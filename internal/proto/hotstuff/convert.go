package proto

import (
	"math/big"

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
