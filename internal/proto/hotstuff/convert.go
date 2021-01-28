package proto

import (
	"math/big"

	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
)

func PartialSigToProto(p *data.PartialSig) *hotstuff.PartialSig {
	r := p.R.Bytes()
	s := p.S.Bytes()
	return &hotstuff.PartialSig{
		ReplicaID: int32(p.ID),
		R:         r,
		S:         s,
	}
}

func (pps *hotstuff.PartialSig) FromProto() *data.PartialSig {
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

func PartialCertToProto(p *data.PartialCert) *hotstuff.PartialCert {
	return &hotstuff.PartialCert{
		Sig:  PartialSigToProto(&p.Sig),
		Hash: p.BlockHash[:],
	}
}

func (ppc *hotstuff.PartialCert) FromProto() *data.PartialCert {
	pc := &data.PartialCert{
		Sig: *ppc.GetSig().FromProto(),
	}
	copy(pc.BlockHash[:], ppc.GetHash())
	return pc
}

func QuorumCertToProto(qc *data.QuorumCert) *hotstuff.QuorumCert {
	sigs := make([]*hotstuff.PartialSig, 0, len(qc.Sigs))
	for _, psig := range qc.Sigs {
		sigs = append(sigs, PartialSigToProto(&psig))
	}
	return &hotstuff.QuorumCert{
		Sigs: sigs,
		Hash: qc.BlockHash[:],
	}
}

func (pqc *hotstuff.QuorumCert) FromProto() *data.QuorumCert {
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

func BlockToProto(n *data.Block) *hotstuff.Block {
	commands := make([]*hotstuff.Command, 0, len(n.Commands))
	for _, cmd := range n.Commands {
		commands = append(commands, CommandToProto(cmd))
	}
	return &hotstuff.Block{
		ParentHash: n.ParentHash[:],
		Commands:   commands,
		QC:         QuorumCertToProto(n.Justify),
		Height:     int64(n.Height),
	}
}

func (pn *hotstuff.Block) FromProto() *data.Block {
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

func CommandToProto(cmd data.Command) *hotstuff.Command {
	return &hotstuff.Command{Data: []byte(cmd)}
}

func (cmd *hotstuff.Command) FromProto() data.Command {
	return data.Command(cmd.GetData())
}
