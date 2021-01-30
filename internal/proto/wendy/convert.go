package proto

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
)

// PartialSigBlsToProto returns
func PartialSigBlsToProto(p *data.PartialSigBls) *PartialSigBls {
	s := p.S.Serialize()
	return &PartialSigBls{
		ReplicaID: int32(p.ID),
		S:         s,
	}
}

// FromProto returns
func (pps *PartialSigBls) FromProto() *data.PartialSigBls {
	var s bls.Sign
	s.Deserialize(pps.S)
	return &data.PartialSigBls{
		ID: config.ReplicaID(pps.GetReplicaID()),
		S:  &s,
	}
}

// PartialCertBlsToProto returns
func PartialCertBlsToProto(p *data.PartialCertBls) *PartialCertBls {
	return &PartialCertBls{
		Sig:  PartialSigBlsToProto(&p.Sig),
		Hash: p.BlockHash[:],
	}
}

// FromProto returns
func (ppc *PartialCertBls) FromProto() *data.PartialCertBls {
	pc := &data.PartialCertBls{
		Sig: *ppc.GetSig().FromProto(),
	}
	copy(pc.BlockHash[:], ppc.GetHash())
	return pc
}

// QuorumCertBlsToProto returns
func QuorumCertBlsToProto(qc *data.QuorumCertBls) *QuorumCertBls {
	sigs := make([][]byte, 0, len(qc.Sig))
	for _, psig := range qc.Sig {
		sigs = append(sigs, psig.Serialize())
	}
	indices := make([]*Index, 0, len(qc.I))
	for key, value := range qc.I {
		index := Index{ReplicaID: int32(key), Exists: value}
		indices = append(indices, &index)
	}

	return &QuorumCertBls{
		Sig:  sigs,
		Hash: qc.BlockHash[:],
		I:    indices,
	}
}

// FromProto returns
func (pqc *QuorumCertBls) FromProto() *data.QuorumCertBls {
	qc := &data.QuorumCertBls{
		Sig: make([]bls.Sign, 0),
		I:   make(map[config.ReplicaID]bool),
	}
	copy(qc.BlockHash[:], pqc.GetHash())
	var psig bls.Sign

	for _, ppsig := range pqc.GetSig() {
		psig.Deserialize(ppsig)
		qc.Sig = append(qc.Sig, psig)
	}

	for _, index := range pqc.GetI() {
		qc.I[config.ReplicaID(index.ReplicaID)] = index.Exists
	}

	return qc
}

// BlockBlsToProto returns
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

// FromProto returns
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

// CommandToProto returns
func CommandToProto(cmd data.Command) *Command {
	return &Command{Data: []byte(cmd)}
}

// FromProto returns
func (cmd *Command) FromProto() data.Command {
	return data.Command(cmd.GetData())
}
