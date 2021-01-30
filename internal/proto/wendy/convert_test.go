package proto

import (
	bytes "bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/data"
)

var pk bls.SecretKey

func init() {
	_pk := data.GeneratePrivateKeyBls()
	pk = _pk
}

var simpleRc = config.ReplicaConfigBls{
	Replicas: map[config.ReplicaID]*config.ReplicaInfoBls{
		0: {
			ID:        0,
			Address:   "",
			PubKeyBLS: pk.GetPublicKey(), // this is why
		},
	},
	QuorumSize: 1,
}

var testBlock = data.BlockBls{
	Commands: []data.Command{data.Command("this is a test")},
	Height:   0,
}

func TestMarshalingPartialCertBlsToProto(t *testing.T) {
	pc1, _ := data.CreatePartialCertBls(config.ReplicaID(0), &pk, &testBlock)

	ppc := PartialCertBlsToProto(pc1)
	pc2 := ppc.FromProto()

	if !bytes.Equal(pc1.BlockHash[:], pc2.BlockHash[:]) {
		t.Errorf("Hashes don't match! Got %v, want: %v\n",
			hex.EncodeToString(pc2.BlockHash[:]), hex.EncodeToString(pc1.BlockHash[:]))
	}

	if !data.VerifyPartialCertBls(&simpleRc, pc2) {
		t.Errorf("Cert failed to verify!\n")
	}
}

func TestMarshalingQuorumCertBlsToProto(t *testing.T) {
	qc1 := data.CreateQuorumCertBls(&testBlock)
	pc1, _ := data.CreatePartialCertBls(0, &pk, &testBlock)
	qc1.AddPartialBls(pc1)
	pqc := QuorumCertBlsToProto(qc1)
	qc2 := pqc.FromProto()

	if !bytes.Equal(qc1.BlockHash[:], qc2.BlockHash[:]) {
		t.Errorf("Hashes don't match! Got %v, want: %v\n",
			hex.EncodeToString(qc2.BlockHash[:]), hex.EncodeToString(qc1.BlockHash[:]))
	}

	if !data.VerifyQuorumCertBls(&simpleRc, qc2) {
		t.Errorf("Cert failed to verify!\n")
	}
}

func TestMarshalAndUnmarshalBlock(t *testing.T) {
	testBlock := &data.BlockBls{Commands: []data.Command{data.Command("test")}}
	testQC := data.CreateQuorumCertBls(testBlock)
	numSigs, _ := rand.Int(rand.Reader, big.NewInt(10))
	for j := int64(0); j < numSigs.Int64(); j++ {
		id, _ := rand.Int(rand.Reader, big.NewInt(1000))
		s := pk.Sign(testBlock.Hash().String())
		sig := &data.PartialSigBls{ID: config.ReplicaID(id.Int64()), S: s}
		cert := &data.PartialCertBls{Sig: *sig, BlockHash: testBlock.Hash()}
		testQC.AddPartialBls(cert)
	}

	testBlock.Justify = testQC

	h1 := testBlock.Hash()
	protoBlock := BlockBlsToProto(testBlock)
	testBlock2 := protoBlock.FromProto()
	h2 := testBlock2.Hash()

	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatalf("Hashes don't match after marshaling / unmarshaling!")
	}
}
