package data

import (
	"crypto/ecdsa"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/relab/hotstuff/config"
)

var pk ecdsa.PrivateKey // must not be a pointer

var simpleRc = &config.ReplicaConfig{
	Replicas: map[config.ReplicaID]*config.ReplicaInfo{
		0: {
			ID:      0,
			Address: "",
			PubKey:  &pk.PublicKey, // this is why
		},
	},
	QuorumSize: 1,
}

var biggerRc = &config.ReplicaConfig{
	Replicas: map[config.ReplicaID]*config.ReplicaInfo{
		0: {
			ID:      0,
			Address: "",
			PubKey:  &pk.PublicKey,
		},
		1: {
			ID:      1,
			Address: "",
			PubKey:  &pk.PublicKey,
		},
		2: {
			ID:      2,
			Address: "",
			PubKey:  &pk.PublicKey,
		},
		3: {
			ID:      3,
			Address: "",
			PubKey:  &pk.PublicKey,
		},
	},
	QuorumSize: 3,
}

var testBlock = &Block{
	Commands: []Command{Command("this is a test")},
	Height:   0,
}

func init() {
	k, err := GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	pk = *k
}

func createPartialCert(t *testing.T, id config.ReplicaID) *PartialCert {
	pc, err := CreatePartialCert(id, &pk, testBlock)
	if err != nil {
		t.Errorf("Failed to create partial certificate: %v\n", err)
	}
	return pc
}

func TestVerifyPartialCert(t *testing.T) {
	pc := createPartialCert(t, 0)

	if !VerifyPartialCert(simpleRc, pc) {
		t.Errorf("Partial cert failed to verify!")
	}
}

func createQuorumCert(t *testing.T) *QuorumCert {
	qc := CreateQuorumCert(testBlock)
	for k := range biggerRc.Replicas {
		err := qc.AddPartial(createPartialCert(t, k))
		if err != nil {
			t.Errorf("Failed to add partial cert to quorum cert: %v\n", err)
		}
	}
	return qc
}

func TestVerifyQuorumCert(t *testing.T) {
	qc := createQuorumCert(t)
	if !VerifyQuorumCert(biggerRc, qc) {
		t.Errorf("Quorum cert failed to verify!")
	}
}

func BenchmarkQuroumCertToBytes(b *testing.B) {
	qc := CreateQuorumCert(testBlock)
	for _, r := range biggerRc.Replicas {
		pc, _ := CreatePartialCert(r.ID, &pk, testBlock)
		qc.AddPartial(pc)
	}
	for n := 0; n < b.N; n++ {
		qc.ToBytes()
	}
}

func BenchmarkPartialSigToBytes(b *testing.B) {
	pc, _ := CreatePartialCert(0, &pk, testBlock)
	for n := 0; n < b.N; n++ {
		pc.Sig.ToBytes()
	}
}

func TestVerifySig(t *testing.T) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	fmt.Printf("sample1\n")
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	msg := []byte("abc")
	pub := sec.GetPublicKey()
	sig := sec.SignByte(msg)
	fmt.Printf("verify=%v\n", sig.VerifyByte(pub, msg))
}

func TestMultiSigVerify(t *testing.T) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	fileName := "fast_aggregate_verify.txt"
	fp, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("can't open %v %v", fileName, err)
	}
	defer fp.Close()

	reader := csv.NewReader(fp)
	reader.Comma = ' '
	i := 0
	for {
		var pubVec []bls.PublicKey
		var s []string
		var err error
		for {
			s, err = reader.Read()
			if err == io.EOF {
				return
			}
			if s[0] == "msg" {
				break
			}
			var pub bls.PublicKey
			if pub.DeserializeHexStr(s[1]) != nil {
				t.Fatalf("bad signature")
			}
			pubVec = append(pubVec, pub)
		}
		t.Logf("i=%v\n", i)
		i++
		msg, _ := hex.DecodeString(s[1])
		sigHex, _ := reader.Read()
		outHex, _ := reader.Read()
		var sig bls.Sign
		if sig.DeserializeHexStr(sigHex[1]) != nil {
			t.Logf("bad signature %v", sigHex[1])
			continue
		}
		if !sig.IsValidOrder() {
			t.Logf("bad order %v", sigHex[1])
			continue
		}
		out := outHex[1] == "true"
		if sig.FastAggregateVerify(pubVec, msg) != out {
			t.Fatalf("bad FastAggregateVerify")
		}
	}
}
