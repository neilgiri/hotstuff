package data

import (
	"crypto/ecdsa"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
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

func TestProof(t *testing.T) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	fmt.Printf("Testing Proof of no commit\n")

	numReplicas := int(4)
	publicKeys := make([][]bls.PublicKey, numReplicas)
	signatures := make([][]bls.Sign, numReplicas)
	multisignatures := make([]bls.Sign, numReplicas)
	bitVectors := make([]string, numReplicas)

	commonView := int(6)
	n := int64(5)
	bitString := strconv.FormatInt(n, 2)

	// Construct no-commit proof
	for i := 0; i < numReplicas; i++ {
		bitVectors[i] = bitString
		signatures[i] = make([]bls.Sign, len(bitVectors[i]))
		publicKeys[i] = make([]bls.PublicKey, len(bitVectors[i]))
		for j := 0; j < len(bitVectors[i]); j++ {
			if bitString[j] == 49 {
				var sec bls.SecretKey
				sec.SetByCSPRNG()
				pub := sec.GetPublicKey()
				publicKeys[i][j] = *pub
				sig := sec.Sign(strconv.Itoa(commonView))
				signatures[i][j] = *sig
			}
		}
		var aggSig bls.Sign
		aggSig.Aggregate(signatures[i])
		multisignatures[i] = aggSig
	}

	// Primary verifying signatures and constructing no-commit proof
	for i := 0; i < len(multisignatures); i++ {
		//bv := bitVectors[i]
		// Verify using replica i's public keys the validity of the multisig on common view
		aggSig := multisignatures[i]
		commonViewBytes := []byte(strconv.Itoa(commonView))
		t.Error(aggSig.FastAggregateVerify(publicKeys[i], commonViewBytes))
	}

	/*msg := []byte("abc")
	pub := sec.GetPublicKey()
	sig := sec.SignByte(msg)
	fmt.Printf("verify=%v\n", sig.VerifyByte(pub, msg))*/
}

func BenchmarkNoCommitProof(b *testing.B) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	fmt.Printf("Testing Proof of no commit\n")

	numReplicas := int(100)
	publicKeys := make([][]bls.PublicKey, numReplicas)
	signatures := make([][]bls.Sign, numReplicas)
	multisignatures := make([]bls.Sign, numReplicas)
	bitVectors := make([]string, numReplicas)

	commonView := int(6)
	n := int64(16)
	bitString := strconv.FormatInt(n, 2)

	// Construct no-commit proof
	for i := 0; i < numReplicas; i++ {
		bitVectors[i] = bitString
		signatures[i] = make([]bls.Sign, len(bitVectors[i]))
		publicKeys[i] = make([]bls.PublicKey, len(bitVectors[i]))
		for j := 0; j < len(bitVectors[i]); j++ {
			if bitString[j] == 49 {
				var sec bls.SecretKey
				sec.SetByCSPRNG()
				pub := sec.GetPublicKey()
				publicKeys[i][j] = *pub
				sig := sec.Sign(strconv.Itoa(commonView))
				signatures[i][j] = *sig
			}
		}
		var aggSig bls.Sign
		aggSig.Aggregate(signatures[i])
		multisignatures[i] = aggSig
	}

	for n := 0; n < b.N; n++ {
		// Primary verifying signatures and constructing no-commit proof
		for i := 0; i < len(multisignatures); i++ {
			// Verify using replica i's public keys the validity of the multisig on common view
			aggSig := multisignatures[i]
			commonViewBytes := []byte(strconv.Itoa(commonView))
			if !aggSig.FastAggregateVerify(publicKeys[i], commonViewBytes) {
				b.Error("Failed verification")
			}
		}
		var authenticator bls.Sign
		authenticator.Aggregate(multisignatures)
	}
}

func BenchmarkNoCommitProofReplica(b *testing.B) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	fmt.Printf("Testing Proof of no commit\n")

	numReplicas := int(100)
	publicKeys := make([][]bls.PublicKey, numReplicas)
	signatures := make([][]bls.Sign, numReplicas)
	multisignatures := make([]bls.Sign, numReplicas)
	bitVectors := make([]string, numReplicas)

	commonView := int(6)
	n := int64(16)
	bitString := strconv.FormatInt(n, 2)

	// Construct no-commit proof
	for i := 0; i < numReplicas; i++ {
		bitVectors[i] = bitString
		signatures[i] = make([]bls.Sign, len(bitVectors[i]))
		publicKeys[i] = make([]bls.PublicKey, len(bitVectors[i]))
		for j := 0; j < len(bitVectors[i]); j++ {
			if bitString[j] == 49 {
				var sec bls.SecretKey
				sec.SetByCSPRNG()
				pub := sec.GetPublicKey()
				publicKeys[i][j] = *pub
				sig := sec.Sign(strconv.Itoa(commonView))
				signatures[i][j] = *sig
			}
		}
		var aggSig bls.Sign
		aggSig.Aggregate(signatures[i])
		multisignatures[i] = aggSig
	}

	aggregatedPks := make([]bls.PublicKey, len(multisignatures))

	// Primary verifying signatures and constructing no-commit proof
	for i := 0; i < len(multisignatures); i++ {
		// Verify using replica i's public keys the validity of the multisig on common view
		aggSig := multisignatures[i]
		commonViewBytes := []byte(strconv.Itoa(commonView))
		if !aggSig.FastAggregateVerify(publicKeys[i], commonViewBytes) {
			b.Error("Failed verification")
		}

		addedPk := &publicKeys[i][0]
		for j := 1; j < len(publicKeys[i]); j++ {
			addedPk.Add(&publicKeys[i][j])
		}
		aggregatedPks[i] = *addedPk
	}
	var authenticator bls.Sign
	authenticator.Aggregate(multisignatures)

	for n := 0; n < b.N; n++ {
		commonViewBytes := []byte(strconv.Itoa(commonView))
		if !authenticator.FastAggregateVerify(aggregatedPks, commonViewBytes) {
			b.Error("Failed verification of the authenticator")
		}
	}
}

func BenchmarkNoCommitProofAlternative(b *testing.B) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	fmt.Printf("Testing Proof of no commit\n")

	numReplicas := int(100)
	publicKeys := make([]bls.PublicKey, numReplicas)
	signatures := make([]bls.Sign, numReplicas)
	messages := make([]string, numReplicas)
	msgs := make([]byte, numReplicas)

	// Construct no-commit proof
	for i := 0; i < numReplicas; i++ {
		message := rand.Intn(16)

		msgs[i] = byte(message)
		messages[i] = strconv.Itoa(message)

		var sec bls.SecretKey
		sec.SetByCSPRNG()
		pub := sec.GetPublicKey()
		publicKeys[i] = *pub
		sig := sec.Sign(messages[i])
		signatures[i] = *sig
	}

	for n := 0; n < b.N; n++ {
		// Primary verifying signatures and constructing no-commit proof
		/*var aggSig bls.Sign
		aggSig.Aggregate(signatures)
		b.Error(aggSig.AggregateVerify(publicKeys, msgs))*/
		for i := 0; i < numReplicas; i++ {
			if !signatures[i].Verify(&publicKeys[i], messages[i]) {
				b.Error("Failed verification")
			}
			//signatures[i].Verify(&publicKeys[i], messages[i])
		}
	}
}

func BenchmarkNoCommitProofAlternativeTwo(b *testing.B) {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	fmt.Printf("Testing Proof of no commit\n")

	numReplicas := int(100)
	publicKeys := make([]bls.PublicKey, numReplicas)
	signatures := make([]bls.Sign, numReplicas)
	messages := make([]string, numReplicas)
	msgs := make([]byte, numReplicas)

	// Construct no-commit proof
	for i := 0; i < numReplicas; i++ {
		message := rand.Intn(16)

		msgs[i] = byte(message)
		messages[i] = strconv.Itoa(message)

		var sec bls.SecretKey
		sec.SetByCSPRNG()
		pub := sec.GetPublicKey()
		publicKeys[i] = *pub
		sig := sec.Sign(messages[i])
		signatures[i] = *sig
	}

	for n := 0; n < b.N; n++ {
		// Primary verifying signatures and constructing no-commit proof
		/*var aggSig bls.Sign
		aggSig.Aggregate(signatures)
		b.Error(aggSig.AggregateVerify(publicKeys, msgs))*/
		for i := 0; i < numReplicas; i++ {
			if !signatures[i].Verify(&publicKeys[i], messages[i]) {
				b.Error("Failed verification")
			}
		}

		var aggSig bls.Sign
		aggSig.Aggregate(signatures)
		//b.Error(aggSig.AggregateVerify(publicKeys, msgs))
	}
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
