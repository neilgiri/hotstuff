package data

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	c "crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"math"
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

func BenchmarkVerifyQuorumCert(b *testing.B) {
	qc := createQuorumCert(nil)
	/*for n := 0; n < b.N; n++ {
		VerifyQuorumCertFastWendy(biggerRc, qc, len(qc.Sigs))
	}*/
	for n := 0; n < b.N; n++ {
		VerifyQuorumCert(biggerRc, qc)
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

func BenchmarkVerifyP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	hashed := []byte("testing")
	priv, _ := ecdsa.GenerateKey(p256, c.Reader)
	r, s, _ := ecdsa.Sign(c.Reader, priv, hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for i := 0; i < 100; i++ {
				ecdsa.Verify(&priv.PublicKey, hashed, r, s)
			}

		}
	})
}

func BenchmarkPartialSigToBytes(b *testing.B) {
	pc, _ := CreatePartialCert(0, &pk, testBlock)
	for n := 0; n < b.N; n++ {
		pc.Sig.ToBytes()
	}
}

func BenchmarkVerifySignature(b *testing.B) {
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

	fmt.Printf("Generating Public/Private Key Pairs\n")
	numKeys := 5
	numReplicas := 4

	secretKeys := make([][]bls.SecretKey, numReplicas)
	publicKeys := make([][]bls.PublicKey, numReplicas)
	signatures := make([]bls.Sign, numReplicas)
	keyAggMessagePairs := make([]KeyAggMessagePair, numReplicas)

	for i := 0; i < numReplicas; i++ {
		secretKeys[i] = make([]bls.SecretKey, numKeys)
		publicKeys[i] = make([]bls.PublicKey, numKeys)
		for j := 0; j < numKeys; j++ {
			var sk bls.SecretKey
			sk.SetByCSPRNG()
			secretKeys[i][j] = sk
			publicKeys[i][j] = *sk.GetPublicKey()
		}
	}

	var AS AggregateSignature

	view := "110"
	messages := make([]AggMessage, numReplicas)
	for i := 0; i < numReplicas; i++ {
		cI := strconv.FormatInt(int64(i+1), 2)
		messages[i] = AggMessage{C: cI, V: view}
		signatures[i] = AS.SignShare(secretKeys[i], messages[i])
	}

	for i := 0; i < numReplicas; i++ {
		if !AS.VerifyShare(publicKeys[i], messages[i], signatures[i]) {
			t.Error("AS.VerifyShare failed")
		}
	}

	aggSig := AS.Agg(signatures)
	for i := 0; i < numReplicas; i++ {
		keyAggMessagePairs[i] = KeyAggMessagePair{PK: publicKeys[i], M: messages[i]}
	}

	if !AS.VerifyAgg(keyAggMessagePairs, aggSig) {
		t.Error("AS.VerifyAgg failed")
	}
}

func BenchmarkNoCommitProofTopLevel(b *testing.B) {
	benchmarks := []struct {
		faulty  int
		numKeys int
	}{
		{1, 6},
		{2, 6},
		{4, 6},
		{8, 6},
		{16, 6},
		{32, 6},
		{64, 6},
	}

	for _, bm := range benchmarks {
		bls.Init(bls.BLS12_381)
		bls.SetETHmode(bls.EthModeDraft07)
		numReplicas := 2*bm.faulty + 1
		numKeys := bm.numKeys

		secretKeys := make([][]bls.SecretKey, numReplicas)
		publicKeys := make([][]bls.PublicKey, numReplicas)
		signatures := make([]bls.Sign, numReplicas)
		keyAggMessagePairs := make([]KeyAggMessagePair, numReplicas)

		for i := 0; i < numReplicas; i++ {
			secretKeys[i] = make([]bls.SecretKey, numKeys)
			publicKeys[i] = make([]bls.PublicKey, numKeys)
			for j := 0; j < numKeys; j++ {
				var sk bls.SecretKey
				sk.SetByCSPRNG()
				secretKeys[i][j] = sk
				publicKeys[i][j] = *sk.GetPublicKey()
			}
		}

		var AS AggregateSignature

		tView := 100
		view := strconv.FormatInt(int64(tView), 2)
		messages := make([]AggMessage, numReplicas)
		for i := 0; i < numReplicas; i++ {
			maxDifference := int(math.Pow(2, float64(numKeys)))
			vD := rand.Intn(maxDifference)
			cI := strconv.FormatInt(int64(vD), 2)
			messages[i] = AggMessage{C: cI, V: view}
			signatures[i] = AS.SignShare(secretKeys[i], messages[i])
		}

		for i := 0; i < numReplicas; i++ {
			if !AS.VerifyShare(publicKeys[i], messages[i], signatures[i]) {
				b.Error("AS.VerifyShare failed")
			}
		}

		aggSig := AS.Agg(signatures)
		for i := 0; i < numReplicas; i++ {
			keyAggMessagePairs[i] = KeyAggMessagePair{PK: publicKeys[i], M: messages[i]}
		}
		b.Run(strconv.Itoa(bm.faulty),
			func(b *testing.B) {
				benchmarkNoCommitProof(b, aggSig, keyAggMessagePairs)
			},
		)
	}
}

func BenchmarkNoCommitProofVdTopLevel(b *testing.B) {
	benchmarks := []struct {
		faulty  int
		numKeys int
	}{
		{64, 1},
		{64, 2},
		{64, 3},
		{64, 4},
		{64, 5},
		{64, 6},
		{64, 7},
		{64, 8},
		{64, 9},
		{64, 10},
	}

	for _, bm := range benchmarks {
		bls.Init(bls.BLS12_381)
		bls.SetETHmode(bls.EthModeDraft07)
		numReplicas := 2*bm.faulty + 1
		numKeys := bm.numKeys

		secretKeys := make([][]bls.SecretKey, numReplicas)
		publicKeys := make([][]bls.PublicKey, numReplicas)
		signatures := make([]bls.Sign, numReplicas)
		keyAggMessagePairs := make([]KeyAggMessagePair, numReplicas)

		for i := 0; i < numReplicas; i++ {
			secretKeys[i] = make([]bls.SecretKey, numKeys)
			publicKeys[i] = make([]bls.PublicKey, numKeys)
			for j := 0; j < numKeys; j++ {
				var sk bls.SecretKey
				sk.SetByCSPRNG()
				secretKeys[i][j] = sk
				publicKeys[i][j] = *sk.GetPublicKey()
			}
		}

		var AS AggregateSignature

		tView := 100
		view := strconv.FormatInt(int64(tView), 2)
		messages := make([]AggMessage, numReplicas)
		for i := 0; i < numReplicas; i++ {
			maxDifference := int(math.Pow(2, float64(numKeys)))
			//vD := rand.Intn(maxDifference)
			cI := strconv.FormatInt(int64(maxDifference-1), 2)
			messages[i] = AggMessage{C: cI, V: view}
			//fmt.Printf("# of replicas %s\n", cI)
			signatures[i] = AS.SignShare(secretKeys[i], messages[i])
		}

		for i := 0; i < numReplicas; i++ {
			if !AS.VerifyShare(publicKeys[i], messages[i], signatures[i]) {
				b.Error("AS.VerifyShare failed")
			}
		}

		//aggSig := AS.Agg(signatures)
		for i := 0; i < numReplicas; i++ {
			keyAggMessagePairs[i] = KeyAggMessagePair{PK: publicKeys[i], M: messages[i]}
		}
		b.Run(strconv.Itoa(bm.faulty),
			func(b *testing.B) {
				benchmarkSign(b, secretKeys[0], messages[0])
			},
		)
	}
}

func benchmarkSign(b *testing.B, sk []bls.SecretKey, message AggMessage) {
	var AS AggregateSignature
	for n := 0; n < b.N; n++ {
		AS.SignShare(sk, message)
	}
}

func benchmarkNoCommitProof(b *testing.B, aggSig bls.Sign, keyAggMessagePairs []KeyAggMessagePair) {
	var AS AggregateSignature
	for n := 0; n < b.N; n++ {
		if !AS.VerifyAgg(keyAggMessagePairs, aggSig) {
			b.Error("AS.VerifyAgg failed")
		}
	}
}

func BenchmarkNoCommitProofBGLSTopLevel(b *testing.B) {
	benchmarks := []struct {
		faulty  int
		numKeys int
	}{
		{1, 6},
		{2, 6},
		{4, 6},
		{8, 6},
		{16, 6},
		{32, 6},
		{64, 6},
	}

	for _, bm := range benchmarks {
		bls.Init(bls.BLS12_381)
		bls.SetETHmode(bls.EthModeDraft07)

		numReplicas := 2*bm.faulty + 1
		publicKeys := make([]bls.PublicKey, numReplicas)
		signatures := make([]bls.Sign, numReplicas)
		messages := make([]string, numReplicas)
		msgs := make([]byte, 32*numReplicas)

		// Construct no-commit proof
		for i := 0; i < numReplicas; i++ {
			message := rand.Intn(int(math.Pow(2, float64(bm.numKeys))))

			msgs[32*i] = byte(message)
			messages[i] = strconv.Itoa(message)

			var sec bls.SecretKey
			sec.SetByCSPRNG()
			pub := sec.GetPublicKey()
			publicKeys[i] = *pub
			sig := sec.SignByte(msgs[32*i : 32*i+32])
			signatures[i] = *sig
		}
		for i := 0; i < numReplicas; i++ {
			if !signatures[i].VerifyByte(&publicKeys[i], msgs[32*i:32*i+32]) {
				b.Error("Failed verification One")
			}
		}
		var aggSig bls.Sign
		aggSig.Aggregate(signatures)
		b.Run(strconv.Itoa(bm.faulty),
			func(b *testing.B) {
				benchmarkNoCommitProofBGLS(b, aggSig, publicKeys, msgs)
			},
		)
	}
}

func BenchmarkNoCommitProofBGLSVdTopLevel(b *testing.B) {
	benchmarks := []struct {
		faulty  int
		numKeys int
	}{
		{64, 1},
		{64, 2},
		{64, 3},
		{64, 4},
		{64, 5},
		{64, 6},
		{64, 7},
		{64, 8},
		{64, 9},
		{64, 10},
	}

	for _, bm := range benchmarks {
		bls.Init(bls.BLS12_381)
		bls.SetETHmode(bls.EthModeDraft07)

		numReplicas := 2*bm.faulty + 1
		publicKeys := make([]bls.PublicKey, numReplicas)
		signatures := make([]bls.Sign, numReplicas)
		messages := make([]string, numReplicas)
		msgs := make([]byte, 32*numReplicas)

		// Construct no-commit proof
		for i := 0; i < numReplicas; i++ {
			message := rand.Intn(int(math.Pow(2, float64(bm.numKeys))))

			msgs[32*i] = byte(message)
			messages[i] = strconv.Itoa(message)

			var sec bls.SecretKey
			sec.SetByCSPRNG()
			pub := sec.GetPublicKey()
			publicKeys[i] = *pub
			sig := sec.SignByte(msgs[32*i : 32*i+32])
			signatures[i] = *sig
		}
		for i := 0; i < numReplicas; i++ {
			if !signatures[i].VerifyByte(&publicKeys[i], msgs[32*i:32*i+32]) {
				b.Error("Failed verification One")
			}
		}
		var aggSig bls.Sign
		aggSig.Aggregate(signatures)
		var sec bls.SecretKey
		sec.SetByCSPRNG()
		b.Run(strconv.Itoa(bm.faulty),
			func(b *testing.B) {
				benchmarkBGLSVd(b, sec, msgs)
			},
		)
	}
}

func benchmarkBGLSVd(b *testing.B, sec bls.SecretKey, msgs []byte) {
	for n := 0; n < b.N; n++ {
		sec.SignByte(msgs[32 : 32+32])
	}
}

func benchmarkNoCommitProofBGLS(b *testing.B, aggSig bls.Sign, publicKeys []bls.PublicKey, msgs []byte) {
	for n := 0; n < b.N; n++ {
		if !aggSig.AggregateVerifyNoCheck(publicKeys, msgs) {
			b.Error("Failed verification Two")
		}
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
	msgs := make([]byte, 32*numReplicas)

	// Construct no-commit proof
	for i := 0; i < numReplicas; i++ {
		message := rand.Intn(16)

		msgs[32*i] = byte(message)
		messages[i] = strconv.Itoa(message)

		var sec bls.SecretKey
		sec.SetByCSPRNG()
		pub := sec.GetPublicKey()
		publicKeys[i] = *pub
		sig := sec.SignByte(msgs[32*i : 32*i+32])
		signatures[i] = *sig
	}
	for i := 0; i < numReplicas; i++ {
		if !signatures[i].VerifyByte(&publicKeys[i], msgs[32*i:32*i+32]) {
			b.Error("Failed verification One")
		}
	}
	var aggSig bls.Sign
	aggSig.Aggregate(signatures)

	for n := 0; n < b.N; n++ {
		// Primary verifying signatures and constructing no-commit proof
		/*var aggSig bls.Sign
		aggSig.Aggregate(signatures)
		b.Error(aggSig.AggregateVerify(publicKeys, msgs))*/
		//b.Error(msgs)

		if !aggSig.AggregateVerifyNoCheck(publicKeys, msgs) {
			b.Error("Failed verification Two")
		}
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
