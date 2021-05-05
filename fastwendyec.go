package hotstuff

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/relab/hotstuff/config"
	"github.com/relab/hotstuff/consensus"
	"github.com/relab/hotstuff/data"
	"github.com/relab/hotstuff/internal/logging"
	proto "github.com/relab/hotstuff/internal/proto/fastwendyec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func init() {
	logger = logging.GetLogger()
}

// PacemakerFastWendyEC is a mechanism that provides synchronization
type PacemakerFastWendyEC interface {
	GetLeader(view int) config.ReplicaID
	Init(*FastWendyEC)
}

// FastWendyEC is a thing
type FastWendyEC struct {
	*consensus.FastWendyCoreEC
	tls bool

	pacemaker     PacemakerFastWendyEC
	viewBenchmark int

	nodes map[config.ReplicaID]*proto.Node

	server  *fastwendyecServer
	manager *proto.Manager
	cfg     *proto.Configuration

	closeOnce sync.Once

	qcTimeout      time.Duration
	connectTimeout time.Duration
}

//NewFastWendyEC creates a new GorumsHotStuff backend object.
func NewFastWendyEC(conf *config.ReplicaConfigFastWendy, pacemaker PacemakerFastWendyEC, tls bool, connectTimeout, qcTimeout time.Duration, viewBenchmark int) *FastWendyEC {
	wendyEC := &FastWendyEC{
		pacemaker:       pacemaker,
		FastWendyCoreEC: consensus.NewFastWendyEC(conf),
		nodes:           make(map[config.ReplicaID]*proto.Node),
		connectTimeout:  connectTimeout,
		qcTimeout:       qcTimeout,
		viewBenchmark:   viewBenchmark,
	}
	pacemaker.Init(wendyEC)
	return wendyEC
}

//Start starts the server and client
func (wendyEC *FastWendyEC) Start() error {
	addr := wendyEC.Config.Replicas[wendyEC.Config.ID].Address
	err := wendyEC.startServer(addr)
	if err != nil {
		return fmt.Errorf("Failed to start GRPC Server: %w", err)
	}
	err = wendyEC.startClient(wendyEC.connectTimeout)
	if err != nil {
		return fmt.Errorf("Failed to start GRPC Clients: %w", err)
	}
	return nil
}

func (wendyEC *FastWendyEC) startClient(connectTimeout time.Duration) error {
	idMapping := make(map[string]uint32, len(wendyEC.Config.Replicas)-1)
	for _, replica := range wendyEC.Config.Replicas {
		if replica.ID != wendyEC.Config.ID {
			idMapping[replica.Address] = uint32(replica.ID)
		}
	}

	// embed own ID to allow other replicas to identify messages from this replica
	md := metadata.New(map[string]string{
		"id": fmt.Sprintf("%d", wendyEC.Config.ID),
	})

	perNodeMD := func(nid uint32) metadata.MD {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], nid)
		hash := sha256.Sum256(b[:])
		R, S, err := ecdsa.Sign(rand.Reader, wendyEC.Config.PrivateKey, hash[:])
		if err != nil {
			panic(fmt.Errorf("Could not sign proof for replica %d: %w", nid, err))
		}
		md := metadata.MD{}
		md.Append("proof", base64.StdEncoding.EncodeToString(R.Bytes()), base64.StdEncoding.EncodeToString(S.Bytes()))
		return md
	}

	mgrOpts := []proto.ManagerOption{
		proto.WithDialTimeout(connectTimeout),
		proto.WithNodeMap(idMapping),
		proto.WithMetadata(md),
		proto.WithPerNodeMetadata(perNodeMD),
	}
	grpcOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	}

	if wendyEC.tls {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(wendyEC.Config.CertPool, "")))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
	}

	mgrOpts = append(mgrOpts, proto.WithGrpcDialOptions(grpcOpts...))

	mgr, err := proto.NewManager(mgrOpts...)
	if err != nil {
		return fmt.Errorf("Failed to connect to replicas: %w", err)
	}
	wendyEC.manager = mgr

	for _, node := range mgr.Nodes() {
		wendyEC.nodes[config.ReplicaID(node.ID())] = node
	}

	wendyEC.cfg, err = wendyEC.manager.NewConfiguration(wendyEC.manager.NodeIDs(), &struct{}{})
	if err != nil {
		return fmt.Errorf("Failed to create configuration: %w", err)
	}

	return nil
}

// startServer runs a new instance of hotstuffServer
func (wendyEC *FastWendyEC) startServer(port string) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("Failed to listen to port %s: %w", port, err)
	}

	serverOpts := []proto.ServerOption{}
	grpcServerOpts := []grpc.ServerOption{}

	if wendyEC.tls {
		grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewServerTLSFromCert(wendyEC.Config.Cert)))
	}

	serverOpts = append(serverOpts, proto.WithGRPCServerOptions(grpcServerOpts...))

	wendyEC.server = newFastWendyECServer(wendyEC, proto.NewGorumsServer(serverOpts...))
	wendyEC.server.RegisterFastWendyECServer(wendyEC.server)

	go wendyEC.server.Serve(lis)
	return nil
}

// Close closes all connections made by the HotStuff instance
func (wendyEC *FastWendyEC) Close() {
	wendyEC.closeOnce.Do(func() {
		wendyEC.FastWendyCoreEC.Close()
		wendyEC.manager.Close()
		wendyEC.server.Stop()
	})
}

// Propose broadcasts a new proposal to all replicas
func (wendyEC *FastWendyEC) Propose() {
	proposal := wendyEC.CreateProposal()
	logger.Printf("Propose (%d commands): %s\n", len(proposal.Commands), proposal)
	protobuf := proto.BlockToProto(proposal)
	wendyEC.cfg.Propose(protobuf)
	// self-vote
	wendyEC.handlePropose(proposal)
}

func Hash(s data.AggMessage) []byte {
	/*var b bytes.Buffer
	gob.NewEncoder(&b).Encode(s)
	return b.Bytes()*/
	return []byte(s.C + s.V)
}

// SendNewView sends a NEW-VIEW message to a specific replica
func (wendyEC *FastWendyEC) SendNewView(id config.ReplicaID) {
	if node, ok := wendyEC.nodes[id]; ok {
		//node.NewView(proto.QuorumCertToProto(qc))
		v := strconv.FormatInt(int64(wendyEC.FastWendyCoreEC.GetHeight()), 10)
		vD := strconv.FormatInt(int64(wendyEC.FastWendyCoreEC.GetHeight()-wendyEC.FastWendyCoreEC.GetLock().Height), 2)
		msg := data.AggMessage{C: vD, V: v}
		var AS data.AggregateSignature
		sig := AS.SignShare(wendyEC.FastWendyCoreEC.Config.ProofNCPrivKeys, msg)

		//vDWL := strconv.FormatInt(int64(wendyEC.FastWendyCoreEC.GetHeight()-wendyEC.FastWendyCoreEC.GetWeakLock().Height), 2)
		voteBlock := wendyEC.GetVote()
		msgWL := data.AggMessage{C: wendyEC.GetPCVote().BlockHash.String(), V: strconv.Itoa(voteBlock.Height)}
		sigWL := *wendyEC.FastWendyCoreEC.Config.ProofNCPrivKeys[0].SignHash(Hash(msgWL))
		//fmt.Println("Hash: " + wendyEC.GetPCVote().BlockHash.String())

		newViewMsg := data.NewViewMsgFastWendy{LockCertificate: wendyEC.GetQCLock(), Message: msg, Signature: sig, ID: wendyEC.Config.ID,
			WeakLockCertificate: wendyEC.GetQCWeakLock(), MessageWeakLock: msgWL, SignatureWeakLock: sigWL, Vote: wendyEC.GetPCVote()}

		node.NewView(proto.NewViewMsgToProto(newViewMsg))
	}
}

func (wendyEC *FastWendyEC) handlePropose(block *data.BlockFastWendy) {
	p, nack, err := wendyEC.OnReceiveProposal(block)
	leaderID := wendyEC.pacemaker.GetLeader(block.Height)
	wendyEC.Blocks.Put(block)

	if wendyEC.viewBenchmark != 0 && wendyEC.GetHeight() > 0 && wendyEC.GetHeight()%wendyEC.viewBenchmark == 0 {
		wendyEC.Blocks.Put(block)
		newHeight := wendyEC.GetHeight() + 1
		//wendyEC.SetLeaf(consensus.CreateLeafFastWendy(wendyEC.GetLeaf(), nil, nil, newHeight))
		wendyEC.SendNewView(wendyEC.pacemaker.GetLeader(newHeight))
		//fmt.Println("New height: " + strconv.Itoa(newHeight))
	}

	if err != nil {
		logger.Println("OnReceiveProposal returned with error:", err)
		//qcBlock, _ := wendyEC.Blocks.BlockOf(block.Justify)
		//fmt.Println("Proposed height: " + strconv.Itoa(qcBlock.Height) + " : " + strconv.Itoa(wendyEC.GetVote().Height))
		if nack != nil {
			if leader, ok := wendyEC.nodes[leaderID]; ok {
				//fmt.Println("Sending nack")
				leader.Nack(proto.NackMsgToProto(*nack))
			}
		}
		return
	}

	if wendyEC.Config.ID == leaderID {
		wendyEC.OnReceiveVote(p)
	} else if leader, ok := wendyEC.nodes[leaderID]; ok {
		leader.Vote(proto.PartialCertToProto(p))
	}
}

type fastwendyecServer struct {
	*FastWendyEC
	*proto.GorumsServer
	// maps a stream context to client info
	mut     sync.RWMutex
	clients map[context.Context]config.ReplicaID
}

func newFastWendyECServer(wendyec *FastWendyEC, srv *proto.GorumsServer) *fastwendyecServer {
	wendyecSrv := &fastwendyecServer{
		FastWendyEC:  wendyec,
		GorumsServer: srv,
		clients:      make(map[context.Context]config.ReplicaID),
	}
	return wendyecSrv
}

func (wendyEC *fastwendyecServer) getClientID(ctx context.Context) (config.ReplicaID, error) {
	wendyEC.mut.RLock()
	// fast path for known stream
	if id, ok := wendyEC.clients[ctx]; ok {
		wendyEC.mut.RUnlock()
		return id, nil
	}

	wendyEC.mut.RUnlock()
	wendyEC.mut.Lock()
	defer wendyEC.mut.Unlock()

	// cleanup finished streams
	for ctx := range wendyEC.clients {
		if ctx.Err() != nil {
			delete(wendyEC.clients, ctx)
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, fmt.Errorf("getClientID: metadata not available")
	}

	v := md.Get("id")
	if len(v) < 1 {
		return 0, fmt.Errorf("getClientID: id field not present")
	}

	id, err := strconv.Atoi(v[0])
	if err != nil {
		return 0, fmt.Errorf("getClientID: cannot parse ID field: %w", err)
	}

	info, ok := wendyEC.Config.Replicas[config.ReplicaID(id)]
	if !ok {
		return 0, fmt.Errorf("getClientID: could not find info about id '%d'", id)
	}

	v = md.Get("proof")
	if len(v) < 2 {
		return 0, fmt.Errorf("getClientID: No proof found")
	}

	var R, S big.Int
	v0, err := base64.StdEncoding.DecodeString(v[0])
	if err != nil {
		return 0, fmt.Errorf("getClientID: could not decode proof: %v", err)
	}
	v1, err := base64.StdEncoding.DecodeString(v[1])
	if err != nil {
		return 0, fmt.Errorf("getClientID: could not decode proof: %v", err)
	}
	R.SetBytes(v0)
	S.SetBytes(v1)

	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(wendyEC.Config.ID))
	hash := sha256.Sum256(b[:])

	if !ecdsa.Verify(info.PubKey, hash[:], &R, &S) {
		return 0, fmt.Errorf("Invalid proof")
	}

	wendyEC.clients[ctx] = config.ReplicaID(id)
	return config.ReplicaID(id), nil
}

// Propose handles a replica's response to the Propose QC from the leader
func (wendyEC *fastwendyecServer) Propose(ctx context.Context, protoB *proto.Block) {
	block := protoB.FromProto()
	id, err := wendyEC.getClientID(ctx)
	if err != nil {
		logger.Printf("Failed to get client ID: %v", err)
		return
	}
	// defaults to 0 if error
	block.Proposer = id
	wendyEC.handlePropose(block)
}

func (wendyEC *fastwendyecServer) Vote(ctx context.Context, cert *proto.PartialCert) {
	wendyEC.OnReceiveVote(cert.FromProto())
}

// NewView handles the leader's response to receiving a NewView rpc from a replica
func (wendyEC *fastwendyecServer) NewView(ctx context.Context, msg *proto.NewViewMsg) {
	newViewMsg := msg.FromProto()
	proofNC := wendyEC.OnReceiveNewView(&newViewMsg)

	nackMsg := data.NackMsg{HighLockCertificate: wendyEC.GetQCHigh(), Hash: wendyEC.GetLeaf().Hash()}
	if wendyEC.viewBenchmark != 0 && proofNC >= wendyEC.Config.QuorumSize {
		//fmt.Println("Nack: " + newViewMsg.Message.V)
		proof := wendyEC.OnReceiveNack(&nackMsg, newViewMsg.Message.V)
		md, _ := metadata.FromIncomingContext(ctx)
		v := md.Get("id")
		id, _ := strconv.Atoi(v[0])

		if node, ok := wendyEC.nodes[config.ReplicaID(id)]; ok {
			node.ProofNoCommit(proto.ProofNCToProto(proof))
		}
	}
}

// Nack handles the leader's response to receiving a Nack rpc from a replica
func (wendyEC *fastwendyecServer) Nack(ctx context.Context, nackMsg *proto.NackMsg) {
	nack := nackMsg.FromProto()
	block, _ := wendyEC.Blocks.Get(nack.Hash)
	proof := wendyEC.OnReceiveNack(&nack, strconv.Itoa(block.Height))

	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get("id")
	id, _ := strconv.Atoi(v[0])

	if node, ok := wendyEC.nodes[config.ReplicaID(id)]; ok {
		node.ProofNoCommit(proto.ProofNCToProto(proof))
	}
}

// ProofNoCommit handles the replica's response to receiving a ProofNC rpc from a leader
func (wendyEC *fastwendyecServer) ProofNoCommit(ctx context.Context, proof *proto.ProofNC) {
	proofNC := proof.FromProto()
	wendyEC.OnReceiveProofNC(&proofNC)

	/*md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get("id")
	id, _ := strconv.Atoi(v[0])

	if err == nil {
		if node, ok := wendyEC.nodes[config.ReplicaID(id)]; ok {
			node.Vote(proto.PartialCertToProto(pc))
		}
	}*/
}
