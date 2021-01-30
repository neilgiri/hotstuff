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
	proto "github.com/relab/hotstuff/internal/proto/wendy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func init() {
	logger = logging.GetLogger()
}

// PacemakerWendy is a mechanism that provides synchronization
type PacemakerWendy interface {
	GetLeader(view int) config.ReplicaID
	Init(*Wendy)
}

// Wendy is a thing
type Wendy struct {
	*consensus.WendyCore
	tls bool

	pacemaker PacemakerWendy

	nodes map[config.ReplicaID]*proto.Node

	server  *wendyServer
	manager *proto.Manager
	cfg     *proto.Configuration

	closeOnce sync.Once

	qcTimeout      time.Duration
	connectTimeout time.Duration
}

//NewWendy creates a new GorumsHotStuff backend object.
func NewWendy(conf *config.ReplicaConfigBls, pacemaker PacemakerWendy, tls bool, connectTimeout, qcTimeout time.Duration) *Wendy {
	wendy := &Wendy{
		pacemaker:      pacemaker,
		WendyCore:      consensus.NewWendy(conf),
		nodes:          make(map[config.ReplicaID]*proto.Node),
		connectTimeout: connectTimeout,
		qcTimeout:      qcTimeout,
	}
	pacemaker.Init(wendy)
	return wendy
}

//Start starts the server and client
func (wendy *Wendy) Start() error {
	addr := wendy.Config.Replicas[wendy.Config.ID].Address
	err := wendy.startServer(addr)
	if err != nil {
		return fmt.Errorf("Failed to start GRPC Server: %w", err)
	}
	err = wendy.startClient(wendy.connectTimeout)
	if err != nil {
		return fmt.Errorf("Failed to start GRPC Clients: %w", err)
	}
	return nil
}

func (wendy *Wendy) startClient(connectTimeout time.Duration) error {
	idMapping := make(map[string]uint32, len(wendy.Config.Replicas)-1)
	for _, replica := range wendy.Config.Replicas {
		if replica.ID != wendy.Config.ID {
			idMapping[replica.Address] = uint32(replica.ID)
		}
	}

	// embed own ID to allow other replicas to identify messages from this replica
	md := metadata.New(map[string]string{
		"id": fmt.Sprintf("%d", wendy.Config.ID),
	})

	perNodeMD := func(nid uint32) metadata.MD {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], nid)
		hash := sha256.Sum256(b[:])
		R, S, err := ecdsa.Sign(rand.Reader, wendy.Config.PrivateKeyCert, hash[:])
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

	if wendy.tls {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(wendy.Config.CertPool, "")))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
	}

	mgrOpts = append(mgrOpts, proto.WithGrpcDialOptions(grpcOpts...))

	mgr, err := proto.NewManager(mgrOpts...)
	if err != nil {
		return fmt.Errorf("Failed to connect to replicas: %w", err)
	}
	wendy.manager = mgr

	for _, node := range mgr.Nodes() {
		wendy.nodes[config.ReplicaID(node.ID())] = node
	}

	wendy.cfg, err = wendy.manager.NewConfiguration(wendy.manager.NodeIDs(), &struct{}{})
	if err != nil {
		return fmt.Errorf("Failed to create configuration: %w", err)
	}

	return nil
}

// startServer runs a new instance of wendyServer
func (wendy *Wendy) startServer(port string) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("Failed to listen to port %s: %w", port, err)
	}

	serverOpts := []proto.ServerOption{}
	grpcServerOpts := []grpc.ServerOption{}

	if wendy.tls {
		grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewServerTLSFromCert(wendy.Config.Cert)))
	}

	serverOpts = append(serverOpts, proto.WithGRPCServerOptions(grpcServerOpts...))

	wendy.server = newWendyServer(wendy, proto.NewGorumsServer(serverOpts...))
	wendy.server.RegisterWendyServer(wendy.server)

	go wendy.server.Serve(lis)
	return nil
}

// Close closes all connections made by the HotStuff instance
func (wendy *Wendy) Close() {
	wendy.closeOnce.Do(func() {
		wendy.WendyCore.Close()
		wendy.manager.Close()
		wendy.server.Stop()
	})
}

// Propose broadcasts a new proposal to all replicas
func (wendy *Wendy) Propose() {
	proposal := wendy.CreateProposal()
	logger.Printf("Propose (%d commands): %s\n", len(proposal.Commands), proposal)
	protobuf := proto.BlockBlsToProto(proposal)

	wendy.cfg.Propose(protobuf)
	// self-vote
	wendy.handlePropose(proposal)
}

// SendNewView sends a NEW-VIEW message to a specific replica
func (wendy *Wendy) SendNewView(id config.ReplicaID) {
	qc := wendy.GetQCHigh()
	partialSig, bv := wendy.GetLockViewSig()
	bitVector := proto.BitVector{Bits: bv}
	newView := proto.NewViewBls{QC: proto.QuorumCertBlsToProto(qc), MultiSig: proto.PartialSigBlsToProto(partialSig), BV: &bitVector}
	if node, ok := wendy.nodes[id]; ok {
		node.NewView(&newView)
	}
}

func (wendy *Wendy) handlePropose(block *data.BlockBls) {
	p, err := wendy.OnReceiveProposal(block)
	if err != nil {
		logger.Println("OnReceiveProposal returned with error:", err)
		return
	}
	leaderID := wendy.pacemaker.GetLeader(block.Height)
	if wendy.Config.ID == leaderID {
		wendy.OnReceiveVote(p)
	} else if leader, ok := wendy.nodes[leaderID]; ok {
		leader.Vote(proto.PartialCertBlsToProto(p))
	}
}

type wendyServer struct {
	*Wendy
	*proto.GorumsServer
	// maps a stream context to client info
	mut     sync.RWMutex
	clients map[context.Context]config.ReplicaID
}

func newWendyServer(wendy *Wendy, srv *proto.GorumsServer) *wendyServer {
	wendySrv := &wendyServer{
		Wendy:        wendy,
		GorumsServer: srv,
		clients:      make(map[context.Context]config.ReplicaID),
	}
	return wendySrv
}

func (wendy *wendyServer) getClientID(ctx context.Context) (config.ReplicaID, error) {
	wendy.mut.RLock()
	// fast path for known stream
	if id, ok := wendy.clients[ctx]; ok {
		wendy.mut.RUnlock()
		return id, nil
	}

	wendy.mut.RUnlock()
	wendy.mut.Lock()
	defer wendy.mut.Unlock()

	// cleanup finished streams
	for ctx := range wendy.clients {
		if ctx.Err() != nil {
			delete(wendy.clients, ctx)
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

	info, ok := wendy.Config.Replicas[config.ReplicaID(id)]
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
	binary.LittleEndian.PutUint32(b[:], uint32(wendy.Config.ID))
	hash := sha256.Sum256(b[:])

	if !ecdsa.Verify(info.PubKey, hash[:], &R, &S) {
		return 0, fmt.Errorf("Invalid proof")
	}

	wendy.clients[ctx] = config.ReplicaID(id)
	return config.ReplicaID(id), nil
}

// Propose handles a replica's response to the Propose QC from the leader
func (wendy *wendyServer) Propose(ctx context.Context, protoB *proto.BlockBls) {
	block := protoB.FromProto()
	id, err := wendy.getClientID(ctx)
	if err != nil {
		logger.Printf("Failed to get client ID: %v", err)
		return
	}
	// defaults to 0 if error
	block.Proposer = id
	wendy.handlePropose(block)
}

func (wendy *wendyServer) Vote(ctx context.Context, cert *proto.PartialCertBls) {
	wendy.OnReceiveVote(cert.FromProto())
}

// NewView handles the leader's response to receiving a NewView rpc from a replica
func (wendy *wendyServer) NewView(ctx context.Context, msg *proto.NewViewBls) {

	//qc := msg.FromProto()
	//wendy.OnReceiveNewView(qc)
}

// ProofNoCommit handles response to locked replica
func (wendy *wendyServer) ProofNoCommit(ctx context.Context, msg *proto.Proof) {
	//qc := msg.FromProto()
	//wendy.OnReceiveNewView(qc)
}
