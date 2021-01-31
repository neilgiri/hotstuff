// Code generated by protoc-gen-gorums. DO NOT EDIT.

package proto

import (
	bytes "bytes"
	context "context"
	binary "encoding/binary"
	fmt "fmt"
	ordering "github.com/relab/gorums/ordering"
	trace "golang.org/x/net/trace"
	grpc "google.golang.org/grpc"
	backoff "google.golang.org/grpc/backoff"
	codes "google.golang.org/grpc/codes"
	encoding "google.golang.org/grpc/encoding"
	metadata "google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"
	protowire "google.golang.org/protobuf/encoding/protowire"
	proto "google.golang.org/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	fnv "hash/fnv"
	log "log"
	math "math"
	rand "math/rand"
	net "net"
	sort "sort"
	strconv "strconv"
	strings "strings"
	sync "sync"
	atomic "sync/atomic"
	time "time"
)

// A Configuration represents a static set of nodes on which quorum remote
// procedure calls may be invoked.
type Configuration struct {
	id    uint32
	nodes []*Node
	n     int
	mgr   *Manager
	qspec QuorumSpec
	errs  chan GRPCError
}

// NewConfig returns a configuration for the given node addresses and quorum spec.
// The returned func() must be called to close the underlying connections.
// This is an experimental API.
func NewConfig(qspec QuorumSpec, opts ...ManagerOption) (*Configuration, func(), error) {
	man, err := NewManager(opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create manager: %v", err)
	}
	c, err := man.NewConfiguration(man.NodeIDs(), qspec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create configuration: %v", err)
	}
	return c, func() { man.Close() }, nil
}

// ID reports the identifier for the configuration.
func (c *Configuration) ID() uint32 {
	return c.id
}

// NodeIDs returns a slice containing the local ids of all the nodes in the
// configuration. IDs are returned in the same order as they were provided in
// the creation of the Configuration.
func (c *Configuration) NodeIDs() []uint32 {
	ids := make([]uint32, len(c.nodes))
	for i, node := range c.nodes {
		ids[i] = node.ID()
	}
	return ids
}

// Nodes returns a slice of each available node. IDs are returned in the same
// order as they were provided in the creation of the Configuration.
func (c *Configuration) Nodes() []*Node {
	return c.nodes
}

// Size returns the number of nodes in the configuration.
func (c *Configuration) Size() int {
	return c.n
}

func (c *Configuration) String() string {
	return fmt.Sprintf("config-%d", c.id)
}

// Equal returns a boolean reporting whether a and b represents the same
// configuration.
func Equal(a, b *Configuration) bool { return a.id == b.id }

// SubError returns a channel for listening to individual node errors. Currently
// only a single listener is supported.
func (c *Configuration) SubError() <-chan GRPCError {
	return c.errs
}

const gorumsContentType = "gorums"

func init() {
	encoding.RegisterCodec(newGorumsCodec())
}

type gorumsMsgType uint8

const (
	gorumsRequest gorumsMsgType = iota + 1
	gorumsResponse
)

type gorumsMessage struct {
	metadata *ordering.Metadata
	message  protoreflect.ProtoMessage
	msgType  gorumsMsgType
}

// newGorumsMessage creates a new gorumsMessage struct for unmarshaling.
// msgType specifies the type of message that should be unmarshaled.
func newGorumsMessage(msgType gorumsMsgType) *gorumsMessage {
	return &gorumsMessage{metadata: &ordering.Metadata{}, msgType: msgType}
}

type gorumsCodec struct {
	marshaler   proto.MarshalOptions
	unmarshaler proto.UnmarshalOptions
}

func newGorumsCodec() *gorumsCodec {
	return &gorumsCodec{
		marshaler:   proto.MarshalOptions{AllowPartial: true},
		unmarshaler: proto.UnmarshalOptions{AllowPartial: true},
	}
}

func (c gorumsCodec) Name() string {
	return gorumsContentType
}

func (c gorumsCodec) String() string {
	return gorumsContentType
}

func (c gorumsCodec) Marshal(m interface{}) (b []byte, err error) {
	switch msg := m.(type) {
	case *gorumsMessage:
		return c.gorumsMarshal(msg)
	case protoreflect.ProtoMessage:
		return c.marshaler.Marshal(msg)
	default:
		return nil, fmt.Errorf("gorumsCodec: don't know how to marshal message of type '%T'", m)
	}
}

// gorumsMarshal marshals a metadata and a data message into a single byte slice.
func (c gorumsCodec) gorumsMarshal(msg *gorumsMessage) (b []byte, err error) {
	mdSize := c.marshaler.Size(msg.metadata)
	b = protowire.AppendVarint(b, uint64(mdSize))
	b, err = c.marshaler.MarshalAppend(b, msg.metadata)
	if err != nil {
		return nil, err
	}

	msgSize := c.marshaler.Size(msg.message)
	b = protowire.AppendVarint(b, uint64(msgSize))
	b, err = c.marshaler.MarshalAppend(b, msg.message)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c gorumsCodec) Unmarshal(b []byte, m interface{}) (err error) {
	switch msg := m.(type) {
	case *gorumsMessage:
		return c.gorumsUnmarshal(b, msg)
	case protoreflect.ProtoMessage:
		return c.unmarshaler.Unmarshal(b, msg)
	default:
		return fmt.Errorf("gorumsCodec: don't know how to unmarshal message of type '%T'", m)
	}
}

// gorumsUnmarshal unmarshals a metadata and a data message from a byte slice.
func (c gorumsCodec) gorumsUnmarshal(b []byte, msg *gorumsMessage) (err error) {
	mdBuf, mdLen := protowire.ConsumeBytes(b)
	err = c.unmarshaler.Unmarshal(mdBuf, msg.metadata)
	if err != nil {
		return err
	}
	info, ok := orderingMethods[msg.metadata.MethodID]
	if !ok {
		return fmt.Errorf("gorumsCodec: Unknown MethodID")
	}
	switch msg.msgType {
	case gorumsRequest:
		msg.message = info.requestType.New().Interface()
	case gorumsResponse:
		msg.message = info.responseType.New().Interface()
	default:
		return fmt.Errorf("gorumsCodec: Unknown message type")
	}
	msgBuf, _ := protowire.ConsumeBytes(b[mdLen:])
	err = c.unmarshaler.Unmarshal(msgBuf, msg.message)
	if err != nil {
		return err
	}
	return nil
}

// A NodeNotFoundError reports that a specified node could not be found.
type NodeNotFoundError uint32

func (e NodeNotFoundError) Error() string {
	return fmt.Sprintf("node not found: %d", e)
}

// A ConfigNotFoundError reports that a specified configuration could not be
// found.
type ConfigNotFoundError uint32

func (e ConfigNotFoundError) Error() string {
	return fmt.Sprintf("configuration not found: %d", e)
}

// An IllegalConfigError reports that a specified configuration could not be
// created.
type IllegalConfigError string

func (e IllegalConfigError) Error() string {
	return "illegal configuration: " + string(e)
}

// ManagerCreationError returns an error reporting that a Manager could not be
// created due to err.
func ManagerCreationError(err error) error {
	return fmt.Errorf("could not create manager: %s", err.Error())
}

// A QuorumCallError is used to report that a quorum call failed.
type QuorumCallError struct {
	Reason     string
	ReplyCount int
	Errors     []GRPCError
}

func (e QuorumCallError) Error() string {
	var b bytes.Buffer
	b.WriteString("quorum call error: ")
	b.WriteString(e.Reason)
	b.WriteString(fmt.Sprintf(" (errors: %d, replies: %d)", len(e.Errors), e.ReplyCount))
	if len(e.Errors) == 0 {
		return b.String()
	}
	b.WriteString("\ngrpc errors:\n")
	for _, err := range e.Errors {
		b.WriteByte('\t')
		b.WriteString(fmt.Sprintf("node %d: %v", err.NodeID, err.Cause))
		b.WriteByte('\n')
	}
	return b.String()
}

// GRPCError is used to report that a single gRPC call failed.
type GRPCError struct {
	NodeID uint32
	Cause  error
}

func (e GRPCError) Error() string {
	return fmt.Sprintf("node %d: %v", e.NodeID, e.Cause.Error())
}

// LevelNotSet is the zero value level used to indicate that no level (and
// thereby no reply) has been set for a correctable quorum call.
const LevelNotSet = -1

// Manager manages a pool of node configurations on which quorum remote
// procedure calls can be made.
type Manager struct {
	mu       sync.Mutex
	nodes    []*Node
	lookup   map[uint32]*Node
	configs  map[uint32]*Configuration
	eventLog trace.EventLog

	closeOnce sync.Once
	logger    *log.Logger
	opts      managerOptions

	*receiveQueue
}

// NewManager attempts to connect to the given set of node addresses and if
// successful returns a new Manager containing connections to those nodes.
func NewManager(opts ...ManagerOption) (*Manager, error) {

	m := &Manager{
		lookup:       make(map[uint32]*Node),
		configs:      make(map[uint32]*Configuration),
		receiveQueue: newReceiveQueue(),
		opts:         newManagerOptions(),
	}

	for _, opt := range opts {
		opt(&m.opts)
	}

	m.opts.grpcDialOpts = append(m.opts.grpcDialOpts, grpc.WithDefaultCallOptions(
		grpc.CallContentSubtype(gorumsContentType),
		grpc.ForceCodec(newGorumsCodec()),
	))

	if len(m.opts.addrsList) == 0 && len(m.opts.idMapping) == 0 {
		return nil, fmt.Errorf("could not create manager: no nodes provided")
	}

	if m.opts.backoff != backoff.DefaultConfig {
		m.opts.grpcDialOpts = append(m.opts.grpcDialOpts, grpc.WithConnectParams(
			grpc.ConnectParams{Backoff: m.opts.backoff},
		))
	}

	var nodeAddrs []string
	if m.opts.idMapping != nil {
		for naddr, id := range m.opts.idMapping {
			if m.lookup[id] != nil {
				err := fmt.Errorf("Two node ids are identical(id %d). Node ids have to be unique", id)
				return nil, ManagerCreationError(err)
			}
			nodeAddrs = append(nodeAddrs, naddr)
			node, err := m.createNode(naddr, id)
			if err != nil {
				return nil, ManagerCreationError(err)
			}
			m.lookup[node.id] = node
			m.nodes = append(m.nodes, node)
		}

		// Sort nodes since map iteration is non-deterministic.
		OrderedBy(ID).Sort(m.nodes)

	} else if m.opts.addrsList != nil {
		nodeAddrs = m.opts.addrsList
		for _, naddr := range m.opts.addrsList {
			node, err := m.createNode(naddr, 0)
			if err != nil {
				return nil, ManagerCreationError(err)
			}
			m.lookup[node.id] = node
			m.nodes = append(m.nodes, node)
		}
	}

	if m.opts.trace {
		title := strings.Join(nodeAddrs, ",")
		m.eventLog = trace.NewEventLog("gorums.Manager", title)
	}

	if err := m.connectAll(); err != nil {
		return nil, ManagerCreationError(err)
	}

	if m.opts.logger != nil {
		m.logger = m.opts.logger
	}

	if m.eventLog != nil {
		m.eventLog.Printf("ready")
	}

	return m, nil
}

func (m *Manager) createNode(addr string, id uint32) (*Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("create node %s error: %v", addr, err)
	}

	if id == 0 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(tcpAddr.String()))
		id = h.Sum32()
	}

	if _, found := m.lookup[id]; found {
		return nil, fmt.Errorf("create node %s error: node already exists", addr)
	}

	node := &Node{
		id:      id,
		addr:    tcpAddr.String(),
		latency: -1 * time.Second,
	}
	node.createOrderedStream(m.receiveQueue, m.opts)

	return node, nil
}

func (m *Manager) connectAll() error {
	if m.opts.noConnect {
		return nil
	}

	if m.eventLog != nil {
		m.eventLog.Printf("connecting")
	}

	for _, node := range m.nodes {
		err := node.connect(m.opts)
		if err != nil {
			if m.eventLog != nil {
				m.eventLog.Errorf("connect failed, error connecting to node %s, error: %v", node.addr, err)
			}
			return fmt.Errorf("connect node %s error: %v", node.addr, err)
		}
	}
	return nil
}

func (m *Manager) closeNodeConns() {
	for _, node := range m.nodes {
		err := node.close()
		if err == nil {
			continue
		}
		if m.logger != nil {
			m.logger.Printf("node %d: error closing: %v", node.id, err)
		}
	}
}

// Close closes all node connections and any client streams.
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		if m.eventLog != nil {
			m.eventLog.Printf("closing")
		}
		m.closeNodeConns()
	})
}

// NodeIDs returns the identifier of each available node. IDs are returned in
// the same order as they were provided in the creation of the Manager.
func (m *Manager) NodeIDs() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]uint32, 0, len(m.nodes))
	for _, node := range m.nodes {
		ids = append(ids, node.ID())
	}
	return ids
}

// Node returns the node with the given identifier if present.
func (m *Manager) Node(id uint32) (node *Node, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, found = m.lookup[id]
	return node, found
}

// Nodes returns a slice of each available node. IDs are returned in the same
// order as they were provided in the creation of the Manager.
func (m *Manager) Nodes() []*Node {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nodes
}

// ConfigurationIDs returns the identifier of each available
// configuration.
func (m *Manager) ConfigurationIDs() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]uint32, 0, len(m.configs))
	for id := range m.configs {
		ids = append(ids, id)
	}
	return ids
}

// Configuration returns the configuration with the given global
// identifier if present.
func (m *Manager) Configuration(id uint32) (config *Configuration, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	config, found = m.configs[id]
	return config, found
}

// Configurations returns a slice of each available configuration.
func (m *Manager) Configurations() []*Configuration {
	m.mu.Lock()
	defer m.mu.Unlock()
	configs := make([]*Configuration, 0, len(m.configs))
	for _, conf := range m.configs {
		configs = append(configs, conf)
	}
	return configs
}

// Size returns the number of nodes and configurations in the Manager.
func (m *Manager) Size() (nodes, configs int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.nodes), len(m.configs)
}

// AddNode attempts to dial to the provide node address. The node is
// added to the Manager's pool of nodes if a connection was established.
func (m *Manager) AddNode(addr string) error {
	panic("not implemented")
}

// NewConfiguration returns a new configuration given quorum specification and
// a timeout.
func (m *Manager) NewConfiguration(ids []uint32, qspec QuorumSpec) (*Configuration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(ids) == 0 {
		return nil, IllegalConfigError("need at least one node")
	}

	var nodes []*Node
	unique := make(map[uint32]struct{})
	var uniqueIDs []uint32
	for _, nid := range ids {
		// ensure that identical IDs are only counted once
		if _, duplicate := unique[nid]; duplicate {
			continue
		}
		unique[nid] = struct{}{}
		uniqueIDs = append(uniqueIDs, nid)

		node, found := m.lookup[nid]
		if !found {
			return nil, NodeNotFoundError(nid)
		}
		nodes = append(nodes, node)
	}

	// node IDs are sorted to ensure a globally consistent configuration ID
	sort.Sort(idSlice(uniqueIDs))

	h := fnv.New32a()
	for _, id := range uniqueIDs {
		_ = binary.Write(h, binary.LittleEndian, id)
	}
	cid := h.Sum32()

	conf, found := m.configs[cid]
	if found {
		return conf, nil
	}

	c := &Configuration{
		id:    cid,
		nodes: nodes,
		n:     len(nodes),
		mgr:   m,
		qspec: qspec,
	}
	m.configs[cid] = c

	return c, nil
}

type idSlice []uint32

func (p idSlice) Len() int { return len(p) }

func (p idSlice) Less(i, j int) bool { return p[i] < p[j] }

func (p idSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

const nilAngleString = "<nil>"

// Node encapsulates the state of a node on which a remote procedure call
// can be performed.
type Node struct {
	// Only assigned at creation.
	id      uint32
	addr    string
	conn    *grpc.ClientConn
	cancel  func()
	mu      sync.Mutex
	lastErr error
	latency time.Duration

	*orderedNodeStream

	// embed generated nodeServices
	nodeServices
}

func (n *Node) createOrderedStream(rq *receiveQueue, opts managerOptions) {
	n.orderedNodeStream = &orderedNodeStream{
		receiveQueue: rq,
		sendQ:        make(chan *gorumsMessage, opts.sendBuffer),
		node:         n,
		backoff:      opts.backoff,
		rand:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// connect to this node to facilitate gRPC calls and optionally client streams.
func (n *Node) connect(opts managerOptions) error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), opts.nodeDialTimeout)
	defer cancel()
	n.conn, err = grpc.DialContext(ctx, n.addr, opts.grpcDialOpts...)
	if err != nil {
		return fmt.Errorf("dialing node failed: %w", err)
	}
	md := opts.metadata.Copy()
	if opts.perNodeMD != nil {
		md = metadata.Join(md, opts.perNodeMD(n.id))
	}
	// a context for all of the streams
	ctx, n.cancel = context.WithCancel(context.Background())
	ctx = metadata.NewOutgoingContext(ctx, md)
	// only start ordering RPCs when needed
	if hasOrderingMethods {
		err = n.connectOrderedStream(ctx, n.conn)
		if err != nil {
			return fmt.Errorf("starting stream failed: %w", err)
		}
	}
	return n.connectStream(ctx) // call generated method
}

// close this node for further calls and optionally stream.
func (n *Node) close() error {
	if err := n.conn.Close(); err != nil {
		return fmt.Errorf("%d: conn close error: %w", n.id, err)
	}
	err := n.closeStream() // call generated method
	n.cancel()
	return err
}

// ID returns the ID of n.
func (n *Node) ID() uint32 {
	if n != nil {
		return n.id
	}
	return 0
}

// Address returns network address of n.
func (n *Node) Address() string {
	if n != nil {
		return n.addr
	}
	return nilAngleString
}

// Port returns network port of n.
func (n *Node) Port() string {
	if n != nil {
		_, port, _ := net.SplitHostPort(n.addr)
		return port
	}
	return nilAngleString
}

func (n *Node) String() string {
	if n != nil {
		return fmt.Sprintf("addr: %s", n.addr)
	}
	return nilAngleString
}

// FullString returns a more descriptive string representation of n that
// includes id, network address and latency information.
func (n *Node) FullString() string {
	if n != nil {
		n.mu.Lock()
		defer n.mu.Unlock()
		return fmt.Sprintf(
			"node %d | addr: %s | latency: %v",
			n.id, n.addr, n.latency,
		)
	}
	return nilAngleString
}

func (n *Node) setLastErr(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lastErr = err
}

// LastErr returns the last error encountered (if any) when invoking a remote
// procedure call on this node.
func (n *Node) LastErr() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastErr
}

func (n *Node) setLatency(lat time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.latency = lat
}

// Latency returns the latency of the last successful remote procedure call
// made to this node.
func (n *Node) Latency() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.latency
}

type lessFunc func(n1, n2 *Node) bool

// MultiSorter implements the Sort interface, sorting the nodes within.
type MultiSorter struct {
	nodes []*Node
	less  []lessFunc
}

// Sort sorts the argument slice according to the less functions passed to
// OrderedBy.
func (ms *MultiSorter) Sort(nodes []*Node) {
	ms.nodes = nodes
	sort.Sort(ms)
}

// OrderedBy returns a Sorter that sorts using the less functions, in order.
// Call its Sort method to sort the data.
func OrderedBy(less ...lessFunc) *MultiSorter {
	return &MultiSorter{
		less: less,
	}
}

// Len is part of sort.Interface.
func (ms *MultiSorter) Len() int {
	return len(ms.nodes)
}

// Swap is part of sort.Interface.
func (ms *MultiSorter) Swap(i, j int) {
	ms.nodes[i], ms.nodes[j] = ms.nodes[j], ms.nodes[i]
}

// Less is part of sort.Interface. It is implemented by looping along the
// less functions until it finds a comparison that is either Less or
// !Less. Note that it can call the less functions twice per call. We
// could change the functions to return -1, 0, 1 and reduce the
// number of calls for greater efficiency: an exercise for the reader.
func (ms *MultiSorter) Less(i, j int) bool {
	p, q := ms.nodes[i], ms.nodes[j]
	// Try all but the last comparison.
	var k int
	for k = 0; k < len(ms.less)-1; k++ {
		less := ms.less[k]
		switch {
		case less(p, q):
			// p < q, so we have a decision.
			return true
		case less(q, p):
			// p > q, so we have a decision.
			return false
		}
		// p == q; try the next comparison.
	}
	// All comparisons to here said "equal", so just return whatever
	// the final comparison reports.
	return ms.less[k](p, q)
}

// ID sorts nodes by their identifier in increasing order.
var ID = func(n1, n2 *Node) bool {
	return n1.id < n2.id
}

// Port sorts nodes by their port number in increasing order.
// Warning: This function may be removed in the future.
var Port = func(n1, n2 *Node) bool {
	p1, _ := strconv.Atoi(n1.Port())
	p2, _ := strconv.Atoi(n2.Port())
	return p1 < p2
}

// Latency sorts nodes by latency in increasing order. Latencies less then
// zero (sentinel value) are considered greater than any positive latency.
var Latency = func(n1, n2 *Node) bool {
	if n1.latency < 0 {
		return false
	}
	return n1.latency < n2.latency
}

// Error sorts nodes by their LastErr() status in increasing order. A
// node with LastErr() != nil is larger than a node with LastErr() == nil.
var Error = func(n1, n2 *Node) bool {
	if n1.lastErr != nil && n2.lastErr == nil {
		return false
	}
	return true
}

type managerOptions struct {
	grpcDialOpts    []grpc.DialOption
	nodeDialTimeout time.Duration
	logger          *log.Logger
	noConnect       bool
	trace           bool
	backoff         backoff.Config
	sendBuffer      uint
	idMapping       map[string]uint32
	addrsList       []string
	metadata        metadata.MD
	perNodeMD       func(uint32) metadata.MD
}

func newManagerOptions() managerOptions {
	return managerOptions{
		backoff:    backoff.DefaultConfig,
		sendBuffer: 0,
	}
}

// ManagerOption provides a way to set different options on a new Manager.
type ManagerOption func(*managerOptions)

// WithDialTimeout returns a ManagerOption which is used to set the dial
// context timeout to be used when initially connecting to each node in its pool.
func WithDialTimeout(timeout time.Duration) ManagerOption {
	return func(o *managerOptions) {
		o.nodeDialTimeout = timeout
	}
}

// WithGrpcDialOptions returns a ManagerOption which sets any gRPC dial options
// the Manager should use when initially connecting to each node in its pool.
func WithGrpcDialOptions(opts ...grpc.DialOption) ManagerOption {
	return func(o *managerOptions) {
		o.grpcDialOpts = append(o.grpcDialOpts, opts...)
	}
}

// WithLogger returns a ManagerOption which sets an optional error logger for
// the Manager.
func WithLogger(logger *log.Logger) ManagerOption {
	return func(o *managerOptions) {
		o.logger = logger
	}
}

// WithNoConnect returns a ManagerOption which instructs the Manager not to
// connect to any of its nodes. Mainly used for testing purposes.
func WithNoConnect() ManagerOption {
	return func(o *managerOptions) {
		o.noConnect = true
	}
}

// WithTracing controls whether to trace quorum calls for this Manager instance
// using the golang.org/x/net/trace package. Tracing is currently only supported
// for regular quorum calls.
func WithTracing() ManagerOption {
	return func(o *managerOptions) {
		o.trace = true
	}
}

// WithBackoff allows for changing the backoff delays used by Gorums.
func WithBackoff(backoff backoff.Config) ManagerOption {
	return func(o *managerOptions) {
		o.backoff = backoff
	}
}

// WithSendBufferSize allows for changing the size of the send buffer used by Gorums.
// A larger buffer might achieve higher throughput for asynchronous calltypes, but at
// the cost of latency.
func WithSendBufferSize(size uint) ManagerOption {
	return func(o *managerOptions) {
		o.sendBuffer = size
	}
}

// WithNodeMap returns a ManagerOption containing the provided mapping from node addresses to application-specific IDs.
func WithNodeMap(idMap map[string]uint32) ManagerOption {
	return func(o *managerOptions) {
		o.idMapping = idMap
	}
}

// WithNodeList returns a ManagerOption containing the provided list of node addresses.
// With this option, NodeIDs are generated by the Manager.
func WithNodeList(addrsList []string) ManagerOption {
	return func(o *managerOptions) {
		o.addrsList = addrsList
	}
}

// WithMetadata returns a ManagerOption that sets the metadata that is sent to each node
// when the connection is initially established. This metadata can be retrieved from the
// server-side method handlers.
func WithMetadata(md metadata.MD) ManagerOption {
	return func(o *managerOptions) {
		o.metadata = md
	}
}

// WithPerNodeMetadata returns a ManagerOption that allows you to set metadata for each
// node individually.
func WithPerNodeMetadata(f func(uint32) metadata.MD) ManagerOption {
	return func(o *managerOptions) {
		o.perNodeMD = f
	}
}

type methodInfo struct {
	requestType  protoreflect.Message
	responseType protoreflect.Message
}

type orderingResult struct {
	nid   uint32
	reply protoreflect.ProtoMessage
	err   error
}

type receiveQueue struct {
	msgID    uint64
	recvQ    map[uint64]chan *orderingResult
	recvQMut sync.RWMutex
}

func newReceiveQueue() *receiveQueue {
	return &receiveQueue{
		recvQ: make(map[uint64]chan *orderingResult),
	}
}

func (m *receiveQueue) nextMsgID() uint64 {
	return atomic.AddUint64(&m.msgID, 1)
}

func (m *receiveQueue) putChan(id uint64, c chan *orderingResult) {
	m.recvQMut.Lock()
	m.recvQ[id] = c
	m.recvQMut.Unlock()
}

func (m *receiveQueue) deleteChan(id uint64) {
	m.recvQMut.Lock()
	delete(m.recvQ, id)
	m.recvQMut.Unlock()
}

func (m *receiveQueue) putResult(id uint64, result *orderingResult) {
	m.recvQMut.RLock()
	c, ok := m.recvQ[id]
	m.recvQMut.RUnlock()
	if ok {
		c <- result
	}
}

type orderedNodeStream struct {
	*receiveQueue
	sendQ        chan *gorumsMessage
	node         *Node // needed for ID and setLastError
	backoff      backoff.Config
	rand         *rand.Rand
	gorumsClient ordering.GorumsClient
	gorumsStream ordering.Gorums_NodeStreamClient
	streamMut    sync.RWMutex
	streamBroken uint32
}

func (s *orderedNodeStream) connectOrderedStream(ctx context.Context, conn *grpc.ClientConn) error {
	var err error
	s.gorumsClient = ordering.NewGorumsClient(conn)
	s.gorumsStream, err = s.gorumsClient.NodeStream(ctx)
	if err != nil {
		return err
	}
	go s.sendMsgs(ctx)
	go s.recvMsgs(ctx)
	return nil
}

func (s *orderedNodeStream) sendMsgs(ctx context.Context) {
	var req *gorumsMessage
	for {
		select {
		case <-ctx.Done():
			return
		case req = <-s.sendQ:
		}
		// return error if stream is broken
		if atomic.LoadUint32(&s.streamBroken) == 1 {
			err := status.Errorf(codes.Unavailable, "stream is down")
			s.putResult(req.metadata.MessageID, &orderingResult{nid: s.node.ID(), reply: nil, err: err})
			continue
		}
		// else try to send message
		s.streamMut.RLock()
		err := s.gorumsStream.SendMsg(req)
		if err == nil {
			s.streamMut.RUnlock()
			continue
		}
		atomic.StoreUint32(&s.streamBroken, 1)
		s.streamMut.RUnlock()
		s.node.setLastErr(err)
		// return the error
		s.putResult(req.metadata.MessageID, &orderingResult{nid: s.node.ID(), reply: nil, err: err})
	}
}

func (s *orderedNodeStream) recvMsgs(ctx context.Context) {
	for {
		resp := newGorumsMessage(gorumsResponse)
		s.streamMut.RLock()
		err := s.gorumsStream.RecvMsg(resp)
		if err != nil {
			atomic.StoreUint32(&s.streamBroken, 1)
			s.streamMut.RUnlock()
			s.node.setLastErr(err)
			// attempt to reconnect
			s.reconnectStream(ctx)
		} else {
			s.streamMut.RUnlock()
			err := status.FromProto(resp.metadata.GetStatus()).Err()
			s.putResult(resp.metadata.MessageID, &orderingResult{nid: s.node.ID(), reply: resp.message, err: err})
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (s *orderedNodeStream) reconnectStream(ctx context.Context) {
	s.streamMut.Lock()
	defer s.streamMut.Unlock()

	var retries float64
	for {
		var err error
		s.gorumsStream, err = s.gorumsClient.NodeStream(ctx)
		if err == nil {
			atomic.StoreUint32(&s.streamBroken, 0)
			return
		}
		s.node.setLastErr(err)
		delay := float64(s.backoff.BaseDelay)
		max := float64(s.backoff.MaxDelay)
		for r := retries; delay < max && r > 0; r-- {
			delay *= s.backoff.Multiplier
		}
		delay = math.Min(delay, max)
		delay *= 1 + s.backoff.Jitter*(rand.Float64()*2-1)
		select {
		case <-time.After(time.Duration(delay)):
			retries++
		case <-ctx.Done():
			return
		}
	}
}

// requestHandler is used to fetch a response message based on the request.
// A requestHandler should receive a message from the server, unmarshal it into
// the proper type for that Method's request type, call a user provided Handler,
// and return a marshaled result to the server.
type requestHandler func(context.Context, *gorumsMessage, chan<- *gorumsMessage)

type orderingServer struct {
	handlers map[int32]requestHandler
	opts     *serverOptions
	ordering.UnimplementedGorumsServer
}

func newOrderingServer(opts *serverOptions) *orderingServer {
	s := &orderingServer{
		handlers: make(map[int32]requestHandler),
		opts:     opts,
	}
	return s
}

// wrapMessage wraps the metadata, response and error status in a gorumsMessage
func wrapMessage(md *ordering.Metadata, resp protoreflect.ProtoMessage, err error) *gorumsMessage {
	errStatus, ok := status.FromError(err)
	if !ok {
		errStatus = status.New(codes.Unknown, err.Error())
	}
	md.Status = errStatus.Proto()
	return &gorumsMessage{metadata: md, message: resp}
}

// NodeStream handles a connection to a single client. The stream is aborted if there
// is any error with sending or receiving.
func (s *orderingServer) NodeStream(srv ordering.Gorums_NodeStreamServer) error {
	finished := make(chan *gorumsMessage, s.opts.buffer)
	ctx := srv.Context()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-finished:
				err := srv.SendMsg(msg)
				if err != nil {
					return
				}
			}
		}
	}()

	for {
		req := newGorumsMessage(gorumsRequest)
		err := srv.RecvMsg(req)
		if err != nil {
			return err
		}
		if handler, ok := s.handlers[req.metadata.MethodID]; ok {
			handler(ctx, req, finished)
		}
	}
}

type serverOptions struct {
	buffer   uint
	grpcOpts []grpc.ServerOption
}

// ServerOption is used to change settings for the GorumsServer
type ServerOption func(*serverOptions)

// WithServerBufferSize sets the buffer size for the server.
// A larger buffer may result in higher throughput at the cost of higher latency.
func WithServerBufferSize(size uint) ServerOption {
	return func(o *serverOptions) {
		o.buffer = size
	}
}

// WithGRPCServerOptions allows to set gRPC options for the server.
func WithGRPCServerOptions(opts ...grpc.ServerOption) ServerOption {
	return func(o *serverOptions) {
		o.grpcOpts = append(o.grpcOpts, opts...)
	}
}

// GorumsServer serves all ordering based RPCs using registered handlers.
type GorumsServer struct {
	srv        *orderingServer
	grpcServer *grpc.Server
}

// NewGorumsServer returns a new instance of GorumsServer.
func NewGorumsServer(opts ...ServerOption) *GorumsServer {
	var serverOpts serverOptions
	for _, opt := range opts {
		opt(&serverOpts)
	}
	serverOpts.grpcOpts = append(serverOpts.grpcOpts, grpc.CustomCodec(newGorumsCodec()))
	s := &GorumsServer{
		srv:        newOrderingServer(&serverOpts),
		grpcServer: grpc.NewServer(serverOpts.grpcOpts...),
	}
	ordering.RegisterGorumsServer(s.grpcServer, s.srv)
	return s
}

// Serve starts serving on the listener.
func (s *GorumsServer) Serve(listener net.Listener) error {
	return s.grpcServer.Serve(listener)
}

// GracefulStop waits for all RPCs to finish before stopping.
func (s *GorumsServer) GracefulStop() {
	s.grpcServer.GracefulStop()
}

// Stop stops the server immediately.
func (s *GorumsServer) Stop() {
	s.grpcServer.Stop()
}

type traceInfo struct {
	trace.Trace
	firstLine firstLine
}

type firstLine struct {
	deadline time.Duration
	cid      uint32
}

func (f firstLine) String() string {
	if f.deadline != 0 {
		return fmt.Sprintf("QC: to config%d deadline: %d", f.cid, f.deadline)
	}
	return fmt.Sprintf("QC: to config%d deadline: none", f.cid)
}

type payload struct {
	sent bool
	id   uint32
	msg  interface{}
}

func (p payload) String() string {
	if p.sent {
		return fmt.Sprintf("sent: %v", p.msg)
	}
	return fmt.Sprintf("recv from %d: %v", p.id, p.msg)
}

type qcresult struct {
	ids   []uint32
	reply interface{}
	err   error
}

func (q qcresult) String() string {
	if q.err == nil {
		return fmt.Sprintf("recv QC reply: ids: %v, reply: %v", q.ids, q.reply)
	}
	return fmt.Sprintf("recv QC reply: ids: %v, reply: %v, error: %v", q.ids, q.reply, q.err)
}

func appendIfNotPresent(set []uint32, x uint32) []uint32 {
	for _, y := range set {
		if y == x {
			return set
		}
	}
	return append(set, x)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ emptypb.Empty

// Propose is a one-way multicast call on all nodes in configuration c,
// with the same in argument. The call is asynchronous and has no return value.
func (c *Configuration) Propose(in *BlockBls) error {
	msgID := c.mgr.nextMsgID()
	metadata := &ordering.Metadata{
		MessageID: msgID,
		MethodID:  proposeMethodID,
	}
	msg := &gorumsMessage{metadata: metadata, message: in}
	for _, n := range c.nodes {
		n.sendQ <- msg
	}
	return nil
}

type nodeServices struct {
}

func (n *Node) connectStream(ctx context.Context) (err error) {

	return nil
}

func (n *Node) closeStream() (err error) {
	return err
}

// QuorumSpec is the interface of quorum functions for Wendy.
type QuorumSpec interface {
}

// Wendy is the server-side API for the Wendy Service
type Wendy interface {
	Propose(context.Context, *BlockBls)
	Vote(context.Context, *PartialCertBls)
	NewView(context.Context, *NewViewBls)
	ProofNoCommit(context.Context, *Proof)
}

func (s *GorumsServer) RegisterWendyServer(srv Wendy) {
	s.srv.handlers[proposeMethodID] = func(ctx context.Context, in *gorumsMessage, _ chan<- *gorumsMessage) {
		req := in.message.(*BlockBls)
		srv.Propose(ctx, req)
	}
	s.srv.handlers[voteMethodID] = func(ctx context.Context, in *gorumsMessage, _ chan<- *gorumsMessage) {
		req := in.message.(*PartialCertBls)
		srv.Vote(ctx, req)
	}
	s.srv.handlers[newViewMethodID] = func(ctx context.Context, in *gorumsMessage, _ chan<- *gorumsMessage) {
		req := in.message.(*NewViewBls)
		srv.NewView(ctx, req)
	}
	s.srv.handlers[proofNoCommitMethodID] = func(ctx context.Context, in *gorumsMessage, _ chan<- *gorumsMessage) {
		req := in.message.(*Proof)
		srv.ProofNoCommit(ctx, req)
	}
}

const hasOrderingMethods = true

const proposeMethodID int32 = 0
const voteMethodID int32 = 1
const newViewMethodID int32 = 2
const proofNoCommitMethodID int32 = 3

var orderingMethods = map[int32]methodInfo{

	0: {requestType: new(BlockBls).ProtoReflect(), responseType: new(emptypb.Empty).ProtoReflect()},
	1: {requestType: new(PartialCertBls).ProtoReflect(), responseType: new(emptypb.Empty).ProtoReflect()},
	2: {requestType: new(NewViewBls).ProtoReflect(), responseType: new(emptypb.Empty).ProtoReflect()},
	3: {requestType: new(Proof).ProtoReflect(), responseType: new(emptypb.Empty).ProtoReflect()},
}

// Reference imports to suppress errors if they are not otherwise used.
var _ emptypb.Empty

func (n *Node) Vote(in *PartialCertBls) error {
	msgID := n.nextMsgID()
	metadata := &ordering.Metadata{
		MessageID: msgID,
		MethodID:  voteMethodID,
	}
	msg := &gorumsMessage{metadata: metadata, message: in}
	n.sendQ <- msg
	return nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ emptypb.Empty

func (n *Node) NewView(in *NewViewBls) error {
	msgID := n.nextMsgID()
	metadata := &ordering.Metadata{
		MessageID: msgID,
		MethodID:  newViewMethodID,
	}
	msg := &gorumsMessage{metadata: metadata, message: in}
	n.sendQ <- msg
	return nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ emptypb.Empty

func (n *Node) ProofNoCommit(in *Proof) error {
	msgID := n.nextMsgID()
	metadata := &ordering.Metadata{
		MessageID: msgID,
		MethodID:  proofNoCommitMethodID,
	}
	msg := &gorumsMessage{metadata: metadata, message: in}
	n.sendQ <- msg
	return nil
}