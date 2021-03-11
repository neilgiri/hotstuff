// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: internal/proto/fastwendyec/fastwendyec.proto

package proto

import (
	proto "github.com/golang/protobuf/proto"
	_ "github.com/relab/gorums"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Block struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ParentHash []byte      `protobuf:"bytes,1,opt,name=ParentHash,proto3" json:"ParentHash,omitempty"`
	QC         *QuorumCert `protobuf:"bytes,2,opt,name=QC,proto3" json:"QC,omitempty"`
	Height     int64       `protobuf:"varint,3,opt,name=Height,proto3" json:"Height,omitempty"`
	Commands   []*Command  `protobuf:"bytes,4,rep,name=Commands,proto3" json:"Commands,omitempty"`
}

func (x *Block) Reset() {
	*x = Block{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Block) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Block) ProtoMessage() {}

func (x *Block) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Block.ProtoReflect.Descriptor instead.
func (*Block) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{0}
}

func (x *Block) GetParentHash() []byte {
	if x != nil {
		return x.ParentHash
	}
	return nil
}

func (x *Block) GetQC() *QuorumCert {
	if x != nil {
		return x.QC
	}
	return nil
}

func (x *Block) GetHeight() int64 {
	if x != nil {
		return x.Height
	}
	return 0
}

func (x *Block) GetCommands() []*Command {
	if x != nil {
		return x.Commands
	}
	return nil
}

type PartialSig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ReplicaID int32  `protobuf:"varint,1,opt,name=ReplicaID,proto3" json:"ReplicaID,omitempty"`
	R         []byte `protobuf:"bytes,2,opt,name=R,proto3" json:"R,omitempty"`
	S         []byte `protobuf:"bytes,3,opt,name=S,proto3" json:"S,omitempty"`
}

func (x *PartialSig) Reset() {
	*x = PartialSig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PartialSig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PartialSig) ProtoMessage() {}

func (x *PartialSig) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PartialSig.ProtoReflect.Descriptor instead.
func (*PartialSig) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{1}
}

func (x *PartialSig) GetReplicaID() int32 {
	if x != nil {
		return x.ReplicaID
	}
	return 0
}

func (x *PartialSig) GetR() []byte {
	if x != nil {
		return x.R
	}
	return nil
}

func (x *PartialSig) GetS() []byte {
	if x != nil {
		return x.S
	}
	return nil
}

type PartialCert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sig  *PartialSig `protobuf:"bytes,1,opt,name=Sig,proto3" json:"Sig,omitempty"`
	Hash []byte      `protobuf:"bytes,2,opt,name=Hash,proto3" json:"Hash,omitempty"`
}

func (x *PartialCert) Reset() {
	*x = PartialCert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PartialCert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PartialCert) ProtoMessage() {}

func (x *PartialCert) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PartialCert.ProtoReflect.Descriptor instead.
func (*PartialCert) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{2}
}

func (x *PartialCert) GetSig() *PartialSig {
	if x != nil {
		return x.Sig
	}
	return nil
}

func (x *PartialCert) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

type QuorumCert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sigs []*PartialSig `protobuf:"bytes,1,rep,name=Sigs,proto3" json:"Sigs,omitempty"`
	Hash []byte        `protobuf:"bytes,2,opt,name=Hash,proto3" json:"Hash,omitempty"`
}

func (x *QuorumCert) Reset() {
	*x = QuorumCert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuorumCert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuorumCert) ProtoMessage() {}

func (x *QuorumCert) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuorumCert.ProtoReflect.Descriptor instead.
func (*QuorumCert) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{3}
}

func (x *QuorumCert) GetSigs() []*PartialSig {
	if x != nil {
		return x.Sigs
	}
	return nil
}

func (x *QuorumCert) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

type AggMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C []byte `protobuf:"bytes,1,opt,name=C,proto3" json:"C,omitempty"`
	V []byte `protobuf:"bytes,2,opt,name=V,proto3" json:"V,omitempty"`
}

func (x *AggMessage) Reset() {
	*x = AggMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AggMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AggMessage) ProtoMessage() {}

func (x *AggMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AggMessage.ProtoReflect.Descriptor instead.
func (*AggMessage) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{4}
}

func (x *AggMessage) GetC() []byte {
	if x != nil {
		return x.C
	}
	return nil
}

func (x *AggMessage) GetV() []byte {
	if x != nil {
		return x.V
	}
	return nil
}

type NewViewMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LockCertificate *QuorumCert `protobuf:"bytes,1,opt,name=LockCertificate,proto3" json:"LockCertificate,omitempty"`
	Message         *AggMessage `protobuf:"bytes,2,opt,name=Message,proto3" json:"Message,omitempty"`
	Signature       []byte      `protobuf:"bytes,3,opt,name=Signature,proto3" json:"Signature,omitempty"`
	ReplicaID       int32       `protobuf:"varint,4,opt,name=ReplicaID,proto3" json:"ReplicaID,omitempty"`
}

func (x *NewViewMsg) Reset() {
	*x = NewViewMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NewViewMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NewViewMsg) ProtoMessage() {}

func (x *NewViewMsg) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NewViewMsg.ProtoReflect.Descriptor instead.
func (*NewViewMsg) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{5}
}

func (x *NewViewMsg) GetLockCertificate() *QuorumCert {
	if x != nil {
		return x.LockCertificate
	}
	return nil
}

func (x *NewViewMsg) GetMessage() *AggMessage {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *NewViewMsg) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *NewViewMsg) GetReplicaID() int32 {
	if x != nil {
		return x.ReplicaID
	}
	return 0
}

type Command struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data []byte `protobuf:"bytes,1,opt,name=Data,proto3" json:"Data,omitempty"`
}

func (x *Command) Reset() {
	*x = Command{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command) ProtoMessage() {}

func (x *Command) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Command.ProtoReflect.Descriptor instead.
func (*Command) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{6}
}

func (x *Command) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type Index struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ReplicaID int32 `protobuf:"varint,1,opt,name=ReplicaID,proto3" json:"ReplicaID,omitempty"`
	Exists    bool  `protobuf:"varint,2,opt,name=Exists,proto3" json:"Exists,omitempty"`
}

func (x *Index) Reset() {
	*x = Index{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Index) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Index) ProtoMessage() {}

func (x *Index) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Index.ProtoReflect.Descriptor instead.
func (*Index) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{7}
}

func (x *Index) GetReplicaID() int32 {
	if x != nil {
		return x.ReplicaID
	}
	return 0
}

func (x *Index) GetExists() bool {
	if x != nil {
		return x.Exists
	}
	return false
}

// KeyAggMessagePair type
type KeyAggMessagePair struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PK [][]byte    `protobuf:"bytes,1,rep,name=PK,proto3" json:"PK,omitempty"`
	M  *AggMessage `protobuf:"bytes,2,opt,name=M,proto3" json:"M,omitempty"`
}

func (x *KeyAggMessagePair) Reset() {
	*x = KeyAggMessagePair{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyAggMessagePair) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyAggMessagePair) ProtoMessage() {}

func (x *KeyAggMessagePair) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyAggMessagePair.ProtoReflect.Descriptor instead.
func (*KeyAggMessagePair) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{8}
}

func (x *KeyAggMessagePair) GetPK() [][]byte {
	if x != nil {
		return x.PK
	}
	return nil
}

func (x *KeyAggMessagePair) GetM() *AggMessage {
	if x != nil {
		return x.M
	}
	return nil
}

type ProofNC struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MessagePairs []*KeyAggMessagePair `protobuf:"bytes,1,rep,name=MessagePairs,proto3" json:"MessagePairs,omitempty"`
	Signature    []byte               `protobuf:"bytes,2,opt,name=Signature,proto3" json:"Signature,omitempty"`
	Hash         []byte               `protobuf:"bytes,3,opt,name=Hash,proto3" json:"Hash,omitempty"`
}

func (x *ProofNC) Reset() {
	*x = ProofNC{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProofNC) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProofNC) ProtoMessage() {}

func (x *ProofNC) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProofNC.ProtoReflect.Descriptor instead.
func (*ProofNC) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{9}
}

func (x *ProofNC) GetMessagePairs() []*KeyAggMessagePair {
	if x != nil {
		return x.MessagePairs
	}
	return nil
}

func (x *ProofNC) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *ProofNC) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

type NackMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	QC   *QuorumCert `protobuf:"bytes,1,opt,name=QC,proto3" json:"QC,omitempty"`
	Hash []byte      `protobuf:"bytes,2,opt,name=Hash,proto3" json:"Hash,omitempty"`
}

func (x *NackMsg) Reset() {
	*x = NackMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NackMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NackMsg) ProtoMessage() {}

func (x *NackMsg) ProtoReflect() protoreflect.Message {
	mi := &file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NackMsg.ProtoReflect.Descriptor instead.
func (*NackMsg) Descriptor() ([]byte, []int) {
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP(), []int{10}
}

func (x *NackMsg) GetQC() *QuorumCert {
	if x != nil {
		return x.QC
	}
	return nil
}

func (x *NackMsg) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

var File_internal_proto_fastwendyec_fastwendyec_proto protoreflect.FileDescriptor

var file_internal_proto_fastwendyec_fastwendyec_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x66, 0x61, 0x73, 0x74, 0x77, 0x65, 0x6e, 0x64, 0x79, 0x65, 0x63, 0x2f, 0x66, 0x61, 0x73,
	0x74, 0x77, 0x65, 0x6e, 0x64, 0x79, 0x65, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x67, 0x6f, 0x72, 0x75, 0x6d, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x8e, 0x01, 0x0a, 0x05, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x1e, 0x0a, 0x0a, 0x50, 0x61,
	0x72, 0x65, 0x6e, 0x74, 0x48, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a,
	0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x48, 0x61, 0x73, 0x68, 0x12, 0x21, 0x0a, 0x02, 0x51, 0x43,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x51,
	0x75, 0x6f, 0x72, 0x75, 0x6d, 0x43, 0x65, 0x72, 0x74, 0x52, 0x02, 0x51, 0x43, 0x12, 0x16, 0x0a,
	0x06, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x48,
	0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x2a, 0x0a, 0x08, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
	0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x08, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
	0x73, 0x22, 0x46, 0x0a, 0x0a, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x12,
	0x1c, 0x0a, 0x09, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x09, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x49, 0x44, 0x12, 0x0c, 0x0a,
	0x01, 0x52, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x52, 0x12, 0x0c, 0x0a, 0x01, 0x53,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x53, 0x22, 0x46, 0x0a, 0x0b, 0x50, 0x61, 0x72,
	0x74, 0x69, 0x61, 0x6c, 0x43, 0x65, 0x72, 0x74, 0x12, 0x23, 0x0a, 0x03, 0x53, 0x69, 0x67, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x61,
	0x72, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x52, 0x03, 0x53, 0x69, 0x67, 0x12, 0x12, 0x0a,
	0x04, 0x48, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x48, 0x61, 0x73,
	0x68, 0x22, 0x47, 0x0a, 0x0a, 0x51, 0x75, 0x6f, 0x72, 0x75, 0x6d, 0x43, 0x65, 0x72, 0x74, 0x12,
	0x25, 0x0a, 0x04, 0x53, 0x69, 0x67, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x67,
	0x52, 0x04, 0x53, 0x69, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x61, 0x73, 0x68, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x48, 0x61, 0x73, 0x68, 0x22, 0x28, 0x0a, 0x0a, 0x41, 0x67,
	0x67, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0c, 0x0a, 0x01, 0x43, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x01, 0x43, 0x12, 0x0c, 0x0a, 0x01, 0x56, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x01, 0x56, 0x22, 0xb2, 0x01, 0x0a, 0x0a, 0x4e, 0x65, 0x77, 0x56, 0x69, 0x65, 0x77,
	0x4d, 0x73, 0x67, 0x12, 0x3b, 0x0a, 0x0f, 0x4c, 0x6f, 0x63, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x51, 0x75, 0x6f, 0x72, 0x75, 0x6d, 0x43, 0x65, 0x72, 0x74, 0x52,
	0x0f, 0x4c, 0x6f, 0x63, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x12, 0x2b, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x41, 0x67, 0x67, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x52, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a,
	0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x52,
	0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x49, 0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09,
	0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x49, 0x44, 0x22, 0x1d, 0x0a, 0x07, 0x43, 0x6f, 0x6d,
	0x6d, 0x61, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x44, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x44, 0x61, 0x74, 0x61, 0x22, 0x3d, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65,
	0x78, 0x12, 0x1c, 0x0a, 0x09, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x49, 0x44, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x49, 0x44, 0x12,
	0x16, 0x0a, 0x06, 0x45, 0x78, 0x69, 0x73, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x06, 0x45, 0x78, 0x69, 0x73, 0x74, 0x73, 0x22, 0x44, 0x0a, 0x11, 0x4b, 0x65, 0x79, 0x41, 0x67,
	0x67, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x50, 0x61, 0x69, 0x72, 0x12, 0x0e, 0x0a, 0x02,
	0x50, 0x4b, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x02, 0x50, 0x4b, 0x12, 0x1f, 0x0a, 0x01,
	0x4d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x41, 0x67, 0x67, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x01, 0x4d, 0x22, 0x79, 0x0a,
	0x07, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4e, 0x43, 0x12, 0x3c, 0x0a, 0x0c, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x50, 0x61, 0x69, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4b, 0x65, 0x79, 0x41, 0x67, 0x67, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x50, 0x61, 0x69, 0x72, 0x52, 0x0c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x50, 0x61, 0x69, 0x72, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x48, 0x61, 0x73, 0x68, 0x22, 0x40, 0x0a, 0x07, 0x4e, 0x61, 0x63, 0x6b,
	0x4d, 0x73, 0x67, 0x12, 0x21, 0x0a, 0x02, 0x51, 0x43, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x51, 0x75, 0x6f, 0x72, 0x75, 0x6d, 0x43, 0x65,
	0x72, 0x74, 0x52, 0x02, 0x51, 0x43, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x61, 0x73, 0x68, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x48, 0x61, 0x73, 0x68, 0x32, 0xaf, 0x02, 0x0a, 0x0b, 0x46,
	0x61, 0x73, 0x74, 0x57, 0x65, 0x6e, 0x64, 0x79, 0x45, 0x43, 0x12, 0x35, 0x0a, 0x07, 0x50, 0x72,
	0x6f, 0x70, 0x6f, 0x73, 0x65, 0x12, 0x0c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x04, 0x98, 0xb5, 0x18,
	0x01, 0x12, 0x38, 0x0a, 0x04, 0x56, 0x6f, 0x74, 0x65, 0x12, 0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x43, 0x65, 0x72, 0x74, 0x1a, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x04, 0xa8, 0xb5, 0x18, 0x01, 0x12, 0x3a, 0x0a, 0x07, 0x4e,
	0x65, 0x77, 0x56, 0x69, 0x65, 0x77, 0x12, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4e,
	0x65, 0x77, 0x56, 0x69, 0x65, 0x77, 0x4d, 0x73, 0x67, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74,
	0x79, 0x22, 0x04, 0xa8, 0xb5, 0x18, 0x01, 0x12, 0x34, 0x0a, 0x04, 0x4e, 0x61, 0x63, 0x6b, 0x12,
	0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4e, 0x61, 0x63, 0x6b, 0x4d, 0x73, 0x67, 0x1a,
	0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x04, 0xa8, 0xb5, 0x18, 0x01, 0x12, 0x3d, 0x0a,
	0x0d, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4e, 0x6f, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x12, 0x0e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4e, 0x43, 0x1a, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x04, 0xa8, 0xb5, 0x18, 0x01, 0x42, 0x2a, 0x5a, 0x28,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x65, 0x6c, 0x61, 0x62,
	0x2f, 0x68, 0x6f, 0x74, 0x73, 0x74, 0x75, 0x66, 0x66, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e,
	0x61, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_internal_proto_fastwendyec_fastwendyec_proto_rawDescOnce sync.Once
	file_internal_proto_fastwendyec_fastwendyec_proto_rawDescData = file_internal_proto_fastwendyec_fastwendyec_proto_rawDesc
)

func file_internal_proto_fastwendyec_fastwendyec_proto_rawDescGZIP() []byte {
	file_internal_proto_fastwendyec_fastwendyec_proto_rawDescOnce.Do(func() {
		file_internal_proto_fastwendyec_fastwendyec_proto_rawDescData = protoimpl.X.CompressGZIP(file_internal_proto_fastwendyec_fastwendyec_proto_rawDescData)
	})
	return file_internal_proto_fastwendyec_fastwendyec_proto_rawDescData
}

var file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_internal_proto_fastwendyec_fastwendyec_proto_goTypes = []interface{}{
	(*Block)(nil),             // 0: proto.Block
	(*PartialSig)(nil),        // 1: proto.PartialSig
	(*PartialCert)(nil),       // 2: proto.PartialCert
	(*QuorumCert)(nil),        // 3: proto.QuorumCert
	(*AggMessage)(nil),        // 4: proto.AggMessage
	(*NewViewMsg)(nil),        // 5: proto.NewViewMsg
	(*Command)(nil),           // 6: proto.Command
	(*Index)(nil),             // 7: proto.Index
	(*KeyAggMessagePair)(nil), // 8: proto.KeyAggMessagePair
	(*ProofNC)(nil),           // 9: proto.ProofNC
	(*NackMsg)(nil),           // 10: proto.NackMsg
	(*emptypb.Empty)(nil),     // 11: google.protobuf.Empty
}
var file_internal_proto_fastwendyec_fastwendyec_proto_depIdxs = []int32{
	3,  // 0: proto.Block.QC:type_name -> proto.QuorumCert
	6,  // 1: proto.Block.Commands:type_name -> proto.Command
	1,  // 2: proto.PartialCert.Sig:type_name -> proto.PartialSig
	1,  // 3: proto.QuorumCert.Sigs:type_name -> proto.PartialSig
	3,  // 4: proto.NewViewMsg.LockCertificate:type_name -> proto.QuorumCert
	4,  // 5: proto.NewViewMsg.Message:type_name -> proto.AggMessage
	4,  // 6: proto.KeyAggMessagePair.M:type_name -> proto.AggMessage
	8,  // 7: proto.ProofNC.MessagePairs:type_name -> proto.KeyAggMessagePair
	3,  // 8: proto.NackMsg.QC:type_name -> proto.QuorumCert
	0,  // 9: proto.FastWendyEC.Propose:input_type -> proto.Block
	2,  // 10: proto.FastWendyEC.Vote:input_type -> proto.PartialCert
	5,  // 11: proto.FastWendyEC.NewView:input_type -> proto.NewViewMsg
	10, // 12: proto.FastWendyEC.Nack:input_type -> proto.NackMsg
	9,  // 13: proto.FastWendyEC.ProofNoCommit:input_type -> proto.ProofNC
	11, // 14: proto.FastWendyEC.Propose:output_type -> google.protobuf.Empty
	11, // 15: proto.FastWendyEC.Vote:output_type -> google.protobuf.Empty
	11, // 16: proto.FastWendyEC.NewView:output_type -> google.protobuf.Empty
	11, // 17: proto.FastWendyEC.Nack:output_type -> google.protobuf.Empty
	11, // 18: proto.FastWendyEC.ProofNoCommit:output_type -> google.protobuf.Empty
	14, // [14:19] is the sub-list for method output_type
	9,  // [9:14] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_internal_proto_fastwendyec_fastwendyec_proto_init() }
func file_internal_proto_fastwendyec_fastwendyec_proto_init() {
	if File_internal_proto_fastwendyec_fastwendyec_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Block); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PartialSig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PartialCert); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuorumCert); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AggMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NewViewMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Command); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Index); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyAggMessagePair); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProofNC); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NackMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_internal_proto_fastwendyec_fastwendyec_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_internal_proto_fastwendyec_fastwendyec_proto_goTypes,
		DependencyIndexes: file_internal_proto_fastwendyec_fastwendyec_proto_depIdxs,
		MessageInfos:      file_internal_proto_fastwendyec_fastwendyec_proto_msgTypes,
	}.Build()
	File_internal_proto_fastwendyec_fastwendyec_proto = out.File
	file_internal_proto_fastwendyec_fastwendyec_proto_rawDesc = nil
	file_internal_proto_fastwendyec_fastwendyec_proto_goTypes = nil
	file_internal_proto_fastwendyec_fastwendyec_proto_depIdxs = nil
}
