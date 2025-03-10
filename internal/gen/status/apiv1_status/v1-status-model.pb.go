// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v3.21.12
// source: v1-status-model.proto

package apiv1_status

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type StatusRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StatusRequest) Reset() {
	*x = StatusRequest{}
	mi := &file_v1_status_model_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusRequest) ProtoMessage() {}

func (x *StatusRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_status_model_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusRequest.ProtoReflect.Descriptor instead.
func (*StatusRequest) Descriptor() ([]byte, []int) {
	return file_v1_status_model_proto_rawDescGZIP(), []int{0}
}

type StatusReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data *StatusReply_Data `protobuf:"bytes,10,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *StatusReply) Reset() {
	*x = StatusReply{}
	mi := &file_v1_status_model_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusReply) ProtoMessage() {}

func (x *StatusReply) ProtoReflect() protoreflect.Message {
	mi := &file_v1_status_model_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusReply.ProtoReflect.Descriptor instead.
func (*StatusReply) Descriptor() ([]byte, []int) {
	return file_v1_status_model_proto_rawDescGZIP(), []int{1}
}

func (x *StatusReply) GetData() *StatusReply_Data {
	if x != nil {
		return x.Data
	}
	return nil
}

type StatusProbe struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Healthy       bool                   `protobuf:"varint,2,opt,name=healthy,proto3" json:"healthy,omitempty"`
	Message       string                 `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	LastCheckedTS *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=lastCheckedTS,proto3" json:"lastCheckedTS,omitempty"`
}

func (x *StatusProbe) Reset() {
	*x = StatusProbe{}
	mi := &file_v1_status_model_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusProbe) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusProbe) ProtoMessage() {}

func (x *StatusProbe) ProtoReflect() protoreflect.Message {
	mi := &file_v1_status_model_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusProbe.ProtoReflect.Descriptor instead.
func (*StatusProbe) Descriptor() ([]byte, []int) {
	return file_v1_status_model_proto_rawDescGZIP(), []int{2}
}

func (x *StatusProbe) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *StatusProbe) GetHealthy() bool {
	if x != nil {
		return x.Healthy
	}
	return false
}

func (x *StatusProbe) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *StatusProbe) GetLastCheckedTS() *timestamppb.Timestamp {
	if x != nil {
		return x.LastCheckedTS
	}
	return nil
}

type BuildVariables struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GitCommit string `protobuf:"bytes,1,opt,name=git_commit,json=gitCommit,proto3" json:"git_commit,omitempty"`
	GitBranch string `protobuf:"bytes,2,opt,name=git_branch,json=gitBranch,proto3" json:"git_branch,omitempty"`
	Timestamp string `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	GoVersion string `protobuf:"bytes,4,opt,name=go_version,json=goVersion,proto3" json:"go_version,omitempty"`
	GoArch    string `protobuf:"bytes,5,opt,name=go_arch,json=goArch,proto3" json:"go_arch,omitempty"`
	Version   string `protobuf:"bytes,6,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *BuildVariables) Reset() {
	*x = BuildVariables{}
	mi := &file_v1_status_model_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BuildVariables) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BuildVariables) ProtoMessage() {}

func (x *BuildVariables) ProtoReflect() protoreflect.Message {
	mi := &file_v1_status_model_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BuildVariables.ProtoReflect.Descriptor instead.
func (*BuildVariables) Descriptor() ([]byte, []int) {
	return file_v1_status_model_proto_rawDescGZIP(), []int{3}
}

func (x *BuildVariables) GetGitCommit() string {
	if x != nil {
		return x.GitCommit
	}
	return ""
}

func (x *BuildVariables) GetGitBranch() string {
	if x != nil {
		return x.GitBranch
	}
	return ""
}

func (x *BuildVariables) GetTimestamp() string {
	if x != nil {
		return x.Timestamp
	}
	return ""
}

func (x *BuildVariables) GetGoVersion() string {
	if x != nil {
		return x.GoVersion
	}
	return ""
}

func (x *BuildVariables) GetGoArch() string {
	if x != nil {
		return x.GoArch
	}
	return ""
}

func (x *BuildVariables) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type StatusProbeStore struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NextCheck      *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=nextCheck,proto3" json:"nextCheck,omitempty"`
	PreviousResult *StatusProbe           `protobuf:"bytes,2,opt,name=previousResult,proto3" json:"previousResult,omitempty"`
}

func (x *StatusProbeStore) Reset() {
	*x = StatusProbeStore{}
	mi := &file_v1_status_model_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusProbeStore) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusProbeStore) ProtoMessage() {}

func (x *StatusProbeStore) ProtoReflect() protoreflect.Message {
	mi := &file_v1_status_model_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusProbeStore.ProtoReflect.Descriptor instead.
func (*StatusProbeStore) Descriptor() ([]byte, []int) {
	return file_v1_status_model_proto_rawDescGZIP(), []int{4}
}

func (x *StatusProbeStore) GetNextCheck() *timestamppb.Timestamp {
	if x != nil {
		return x.NextCheck
	}
	return nil
}

func (x *StatusProbeStore) GetPreviousResult() *StatusProbe {
	if x != nil {
		return x.PreviousResult
	}
	return nil
}

type StatusReply_Data struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ServiceName    string          `protobuf:"bytes,1,opt,name=serviceName,proto3" json:"serviceName,omitempty"`
	BuildVariables *BuildVariables `protobuf:"bytes,2,opt,name=build_variables,json=buildVariables,proto3" json:"build_variables,omitempty"`
	Probes         []*StatusProbe  `protobuf:"bytes,3,rep,name=probes,proto3" json:"probes,omitempty"`
	Status         string          `protobuf:"bytes,4,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *StatusReply_Data) Reset() {
	*x = StatusReply_Data{}
	mi := &file_v1_status_model_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusReply_Data) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusReply_Data) ProtoMessage() {}

func (x *StatusReply_Data) ProtoReflect() protoreflect.Message {
	mi := &file_v1_status_model_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusReply_Data.ProtoReflect.Descriptor instead.
func (*StatusReply_Data) Descriptor() ([]byte, []int) {
	return file_v1_status_model_proto_rawDescGZIP(), []int{1, 0}
}

func (x *StatusReply_Data) GetServiceName() string {
	if x != nil {
		return x.ServiceName
	}
	return ""
}

func (x *StatusReply_Data) GetBuildVariables() *BuildVariables {
	if x != nil {
		return x.BuildVariables
	}
	return nil
}

func (x *StatusReply_Data) GetProbes() []*StatusProbe {
	if x != nil {
		return x.Probes
	}
	return nil
}

func (x *StatusReply_Data) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

var File_v1_status_model_proto protoreflect.FileDescriptor

var file_v1_status_model_proto_rawDesc = []byte{
	0x0a, 0x15, 0x76, 0x31, 0x2d, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2d, 0x6d, 0x6f, 0x64, 0x65,
	0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x76, 0x31, 0x2e, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x0f, 0x0a, 0x0d, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x22, 0xf5, 0x01, 0x0a, 0x0b, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52,
	0x65, 0x70, 0x6c, 0x79, 0x12, 0x2f, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x52,
	0x04, 0x64, 0x61, 0x74, 0x61, 0x1a, 0xb4, 0x01, 0x0a, 0x04, 0x44, 0x61, 0x74, 0x61, 0x12, 0x20,
	0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x42, 0x0a, 0x0f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x76, 0x61, 0x72, 0x69, 0x61, 0x62,
	0x6c, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x76, 0x31, 0x2e, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x56, 0x61, 0x72, 0x69, 0x61,
	0x62, 0x6c, 0x65, 0x73, 0x52, 0x0e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x56, 0x61, 0x72, 0x69, 0x61,
	0x62, 0x6c, 0x65, 0x73, 0x12, 0x2e, 0x0a, 0x06, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x76, 0x31, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x52, 0x06, 0x70, 0x72,
	0x6f, 0x62, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x97, 0x01, 0x0a,
	0x0b, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x07, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x40, 0x0a, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x43, 0x68, 0x65, 0x63,
	0x6b, 0x65, 0x64, 0x54, 0x53, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x43, 0x68, 0x65,
	0x63, 0x6b, 0x65, 0x64, 0x54, 0x53, 0x22, 0xbe, 0x01, 0x0a, 0x0e, 0x42, 0x75, 0x69, 0x6c, 0x64,
	0x56, 0x61, 0x72, 0x69, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x67, 0x69, 0x74,
	0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x67,
	0x69, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x67, 0x69, 0x74, 0x5f,
	0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x67, 0x69,
	0x74, 0x42, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x1d, 0x0a, 0x0a, 0x67, 0x6f, 0x5f, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x67, 0x6f, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x12, 0x17, 0x0a, 0x07, 0x67, 0x6f, 0x5f, 0x61, 0x72, 0x63, 0x68, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x67, 0x6f, 0x41, 0x72, 0x63, 0x68, 0x12, 0x18, 0x0a,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x8c, 0x01, 0x0a, 0x10, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x12, 0x38, 0x0a, 0x09,
	0x6e, 0x65, 0x78, 0x74, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x6e, 0x65, 0x78,
	0x74, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x12, 0x3e, 0x0a, 0x0e, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f,
	0x75, 0x73, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16,
	0x2e, 0x76, 0x31, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x52, 0x0e, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73,
	0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x42, 0x25, 0x5a, 0x23, 0x76, 0x63, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x2f, 0x61, 0x70, 0x69, 0x76, 0x31, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_status_model_proto_rawDescOnce sync.Once
	file_v1_status_model_proto_rawDescData = file_v1_status_model_proto_rawDesc
)

func file_v1_status_model_proto_rawDescGZIP() []byte {
	file_v1_status_model_proto_rawDescOnce.Do(func() {
		file_v1_status_model_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_status_model_proto_rawDescData)
	})
	return file_v1_status_model_proto_rawDescData
}

var file_v1_status_model_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_v1_status_model_proto_goTypes = []any{
	(*StatusRequest)(nil),         // 0: v1.status.StatusRequest
	(*StatusReply)(nil),           // 1: v1.status.StatusReply
	(*StatusProbe)(nil),           // 2: v1.status.StatusProbe
	(*BuildVariables)(nil),        // 3: v1.status.BuildVariables
	(*StatusProbeStore)(nil),      // 4: v1.status.StatusProbeStore
	(*StatusReply_Data)(nil),      // 5: v1.status.StatusReply.Data
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
}
var file_v1_status_model_proto_depIdxs = []int32{
	5, // 0: v1.status.StatusReply.data:type_name -> v1.status.StatusReply.Data
	6, // 1: v1.status.StatusProbe.lastCheckedTS:type_name -> google.protobuf.Timestamp
	6, // 2: v1.status.StatusProbeStore.nextCheck:type_name -> google.protobuf.Timestamp
	2, // 3: v1.status.StatusProbeStore.previousResult:type_name -> v1.status.StatusProbe
	3, // 4: v1.status.StatusReply.Data.build_variables:type_name -> v1.status.BuildVariables
	2, // 5: v1.status.StatusReply.Data.probes:type_name -> v1.status.StatusProbe
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_v1_status_model_proto_init() }
func file_v1_status_model_proto_init() {
	if File_v1_status_model_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_v1_status_model_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_v1_status_model_proto_goTypes,
		DependencyIndexes: file_v1_status_model_proto_depIdxs,
		MessageInfos:      file_v1_status_model_proto_msgTypes,
	}.Build()
	File_v1_status_model_proto = out.File
	file_v1_status_model_proto_rawDesc = nil
	file_v1_status_model_proto_goTypes = nil
	file_v1_status_model_proto_depIdxs = nil
}
