// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.21.12
// source: v1-registry.proto

package apiv1_registry

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	apiv1_status "vc/internal/gen/status/apiv1_status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	RegistryService_Add_FullMethodName      = "/v1.registry.RegistryService/Add"
	RegistryService_Revoke_FullMethodName   = "/v1.registry.RegistryService/Revoke"
	RegistryService_Validate_FullMethodName = "/v1.registry.RegistryService/Validate"
	RegistryService_Status_FullMethodName   = "/v1.registry.RegistryService/Status"
)

// RegistryServiceClient is the client API for RegistryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RegistryServiceClient interface {
	Add(ctx context.Context, in *AddRequest, opts ...grpc.CallOption) (*AddReply, error)
	Revoke(ctx context.Context, in *RevokeRequest, opts ...grpc.CallOption) (*RevokeReply, error)
	Validate(ctx context.Context, in *ValidateRequest, opts ...grpc.CallOption) (*ValidateReply, error)
	Status(ctx context.Context, in *apiv1_status.StatusRequest, opts ...grpc.CallOption) (*apiv1_status.StatusReply, error)
}

type registryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewRegistryServiceClient(cc grpc.ClientConnInterface) RegistryServiceClient {
	return &registryServiceClient{cc}
}

func (c *registryServiceClient) Add(ctx context.Context, in *AddRequest, opts ...grpc.CallOption) (*AddReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AddReply)
	err := c.cc.Invoke(ctx, RegistryService_Add_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) Revoke(ctx context.Context, in *RevokeRequest, opts ...grpc.CallOption) (*RevokeReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RevokeReply)
	err := c.cc.Invoke(ctx, RegistryService_Revoke_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) Validate(ctx context.Context, in *ValidateRequest, opts ...grpc.CallOption) (*ValidateReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ValidateReply)
	err := c.cc.Invoke(ctx, RegistryService_Validate_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) Status(ctx context.Context, in *apiv1_status.StatusRequest, opts ...grpc.CallOption) (*apiv1_status.StatusReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(apiv1_status.StatusReply)
	err := c.cc.Invoke(ctx, RegistryService_Status_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RegistryServiceServer is the server API for RegistryService service.
// All implementations must embed UnimplementedRegistryServiceServer
// for forward compatibility.
type RegistryServiceServer interface {
	Add(context.Context, *AddRequest) (*AddReply, error)
	Revoke(context.Context, *RevokeRequest) (*RevokeReply, error)
	Validate(context.Context, *ValidateRequest) (*ValidateReply, error)
	Status(context.Context, *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
	mustEmbedUnimplementedRegistryServiceServer()
}

// UnimplementedRegistryServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedRegistryServiceServer struct{}

func (UnimplementedRegistryServiceServer) Add(context.Context, *AddRequest) (*AddReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Add not implemented")
}
func (UnimplementedRegistryServiceServer) Revoke(context.Context, *RevokeRequest) (*RevokeReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Revoke not implemented")
}
func (UnimplementedRegistryServiceServer) Validate(context.Context, *ValidateRequest) (*ValidateReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Validate not implemented")
}
func (UnimplementedRegistryServiceServer) Status(context.Context, *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Status not implemented")
}
func (UnimplementedRegistryServiceServer) mustEmbedUnimplementedRegistryServiceServer() {}
func (UnimplementedRegistryServiceServer) testEmbeddedByValue()                         {}

// UnsafeRegistryServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RegistryServiceServer will
// result in compilation errors.
type UnsafeRegistryServiceServer interface {
	mustEmbedUnimplementedRegistryServiceServer()
}

func RegisterRegistryServiceServer(s grpc.ServiceRegistrar, srv RegistryServiceServer) {
	// If the following call pancis, it indicates UnimplementedRegistryServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&RegistryService_ServiceDesc, srv)
}

func _RegistryService_Add_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Add(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Add_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Add(ctx, req.(*AddRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_Revoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Revoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Revoke_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Revoke(ctx, req.(*RevokeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_Validate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Validate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Validate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Validate(ctx, req.(*ValidateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_Status_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(apiv1_status.StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Status(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Status_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Status(ctx, req.(*apiv1_status.StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RegistryService_ServiceDesc is the grpc.ServiceDesc for RegistryService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RegistryService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v1.registry.RegistryService",
	HandlerType: (*RegistryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Add",
			Handler:    _RegistryService_Add_Handler,
		},
		{
			MethodName: "Revoke",
			Handler:    _RegistryService_Revoke_Handler,
		},
		{
			MethodName: "Validate",
			Handler:    _RegistryService_Validate_Handler,
		},
		{
			MethodName: "Status",
			Handler:    _RegistryService_Status_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "v1-registry.proto",
}
