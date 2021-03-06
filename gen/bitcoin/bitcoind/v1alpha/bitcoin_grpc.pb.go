// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package bitcoindv1alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// BitcoinServiceClient is the client API for BitcoinService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BitcoinServiceClient interface {
	GetBlockchainInfo(ctx context.Context, in *GetBlockchainInfoRequest, opts ...grpc.CallOption) (*GetBlockchainInfoResponse, error)
}

type bitcoinServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewBitcoinServiceClient(cc grpc.ClientConnInterface) BitcoinServiceClient {
	return &bitcoinServiceClient{cc}
}

func (c *bitcoinServiceClient) GetBlockchainInfo(ctx context.Context, in *GetBlockchainInfoRequest, opts ...grpc.CallOption) (*GetBlockchainInfoResponse, error) {
	out := new(GetBlockchainInfoResponse)
	err := c.cc.Invoke(ctx, "/bitcoin.bitcoind.v1alpha.BitcoinService/GetBlockchainInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BitcoinServiceServer is the server API for BitcoinService service.
// All implementations should embed UnimplementedBitcoinServiceServer
// for forward compatibility
type BitcoinServiceServer interface {
	GetBlockchainInfo(context.Context, *GetBlockchainInfoRequest) (*GetBlockchainInfoResponse, error)
}

// UnimplementedBitcoinServiceServer should be embedded to have forward compatible implementations.
type UnimplementedBitcoinServiceServer struct {
}

func (UnimplementedBitcoinServiceServer) GetBlockchainInfo(context.Context, *GetBlockchainInfoRequest) (*GetBlockchainInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetBlockchainInfo not implemented")
}

// UnsafeBitcoinServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BitcoinServiceServer will
// result in compilation errors.
type UnsafeBitcoinServiceServer interface {
	mustEmbedUnimplementedBitcoinServiceServer()
}

func RegisterBitcoinServiceServer(s grpc.ServiceRegistrar, srv BitcoinServiceServer) {
	s.RegisterService(&BitcoinService_ServiceDesc, srv)
}

func _BitcoinService_GetBlockchainInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBlockchainInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BitcoinServiceServer).GetBlockchainInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bitcoin.bitcoind.v1alpha.BitcoinService/GetBlockchainInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BitcoinServiceServer).GetBlockchainInfo(ctx, req.(*GetBlockchainInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// BitcoinService_ServiceDesc is the grpc.ServiceDesc for BitcoinService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var BitcoinService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "bitcoin.bitcoind.v1alpha.BitcoinService",
	HandlerType: (*BitcoinServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetBlockchainInfo",
			Handler:    _BitcoinService_GetBlockchainInfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bitcoin/bitcoind/v1alpha/bitcoin.proto",
}
