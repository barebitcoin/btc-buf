// Package connectserver serves a Connect dispatcher over HTTP, as btc-buf's
// command line does.
package connectserver

import (
	"net/http"
	"slices"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/connect/v2/connectproto"
	"connectrpc.com/grpchealth/v2"
	"connectrpc.com/grpcreflect/v2"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Handler serves rpc over HTTP, with health checks and reflection for every
// service registered on it. Each request gets an ID, available to rpc's
// handlers through RequestID. Services registered on rpc after this is called
// are not served. Mount it on an http.Server with HTTP/2 enabled, for gRPC.
func Handler(rpc *connect.Server) http.Handler {
	services := serviceNames(rpc)

	// Health and reflection get their own dispatcher, so they don't go
	// through rpc's interceptors.
	aux := connect.NewServer()
	grpchealth.Register(aux, grpchealth.NewStaticChecker(services...))
	grpcreflect.Register(aux, grpcreflect.WithNamer(grpcreflect.NamerFunc(func() []string {
		return services
	})))

	mux := http.NewServeMux()
	connecthttp.Mount(mux, rpc, connecthttp.WithCodecs(connectproto.NewBinaryCodec(), newProtoJsonCodec()))
	connecthttp.Mount(mux, aux)
	return withRequestID(mux)
}

// serviceNames returns the fully qualified names of the protobuf services
// registered on rpc.
func serviceNames(rpc *connect.Server) []string {
	var names []string
	for spec := range rpc.Specs() {
		method, ok := spec.Schema.(protoreflect.MethodDescriptor)
		if !ok {
			continue
		}
		name := string(method.Parent().FullName())
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}
