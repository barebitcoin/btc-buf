package connectserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/grpchealth/v2"
	"connectrpc.com/grpcreflect/v2"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1/bitcoindv1connect"
)

// stubService answers ListWallets with a single wallet, named after the
// request's ID, so tests can see the ID the handler got.
type stubService struct {
	rpc.UnimplementedBitcoinServiceHandler
}

func (stubService) ListWallets(ctx context.Context, _ *emptypb.Empty) (*pb.ListWalletsResponse, error) {
	return &pb.ListWalletsResponse{Wallets: []string{RequestID(ctx)}}, nil
}

func newTestServer(t *testing.T, interceptors ...connect.ServerInterceptor) *httptest.Server {
	t.Helper()
	dispatcher := connect.NewServer(interceptors...)
	rpc.RegisterBitcoinServiceHandler(dispatcher, stubService{})

	srv := httptest.NewUnstartedServer(Handler(dispatcher))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// postJSON posts body to ListWallets with the Connect protocol, returning the
// response's status, ID header and body.
func postJSON(t *testing.T, srv *httptest.Server, requestID, body string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+rpc.BitcoinServiceListWalletsProcedure, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if requestID != "" {
		req.Header.Set(RequestIDHeader, requestID)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header.Get(RequestIDHeader), string(resBody)
}

func TestHandler(t *testing.T) {
	t.Run("serves the Connect protocol", func(t *testing.T) {
		srv := newTestServer(t)
		client := rpc.NewBitcoinServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
		res, err := client.ListWallets(t.Context(), &emptypb.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Wallets) != 1 || !strings.HasPrefix(res.Wallets[0], "req_") {
			t.Fatalf("expected a generated request ID, got %v", res.Wallets)
		}
	})

	t.Run("request ID is taken from the header", func(t *testing.T) {
		status, echoed, body := postJSON(t, newTestServer(t), "req_given", "{}")
		if status != http.StatusOK || echoed != "req_given" || body != `{"wallets":["req_given"]}` {
			t.Fatalf("unexpected response: status=%d id=%q body=%s", status, echoed, body)
		}
	})

	t.Run("request ID is generated", func(t *testing.T) {
		status, echoed, body := postJSON(t, newTestServer(t), "", "{}")
		if status != http.StatusOK || !strings.HasPrefix(echoed, "req_") || body != `{"wallets":["`+echoed+`"]}` {
			t.Fatalf("unexpected response: status=%d id=%q body=%s", status, echoed, body)
		}
	})

	t.Run("empty body is the empty message", func(t *testing.T) {
		if status, _, body := postJSON(t, newTestServer(t), "", ""); status != http.StatusOK {
			t.Fatalf("unexpected response: status=%d body=%s", status, body)
		}
	})

	t.Run("unknown fields are rejected", func(t *testing.T) {
		status, echoed, body := postJSON(t, newTestServer(t), "req_invalid", `{"bogus": 1}`)
		if status != http.StatusBadRequest || echoed != "req_invalid" ||
			!strings.Contains(body, `"invalid_argument"`) || !strings.Contains(body, `unknown field: \"bogus\"`) {
			t.Fatalf("unexpected response: status=%d id=%q body=%s", status, echoed, body)
		}
	})

	t.Run("reflection lists the service", func(t *testing.T) {
		srv := newTestServer(t)
		client := grpcreflect.NewClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
		stream := client.NewStream(t.Context())
		defer func() { _ = stream.Close() }()
		services, err := stream.ListServices()
		if err != nil {
			t.Fatal(err)
		}
		for _, service := range services {
			if string(service) == rpc.BitcoinServiceName {
				return
			}
		}
		t.Fatalf("Bitcoin service absent from reflection: %v", services)
	})

	t.Run("health skips the service's interceptors", func(t *testing.T) {
		// Holds every call to the service, like Bitcoind does during startup.
		hold := func(next connect.ServerFunc) connect.ServerFunc {
			return func(ctx context.Context, _ connect.Spec, _ connect.ServerStream) error {
				<-ctx.Done()
				return ctx.Err()
			}
		}
		srv := newTestServer(t, hold)
		client := grpchealth.NewClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		res, err := client.Check(ctx, &grpchealth.CheckRequest{Service: rpc.BitcoinServiceName})
		if err != nil || res.Status != grpchealth.StatusServing {
			t.Fatalf("health check: status=%v err=%v", res, err)
		}
	})
}
