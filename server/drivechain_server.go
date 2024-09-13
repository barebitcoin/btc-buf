package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/barebitcoin/btcd/rpcclient"
	"github.com/barebitcoin/btcd/rpcclient/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/rs/zerolog"

	"github.com/barebitcoin/btc-buf/drivechain"
	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/drivechaind/v1"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/drivechaind/v1/drivechaindv1connect"
)

var _ rpc.DrivechainServiceHandler = new(Bitcoind)

func (b *Bitcoind) CreateSidechainDeposit(ctx context.Context, c *connect.Request[pb.CreateSidechainDepositRequest]) (*connect.Response[pb.CreateSidechainDepositResponse], error) {
	type rawCreateResponse struct {
		TXID   string   `json:"txid"`
		Errors []string // May be empty
	}

	amount, err := btcutil.NewAmount(c.Msg.Amount)
	if err != nil {
		return nil, fmt.Errorf("amount: %w", err)
	}

	fee, err := btcutil.NewAmount(c.Msg.Fee)
	if err != nil {
		return nil, fmt.Errorf("fee: %w", err)
	}

	if err := drivechain.ValidateDepositAddress(c.Msg.Destination); err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}

	// extract the sidechain slot
	withoutS := strings.TrimPrefix(c.Msg.Destination, "s")
	sidechainSlot := strings.Split(withoutS, "_")[0]

	return withCancel[rawCreateResponse, pb.CreateSidechainDepositResponse](ctx,
		func(ctx context.Context) (rawCreateResponse, error) {
			cmd, err := btcjson.NewCmd("createsidechaindeposit", sidechainSlot, c.Msg.Destination, amount, fee)
			if err != nil {
				return rawCreateResponse{}, err
			}

			res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
			if err != nil {
				return rawCreateResponse{}, fmt.Errorf("send createsidechaindeposit: %w", err)
			}
			zerolog.Ctx(ctx).Err(err).
				Msgf("createsidechaindeposit response: %s", string(res))

			var parsed rawCreateResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return rawCreateResponse{}, fmt.Errorf("unmarshal createsidechaindeposit response: %w", err)
			}

			return parsed, nil
		},

		func(r rawCreateResponse) *pb.CreateSidechainDepositResponse {
			return &pb.CreateSidechainDepositResponse{
				Txid:   r.TXID,
				Errors: r.Errors,
			}
		},
	)
}
