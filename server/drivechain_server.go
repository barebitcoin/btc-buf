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

	return withCancel(ctx,
		func(ctx context.Context) (string, error) {
			cmd, err := btcjson.NewCmd("createsidechaindeposit", sidechainSlot, c.Msg.Destination, amount.ToBTC(), fee.ToBTC())
			if err != nil {
				return "", fmt.Errorf("createsidechaindeposit new cmd: %w", err)
			}

			res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
			if err != nil {
				return "", fmt.Errorf("createsidechaindeposit send: %w", err)
			}
			zerolog.Ctx(ctx).Err(err).
				Msgf("createsidechaindeposit response: %s", string(res))

			var txid string
			if err := json.Unmarshal(res, &txid); err != nil {
				return "", fmt.Errorf("createsidechaindeposit unmarshal response: %w", err)
			}

			return txid, nil
		},

		func(txid string) *pb.CreateSidechainDepositResponse {
			return &pb.CreateSidechainDepositResponse{
				Txid: txid,
			}
		},
	)
}
