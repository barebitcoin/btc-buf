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

type activeSidechain struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	NVersion    int    `json:"nversion"`
	HashID1     string `json:"hashid1"`
	HashID2     string `json:"hashid2"`
}

// ListActiveSidechains implements drivechaindv1connect.DrivechainServiceHandler.
func (b *Bitcoind) ListActiveSidechains(ctx context.Context, _ *connect.Request[pb.ListActiveSidechainsRequest]) (*connect.Response[pb.ListActiveSidechainsResponse], error) {
	return withCancel(ctx, func(ctx context.Context) ([]*pb.ListActiveSidechainsResponse_Sidechain, error) {
		cmd, err := btcjson.NewCmd("listactivesidechains")
		if err != nil {
			return nil, fmt.Errorf("listactivesidechains new cmd: %w", err)
		}

		res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
		if err != nil {
			return nil, fmt.Errorf("listactivesidechains send: %w", err)
		}

		var sidechains []activeSidechain
		if err := json.Unmarshal(res, &sidechains); err != nil {
			return nil, fmt.Errorf("listactivesidechains unmarshal response: %w", err)
		}

		// Log the unmarshaled sidechains for debugging
		zerolog.Ctx(ctx).Debug().
			Interface("sidechains", sidechains).
			Msg("unmarshaled active sidechains")

		pbSidechains := make([]*pb.ListActiveSidechainsResponse_Sidechain, 0, len(sidechains))
		for _, sidechain := range sidechains {
			pbSidechain, err := b.sidechainToProto(ctx, sidechain)
			if err != nil {
				return nil, fmt.Errorf("convert sidechain to proto: %w", err)
			}

			pbSidechains = append(pbSidechains, pbSidechain)
		}

		return pbSidechains, nil
	},

		func(sidechains []*pb.ListActiveSidechainsResponse_Sidechain) *pb.ListActiveSidechainsResponse {
			return &pb.ListActiveSidechainsResponse{
				Sidechains: sidechains,
			}
		},
	)
}

func (b *Bitcoind) getChaintipInfo(ctx context.Context, sidechainSlot int) (btcutil.Amount, string, error) {
	cmd, err := btcjson.NewCmd("listsidechainctip", sidechainSlot)
	if err != nil {
		return 0, "", fmt.Errorf("listsidechainctip new cmd: %w", err)
	}
	res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
	if err != nil {
		return 0, "", fmt.Errorf("listsidechainctip send: %w", err)
	}

	var result struct {
		Amount btcutil.Amount `json:"amount"`
		TXID   string         `json:"txid"`
	}
	if err := json.Unmarshal(res, &result); err != nil {
		return 0, "", fmt.Errorf("unmarshal listsidechainctip response: %w", err)
	}

	return result.Amount, result.TXID, nil
}

func (b *Bitcoind) sidechainToProto(
	ctx context.Context, sidechain activeSidechain,
) (*pb.ListActiveSidechainsResponse_Sidechain, error) {
	slot, err := chainToSlot(sidechain.Title)
	if err != nil {
		return nil, fmt.Errorf("convert chain to slot: %w", err)
	}

	balance, txid, err := b.getChaintipInfo(ctx, slot)
	switch {
	case err == nil:
		// No error, proceed

	case strings.Contains(err.Error(), drivechain.ErrNoCTip):
		zerolog.Ctx(ctx).Warn().Int("slot", slot).Msg("no ctip for sidechain")
		// That's okay, proceed

	default:
		return nil, fmt.Errorf("get balance for chain %s: %w", sidechain.Title, err)
	}

	return &pb.ListActiveSidechainsResponse_Sidechain{
		Title:         sidechain.Title,
		Description:   sidechain.Description,
		Nversion:      uint32(sidechain.NVersion),
		Hashid1:       sidechain.HashID1,
		Hashid2:       sidechain.HashID2,
		Slot:          int32(slot),
		AmountSatoshi: int64(balance),
		ChaintipTxid:  txid,
	}, nil
}

func chainToSlot(chain string) (int, error) {
	switch chain {
	case "Testchain":
		return 0, nil
	case "BitNames":
		return 2, nil
	case "BitAssets":
		return 4, nil
	case "ZSide":
		return 5, nil
	case "EthSide":
		return 6, nil
	case "Thunder":
		return 9, nil
	case "LatestCore":
		return 11, nil
	default:
		return 0, fmt.Errorf("unknown chain: %s", chain)
	}
}

// ListSidechainDeposits implements drivechaindv1connect.DrivechainServiceHandler.
func (b *Bitcoind) ListSidechainDeposits(ctx context.Context, c *connect.Request[pb.ListSidechainDepositsRequest]) (*connect.Response[pb.ListSidechainDepositsResponse], error) {
	cmd, err := btcjson.NewCmd("listsidechaindeposits", c.Msg.Slot)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create listsidechaindeposits command: %w", err))
	}

	res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to execute listsidechaindeposits command: %w", err))
	}

	var deposits []*pb.ListSidechainDepositsResponse_SidechainDeposit
	err = json.Unmarshal(res, &deposits)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to unmarshal listsidechaindeposits response: %w", err))
	}

	return connect.NewResponse(&pb.ListSidechainDepositsResponse{
		Deposits: deposits,
	}), nil
}
