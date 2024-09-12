package commands

import "github.com/btcsuite/btcd/btcutil"

type CreateSidechainDeposit struct {
	Slot        int            `json:"slot"`
	Destination string         `json:"destination"`
	Amount      btcutil.Amount `json:"amount"`
	Fee         btcutil.Amount `json:"fee"`
}
