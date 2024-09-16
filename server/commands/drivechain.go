package commands

type CreateSidechainDeposit struct {
	Slot        int     `json:"slot"`
	Destination string  `json:"destination"`
	Amount      float64 `json:"amount"`
	Fee         float64 `json:"fee"`
}
