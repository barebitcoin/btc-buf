package commands

// Create a sidechain deposit of an amount to a given address.
type CreateSidechainDeposit struct {
	Slot        int     `json:"slot"`
	Destination string  `json:"destination"`
	Amount      float64 `json:"amount"`
	Fee         float64 `json:"fee"`
}

// List active sidechains.
type ListActiveSidechains struct{}

// Returns the crtitical transaction index pair for sidechain in a specific slot
type ListSidechainCTip struct {
	// The sidechain slot
	Slot int `json:"slot"`
}

// ListSidechainDeposits retrieves a list of deposits for a specific sidechain
type ListSidechainDeposits struct {
	// The sidechain slot
	Slot int `json:"slot"`
}
