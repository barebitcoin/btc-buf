package commands

type BumpFee struct {
	TXID string `json:"txid"`
}

type AnalyzePsbt struct {
	Psbt string `json:"psbt"`
}

type CombinePsbt struct {
	Psbts []string `json:"psbts"`
}

type CreatePsbt struct {
	Inputs []struct {
		Txid     string `json:"txid"`
		Vout     uint32 `json:"vout"`
		Sequence uint32 `json:"sequence,omitempty"`
	} `json:"inputs"`
	Outputs     map[string]float64 `json:"outputs"`
	Locktime    uint32             `json:"locktime,omitempty"`
	Replaceable bool               `json:"replaceable,omitempty"`
}
