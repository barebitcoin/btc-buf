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

type CreateRawTransaction struct {
	Inputs []struct {
		Txid     string `json:"txid"`
		Vout     uint32 `json:"vout"`
		Sequence uint32 `json:"sequence,omitempty"`
	} `json:"inputs"`
	Outputs  map[string]float64 `json:"outputs"`
	Locktime uint32             `json:"locktime,omitempty"`
}

type DecodePsbt struct {
	Psbt string `json:"psbt"`
}

type UtxoUpdatePsbt struct {
	Psbt        string `json:"psbt"`
	Descriptors []struct {
		Desc  string      `json:"desc"`
		Range interface{} `json:"range,omitempty"` // Can be int or [int,int]
	} `json:"descriptors,omitempty"`
}

type JoinPsbts struct {
	Psbts []string `json:"psbts"`
}
