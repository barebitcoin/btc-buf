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
