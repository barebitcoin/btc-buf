package main

type config struct {
	Bitcoind bitcoindConfig `group:"bitcoind" namespace:"bitcoind"`
}

type bitcoindConfig struct {
	User string `long:"user"`
	Pass string `long:"pass"`
	Host string `long:"host"`
}
