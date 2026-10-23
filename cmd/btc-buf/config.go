package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

type config struct {
	Listen string

	JsonLog  bool
	LogLevel string
	Bitcoind bitcoindConfig
	SSH      sshConfig

	AllowPrivateDescriptorsExport bool
}

type sshConfig struct {
	Host       string
	LocalPort  int
	RemotePort int
	KnownHosts []string
	KeyFile    string
}

type bitcoindConfig struct {
	User     string
	Pass     string
	PassFile string
	Host     string
	Cookie   bool
	// Set when Cookie is.
	CookiePath string
	Network    string
	Wallet     string
}

// parseFlags parses command line arguments into a config. Flags can be given
// as both -flag and --flag, with values as --flag=value or --flag value.
func parseFlags(args []string) (*config, error) {
	var cfg config
	fs := flag.NewFlagSet("btc-buf", flag.ContinueOnError)

	fs.StringVar(&cfg.Listen, "listen", "localhost:5080", "interface:port for server")
	fs.BoolVar(&cfg.JsonLog, "logging.json", false, "log to JSON format (default human readable)")
	fs.StringVar(&cfg.LogLevel, "logging.level", "debug", "log level")
	fs.BoolVar(&cfg.AllowPrivateDescriptorsExport, "allow-private-descriptors-export", false,
		"allow private descriptors to be exported via the 'listdescriptors' RPC command")

	fs.StringVar(&cfg.Bitcoind.User, "bitcoind.user", "", "username for Bitcoin Core")
	fs.StringVar(&cfg.Bitcoind.Pass, "bitcoind.pass", "", "password for Bitcoin Core")
	fs.StringVar(&cfg.Bitcoind.PassFile, "bitcoind.passfile", "", "if set, reads password from this file")
	fs.StringVar(&cfg.Bitcoind.Host, "bitcoind.host", "",
		"host:port to connect to Bitcoin Core on. Inferred from network if not set.")
	fs.BoolVar(&cfg.Bitcoind.Cookie, "bitcoind.cookie", false,
		"read cookie data from the data directory. Not compatible with user and pass options.")
	fs.StringVar(&cfg.Bitcoind.Network, "bitcoind.network", "regtest",
		"network Bitcoin Core is running on. Only used to infer other parameters if not set.")
	fs.StringVar(&cfg.Bitcoind.Wallet, "bitcoind.wallet", "", "equivalent to -rpcwallet in bitcoin-cli")

	fs.StringVar(&cfg.SSH.Host, "ssh.host", "", "host to connect to")
	fs.IntVar(&cfg.SSH.LocalPort, "ssh.local-port", 0, "local port to connect to")
	fs.IntVar(&cfg.SSH.RemotePort, "ssh.remote-port", 0, "remote port to connect to")
	fs.Func("ssh.known-hosts", "known_hosts entry for the SSH host. Can be repeated.", func(value string) error {
		cfg.SSH.KnownHosts = append(cfg.SSH.KnownHosts, value)
		return nil
	})
	fs.StringVar(&cfg.SSH.KeyFile, "ssh.key-file", "", "path to SSH private key file")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Parsing stops at the first non-flag argument, so anything following it
	// would otherwise be silently ignored.
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}

	return &cfg, nil
}

func readConfig(ctx context.Context) (*config, error) {
	cfg, err := parseFlags(os.Args[1:])
	switch {
	// Help was requested, and has been printed. Not an error.
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)

	case err != nil:
		return nil, err
	}

	if err := configureLogging(cfg); err != nil {
		return nil, err
	}

	if cfg.Bitcoind.Pass != "" && cfg.Bitcoind.PassFile != "" {
		return nil, errors.New("cannot set both pass and passfile")
	}

	if cfg.Bitcoind.PassFile != "" {
		pass, err := os.ReadFile(cfg.Bitcoind.PassFile)
		if err != nil {
			return nil, fmt.Errorf("read passfile: %w", err)
		}
		cfg.Bitcoind.Pass = strings.TrimSpace(string(pass))
	}

	log := zerolog.Ctx(ctx)
	if cfg.Bitcoind.Pass == "" && cfg.Bitcoind.User == "" {
		log.Debug().
			Msg("config: empty bitcoind.pass and bitcoind.user, defaulting to cookie")

		cfg.Bitcoind.Cookie = true
	}

	net, ok := nets[cfg.Bitcoind.Network]
	if !ok {
		return nil, fmt.Errorf("unknown bitcoin network: %q", cfg.Bitcoind.Network)
	}

	if cfg.Bitcoind.Cookie {
		log.Debug().
			Str("network", cfg.Bitcoind.Network).
			Msg("config: reading bitcoind cookie data")

		if cfg.Bitcoind.Pass != "" ||
			cfg.Bitcoind.User != "" {
			return nil, fmt.Errorf("cannot set username or password when specifying bitcoind.cookie")
		}

		path, err := cookiePath(net)
		if err != nil {
			return nil, fmt.Errorf("find cookie path: %w", err)
		}

		log.Debug().Str("path", path).
			Msg("config: found cookie path")

		// Read on each request rather than once here, so a Core restart,
		// which writes a new cookie, doesn't lock us out.
		cfg.Bitcoind.CookiePath = path
	}

	if cfg.Bitcoind.Host == "" {
		log.Debug().Str("network", cfg.Bitcoind.Network).
			Msgf("config: empty bitcoind.host, inferring from network: %q", net.defaultRpcHost)

		cfg.Bitcoind.Host = net.defaultRpcHost
	}

	if cfg.Bitcoind.Wallet != "" {
		cfg.Bitcoind.Host = fmt.Sprintf(
			"%s/wallet/%s",
			cfg.Bitcoind.Host, cfg.Bitcoind.Wallet,
		)
	}

	return cfg, nil
}

func cookiePath(network bitcoinNet) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".bitcoin", network.path, ".cookie"), nil
}

type bitcoinNet struct {
	path           string
	defaultRpcHost string
}

var (
	mainnet = bitcoinNet{
		path:           "",
		defaultRpcHost: "localhost:8332",
	}
	testnet = bitcoinNet{
		path:           "testnet3",
		defaultRpcHost: "localhost:18332",
	}
	regtest = bitcoinNet{
		path:           "regtest",
		defaultRpcHost: "localhost:18443",
	}
	signet = bitcoinNet{
		path:           "signet",
		defaultRpcHost: "localhost:38332",
	}
)

var nets = map[string]bitcoinNet{
	"mainnet":  mainnet,
	"testnet":  testnet,
	"testnet3": testnet,
	"regtest":  regtest,
	"signet":   signet,
}
