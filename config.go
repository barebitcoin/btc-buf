package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog/log"
)

type config struct {
	Bitcoind bitcoindConfig `group:"bitcoind" namespace:"bitcoind"`
}

type bitcoindConfig struct {
	User    string `long:"user"`
	Pass    string `long:"pass"`
	Host    string `long:"host" description:"host:port to connect to Bitcoin Core on. Inferred from network if not set."`
	Cookie  bool   `long:"cookie" description:"Read cookie data from the data directory. Not compatible with user and pass options. "`
	Network string `long:"network" default:"regtest" description:"Network Bitcoin Core is running on. Only used to infer other parameters if not set."`
}

func readConfig() (*config, error) {
	var err error

	var cfg config
	if _, err := flags.Parse(&cfg); err != nil {
		// help was requested, avoid print and non-zero exit code
		if flagErr := new(flags.Error); errors.As(
			err, &flagErr,
		) && flagErr.Type == flags.ErrHelp {
			os.Exit(0)
		}

		return nil, err
	}

	if cfg.Bitcoind.Pass == "" && cfg.Bitcoind.User == "" {
		log.Debug().
			Msg("config: empty bitcoind.pass and bitcoind.user, defaulting to cookie")

		cfg.Bitcoind.Cookie = true
	}

	if cfg.Bitcoind.Cookie {
		log.Debug().
			Str("network", cfg.Bitcoind.Network).
			Msg("config: reading bitcoind cookie data")

		if cfg.Bitcoind.Pass != "" ||
			cfg.Bitcoind.User != "" {
			return nil, fmt.Errorf("cannot set username or password when specifying bitcoind.cookie")
		}

		path, err := cookiePath(cfg.Bitcoind.Network)
		if err != nil {
			return nil, fmt.Errorf("could not find cookie path: %w", err)
		}

		log.Debug().Str("path", path).
			Msg("config: found cookie path")

		cookie, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("could not read cookie: %w", err)
		}

		user, pass, found := strings.Cut(string(cookie), ":")
		if !found {
			return nil, fmt.Errorf("could not parse cookie: %s", string(cookie))
		}

		cfg.Bitcoind.User = user
		cfg.Bitcoind.Pass = pass
	}

	if cfg.Bitcoind.Host == "" {
		log.Debug().Str("network", cfg.Bitcoind.Network).
			Msg("config: empty bitcoind.host, inferring from network")

		cfg.Bitcoind.Host, err = defaultRpcHost(cfg.Bitcoind.Network)
		if err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

func defaultRpcHost(network string) (string, error) {
	switch network {
	case "mainnet":
		return "localhost:8332", nil
	case "testnet":
		return "localhost:18332", nil
	case "regtest":
		return "localhost:18443", nil
	case "signet":
		return "localhost:38332", nil
	default:
		return "", fmt.Errorf("unknown network: %q", network)
	}
}

func cookiePath(network string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch network {
	// empty net segment!
	case "mainnet":
		network = ""
	case "regtest":
		network = "regtest"
	case "testnet", "testnet3":
		network = "testnet3"
	default:
		return "", fmt.Errorf("unknown network: %q", network)
	}

	return filepath.Join(home, ".bitcoin", network, ".cookie"), nil
}
