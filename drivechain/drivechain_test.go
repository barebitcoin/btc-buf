package drivechain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/barebitcoin/btc-buf/drivechain"
)

func TestCheckValidDepositAddress(t *testing.T) {
	t.Run("can check various sidechain deposit addresses", func(t *testing.T) {
		// a valid onchain address, but not a deposit address
		err := drivechain.ValidateDepositAddress("3Ef6Dyk7UdbT8y8dge4Z73Ne2N18dPnU1h")
		require.Error(t, err)

		// valid
		err = drivechain.ValidateDepositAddress("s5_tmEoMXN71n8cQ7VNjP3EpEEn6fbXMvASwXt_712f8a")
		require.NoError(t, err)
		err = drivechain.ValidateDepositAddress("s0_sYvUEgThKWXxEN9PeE3KvcD1vEXEJzq8tv_adfbb5")
		require.NoError(t, err)
		err = drivechain.ValidateDepositAddress("s6_0xc96aaa54e2d44c299564da76e1cd3184a2386b8d_0ad45c")
		require.NoError(t, err)

		err = drivechain.ValidateDepositAddress("s5_tmCtD9o83Y1R2C8E99wV7XCmxD75Ruk71zx_637f80")
		require.NoError(t, err)

		// invalid checksums
		err = drivechain.ValidateDepositAddress("s6_0xc96aaa54e2d44c299564da76e1cd3184a2386b8d_adfbb5")
		require.Error(t, err)
		err = drivechain.ValidateDepositAddress("s5_tmEoMXN71n8cQ7VNjP3EpEEn6fbXMvASwXt_0ad45c")
		require.Error(t, err)
	})
}
