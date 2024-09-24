package drivechain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func ValidateDepositAddress(depositAddress string) error {
	parts := strings.Split(depositAddress, "_")
	if len(parts) != 3 {
		return errors.New("invalid format, expected slot_address_checksum")
	}

	sidechainNumStr := parts[0]
	address := parts[1]

	addrWithoutChecksum := fmt.Sprintf("%s_%s_", sidechainNumStr, address)

	hash := sha256.Sum256([]byte(addrWithoutChecksum))
	calculatedChecksum := hex.EncodeToString(hash[:3])

	checksum := parts[2]
	if checksum != calculatedChecksum {
		return errors.New("invalid checksum")
	}

	return nil
}

//nolint:staticcheck
var ErrNoCTip = "No CTIP found for sidechain!"
