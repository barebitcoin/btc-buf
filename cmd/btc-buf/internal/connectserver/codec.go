package connectserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
)

// protoJsonCodec is the upstream Connect JSON codec, with a few changes:
//
// Unmarshalling:
//  1. We're NOT allowing unknown fields or enum values
//  2. We make sure to not leak internal details on unmarshalling errors
//  3. An empty payload is the empty message, not an error
//
// Marshalling:
//  1. Emit default values
type protoJsonCodec struct {
	*connectproto.JSONCodec
}

func newProtoJsonCodec() protoJsonCodec {
	codec := connectproto.NewJSONCodec()
	codec.MarshalOptions.EmitDefaultValues = true
	codec.UnmarshalOptions.DiscardUnknown = false
	return protoJsonCodec{codec}
}

// UnmarshalRead buffers the payload itself, rather than delegating to the
// upstream codec, so that we have the raw bytes available when producing
// error messages.
func (p protoJsonCodec) UnmarshalRead(ctx context.Context, src io.Reader, message any) error {
	protoMessage, ok := message.(proto.Message)
	if !ok {
		return fmt.Errorf("%T doesn't implement proto.Message", message)
	}
	data, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	// Treat an empty body as the empty message, so requests without fields
	// can be sent without a body.
	if len(data) == 0 {
		data = []byte("{}")
	}

	err = p.UnmarshalOptions.Unmarshal(data, protoMessage)
	switch {
	case !json.Valid(data):
		return errors.New("invalid json")

	// We want to hide internal details on unmarshalling errors, but still
	// provide a meaningful error message. Connect wraps whatever we return
	// here in a CodeInvalidArgument error.
	case err != nil:
		// Check specifically for enum errors and provide a clearer message
		if strings.Contains(err.Error(), "invalid value for enum field") {
			if parts := strings.Split(err.Error(), "field "); len(parts) > 1 {
				fieldName := strings.Split(parts[1], ":")[0]
				return fmt.Errorf("invalid value for %q", strings.Trim(fieldName, `"`))
			}
		}

		if strings.Contains(err.Error(), "unknown field") {
			if parts := strings.Split(err.Error(), "field "); len(parts) > 1 {
				fieldName := strings.Split(parts[1], ":")[0]
				return fmt.Errorf("unknown field: %q", strings.Trim(fieldName, `"`))
			}
		}

		if strings.Contains(err.Error(), "invalid value for double field") {
			if parts := strings.Split(err.Error(), "field "); len(parts) > 1 {
				fieldName := strings.Split(parts[1], ":")[0]
				return fmt.Errorf("invalid number for %q", strings.Trim(fieldName, `"`))
			}
		}

		zerolog.Ctx(ctx).Err(err).
			Msgf("server: protojson codec: unable to unmarshal %T", message)

		// For other errors, return a generic message
		return errors.New("unable to parse request")
	}

	return nil
}

var (
	_ connect.Codec       = protoJsonCodec{}
	_ connect.StableCodec = protoJsonCodec{}
)
