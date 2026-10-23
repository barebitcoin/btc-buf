package server

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
)

// mapSlice returns f applied to each element of s, along with its index.
func mapSlice[T, R any](s []T, f func(T, int) R) []R {
	out := make([]R, len(s))
	for i, v := range s {
		out[i] = f(v, i)
	}
	return out
}

// mapValues returns m with f applied to each value, along with its key.
func mapValues[K comparable, V, R any](m map[K]V, f func(V, K) R) map[K]R {
	out := make(map[K]R, len(m))
	for k, v := range m {
		out[k] = f(v, k)
	}
	return out
}

// deref returns the value p points to, or the zero value if p is nil.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// nonZeroPtr returns a pointer to v, or nil if v is the zero value.
func nonZeroPtr[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return &v
}

// secondsDuration converts Core's decimal seconds to a duration, or nil for
// zero, which Core uses for absent values.
func secondsDuration(seconds float64) *durationpb.Duration {
	if seconds == 0 {
		return nil
	}
	return durationpb.New(time.Duration(seconds * float64(time.Second)))
}
