package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration written as "10m", "24h" or "90s".
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	if v < 0 {
		return fmt.Errorf("duration %q must not be negative", s)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// ByteSize is a size written as "8MB", "1GB" or a plain number of bytes.
type ByteSize int64

func (b *ByteSize) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := ParseByteSize(s)
	if err != nil {
		return err
	}
	*b = ByteSize(v)
	return nil
}

func (b ByteSize) MarshalYAML() (any, error) { return strconv.FormatInt(int64(b), 10), nil }

// ParseByteSize reads sizes such as "512", "8KB", "8MB" or "1GB" (powers of 1024).
func ParseByteSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(t, u.suffix) {
			mult = u.mult
			t = strings.TrimSpace(strings.TrimSuffix(t, u.suffix))
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}
