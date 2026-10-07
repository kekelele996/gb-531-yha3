package config

import (
	"testing"
)

func TestVerificationGraceDaysParsing(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret-at-least-32-bytes-long")

	t.Run("defaults to zero", func(t *testing.T) {
		t.Setenv("VERIFICATION_GRACE_DAYS", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}
		if cfg.VerificationGraceDays != 0 {
			t.Fatalf("grace days = %d, want 0", cfg.VerificationGraceDays)
		}
	})

	t.Run("accepts explicit zero", func(t *testing.T) {
		t.Setenv("VERIFICATION_GRACE_DAYS", "0")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}
		if cfg.VerificationGraceDays != 0 {
			t.Fatalf("grace days = %d, want 0", cfg.VerificationGraceDays)
		}
	})

	t.Run("accepts positive value", func(t *testing.T) {
		t.Setenv("VERIFICATION_GRACE_DAYS", "14")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}
		if cfg.VerificationGraceDays != 14 {
			t.Fatalf("grace days = %d, want 14", cfg.VerificationGraceDays)
		}
	})

	for _, raw := range []string{"-1", "abc"} {
		raw := raw
		t.Run("rejects "+raw, func(t *testing.T) {
			t.Setenv("VERIFICATION_GRACE_DAYS", raw)
			if _, err := Load(); err == nil {
				t.Fatalf("expected error for VERIFICATION_GRACE_DAYS=%q", raw)
			}
		})
	}
}
