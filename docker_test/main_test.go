package main

import (
	"bytes"
	"testing"
)

func TestLoadConfigFromEnvironment(t *testing.T) {
	original := append([]byte(nil), key...)
	t.Cleanup(func() { key = original })

	t.Run("missing", func(t *testing.T) {
		key = []byte("existing-key")
		t.Setenv("ENCRYPTION_KEY", "")
		if err := loadConfig(); err == nil {
			t.Fatal("expected a missing key error")
		}
		if !bytes.Equal(key, []byte("existing-key")) {
			t.Fatal("failed load must not replace the existing key")
		}
	})

	for _, invalid := range []string{
		"too-short",
		"0123456789abcdefghijklmn",
		"0123456789abcdefghijklmnopqrstuv",
	} {
		t.Run("invalid length", func(t *testing.T) {
			key = []byte("existing-key")
			t.Setenv("ENCRYPTION_KEY", invalid)
			if err := loadConfig(); err == nil {
				t.Fatal("expected an invalid key length error")
			}
			if !bytes.Equal(key, []byte("existing-key")) {
				t.Fatal("failed load must not replace the existing key")
			}
		})
	}

	valid := "0123456789abcdef"
	t.Setenv("ENCRYPTION_KEY", valid)
	if err := loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !bytes.Equal(key, []byte(valid)) {
		t.Fatal("loaded key does not match the environment")
	}
}
