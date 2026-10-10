// Build-time manifest signer. Reads a 32-byte Ed25519 seed (hex) from
// AGENT_SIGNING_KEY, signs the input file, and writes a hex signature to the
// output. Used by the release build to sign the update manifest so agents with
// the matching embedded public key can verify it. No-op unless the key is set.
//
//	go run ./cmd/sign manifest.json manifest.json.sig
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	keyHex := os.Getenv("AGENT_SIGNING_KEY")
	if keyHex == "" {
		return // signing disabled — produce no .sig
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sign <in> <out>")
		os.Exit(2)
	}
	seed, err := hex.DecodeString(keyHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "AGENT_SIGNING_KEY must be 64 hex chars (32-byte Ed25519 seed)")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig := ed25519.Sign(priv, data)
	if err := os.WriteFile(os.Args[2], []byte(hex.EncodeToString(sig)), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Print the public key so the operator can confirm what to embed.
	fmt.Fprintln(os.Stderr, "signed; public key:", hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
}
