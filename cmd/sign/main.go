// Build-time manifest signer. Reads a 32-byte Ed25519 seed (hex) from
// AGENT_SIGNING_KEY, signs the input file, and writes a hex signature to the
// output. Used by the release build to sign the update manifest so agents with
// the matching embedded public key can verify it. No-op unless the key is set.
//
//	go run ./cmd/sign manifest.json manifest.json.sig
//
// Since 21 Oct 2026 the API image is built UNSIGNED in CI and this tool runs
// on the deploy box (shipped inside the image as /usr/local/bin/opservo-sign)
// to add the signature there. AGENT_SIGNING_EXPECT_PUB, when set, must equal
// the public key derived from the seed: it is the key compiled into the agent
// binaries of that image, so a box holding the wrong seed (staging's seed
// for a prod image, say) fails here instead of shipping a manifest every
// agent would refuse.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
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
	seed, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "AGENT_SIGNING_KEY must be 64 hex chars (32-byte Ed25519 seed)")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if want := strings.TrimSpace(os.Getenv("AGENT_SIGNING_EXPECT_PUB")); want != "" && want != pubHex {
		fmt.Fprintf(os.Stderr, "AGENT_SIGNING_KEY derives public key %s but the agents in this build expect %s — wrong seed for this image\n", pubHex, want)
		os.Exit(1)
	}
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
	fmt.Fprintln(os.Stderr, "signed; public key:", pubHex)
}
