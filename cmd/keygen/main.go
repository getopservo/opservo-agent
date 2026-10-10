// One-shot Ed25519 keypair generator for agent update code-signing.
// Prints the SEED (private, set as AGENT_SIGNING_KEY) and the PUBLIC key
// (embed in updater.go's signingPublicKeyHex). Keep the seed offline + secret.
//
//	go run ./cmd/keygen
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Println("AGENT_SIGNING_KEY (seed, KEEP SECRET):", hex.EncodeToString(priv.Seed()))
	fmt.Println("signingPublicKeyHex (embed in agent):", hex.EncodeToString(pub))
}
