package main

import (
	"flag"
	"testing"
)

func TestDevTLSAllowedOnlyForLoopback(t *testing.T) {
	for url, want := range map[string]bool{
		"http://localhost:3001":      true,
		"https://localhost":          true,
		"https://127.0.0.1:3001":     true,
		"https://[::1]:3001":         true,
		"https://api.getopservo.com": false,
		"https://localhost.evil.com": false,
		"https://192.0.2.10":         false,
		"::not a url":                false,
	} {
		if got := devTLSAllowed(url); got != want {
			t.Errorf("devTLSAllowed(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestFlagSetOnCommandLine(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("secret-key", "from-env", "")
	fs.String("agent-id", "", "")
	if err := fs.Parse([]string{"--agent-id=x"}); err != nil {
		t.Fatal(err)
	}
	if flagSetOnCommandLine(fs, "secret-key") {
		t.Error("secret-key came from the environment default, not argv")
	}
	if !flagSetOnCommandLine(fs, "agent-id") {
		t.Error("agent-id was passed on the command line")
	}
}
