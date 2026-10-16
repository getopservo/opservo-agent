package main

import (
	"flag"
	"net"
	"net/url"
)

// devTLSAllowed reports whether --dev may relax TLS verification for apiURL:
// only for a loopback API (https://localhost, 127.0.0.1, ::1). Against any
// other host --dev keeps verbose logging but TLS stays verified and the secret
// is never printed, so pointing a dev build at a real API can't leak the key
// to a man in the middle.
func devTLSAllowed(apiURL string) bool {
	u, err := url.Parse(apiURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// flagSetOnCommandLine reports whether a flag was passed explicitly (as
// opposed to taking its default from the environment).
func flagSetOnCommandLine(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
