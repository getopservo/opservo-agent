package collectors

import "testing"

func TestParseSSHHardening(t *testing.T) {
	t.Run("hardened config", func(t *testing.T) {
		cfg := "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n" +
			"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
		h := parseSSHHardening(cfg)
		if !h.readable || h.passwordAuth || h.permitEmpty || h.weakCiphers {
			t.Fatalf("expected fully hardened, got %+v", h)
		}
	})

	t.Run("defaults when directives absent (password auth defaults to yes)", func(t *testing.T) {
		h := parseSSHHardening("# empty config\nPort 22\n")
		if !h.passwordAuth {
			t.Fatal("PasswordAuthentication should default to yes (true)")
		}
		if h.permitEmpty {
			t.Fatal("PermitEmptyPasswords should default to no (false)")
		}
	})

	t.Run("insecure config", func(t *testing.T) {
		cfg := "PasswordAuthentication yes\nPermitEmptyPasswords yes\n" +
			"Ciphers aes256-ctr,3des-cbc,arcfour\n"
		h := parseSSHHardening(cfg)
		if !h.passwordAuth {
			t.Fatal("expected passwordAuth true")
		}
		if !h.permitEmpty {
			t.Fatal("expected permitEmpty true")
		}
		if !h.weakCiphers {
			t.Fatal("expected weakCiphers true (3des/arcfour)")
		}
	})

	t.Run("comments and blanks ignored; last directive wins", func(t *testing.T) {
		cfg := "#PasswordAuthentication yes\n\nPasswordAuthentication yes\nPasswordAuthentication no\n"
		h := parseSSHHardening(cfg)
		if h.passwordAuth {
			t.Fatal("last PasswordAuthentication (no) should win")
		}
	})
}
