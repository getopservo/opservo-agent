package collectors

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// /etc/infrapilot/pg.conf holds ONE libpq connection string — a URI
// (postgresql://user:pass@host:5432/db?sslmode=require) or keyword/value
// pairs (host=… user=… password=… dbname=…). It used to be handed to psql on
// the command line, which put the password in `ps` for every local user.
// pgConnEnv translates it into libpq's PG* environment variables instead, so
// argv only ever holds `psql -X -At … -c <query>`; the child's environment is
// readable only by root and the agent's own user.
//
// Every parameter must map to a known env var: an unknown one is an error
// (the collector then skips the configured instance and logs why) rather than
// silently dropping, say, sslmode. libpq's own precedence applies for anything
// not listed (defaults), which is the same as before: the URI had no way to
// set those either.
var pgParamEnv = map[string]string{
	"host":                     "PGHOST",
	"hostaddr":                 "PGHOSTADDR",
	"port":                     "PGPORT",
	"user":                     "PGUSER",
	"password":                 "PGPASSWORD",
	"dbname":                   "PGDATABASE",
	"sslmode":                  "PGSSLMODE",
	"requiressl":               "PGREQUIRESSL",
	"sslcompression":           "PGSSLCOMPRESSION",
	"sslcert":                  "PGSSLCERT",
	"sslkey":                   "PGSSLKEY",
	"sslpassword":              "PGSSLPASSWORD",
	"sslrootcert":              "PGSSLROOTCERT",
	"sslcrl":                   "PGSSLCRL",
	"sslcrldir":                "PGSSLCRLDIR",
	"sslsni":                   "PGSSLSNI",
	"sslnegotiation":           "PGSSLNEGOTIATION",
	"ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
	"ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION",
	"connect_timeout":          "PGCONNECT_TIMEOUT",
	"application_name":         "PGAPPNAME",
	"options":                  "PGOPTIONS",
	"service":                  "PGSERVICE",
	"passfile":                 "PGPASSFILE",
	"channel_binding":          "PGCHANNELBINDING",
	"target_session_attrs":     "PGTARGETSESSIONATTRS",
	"load_balance_hosts":       "PGLOADBALANCEHOSTS",
	"require_auth":             "PGREQUIREAUTH",
	"gssencmode":               "PGGSSENCMODE",
	"gsslib":                   "PGGSSLIB",
	"gssdelegation":            "PGGSSDELEGATION",
	"krbsrvname":               "PGKRBSRVNAME",
	"client_encoding":          "PGCLIENTENCODING",
	"keepalives":               "PGKEEPALIVES",
	"keepalives_idle":          "PGKEEPALIVESIDLE",
	"keepalives_interval":      "PGKEEPALIVESINTERVAL",
	"keepalives_count":         "PGKEEPALIVESCOUNT",
	"tcp_user_timeout":         "PGTCPUSERTIMEOUT",
}

// pgConnEnv parses a libpq connection string into KEY=VALUE env entries
// (sorted, deterministic). Pure, so it is unit-tested.
func pgConnEnv(conn string) ([]string, error) {
	conn = strings.TrimSpace(conn)
	if conn == "" {
		return nil, fmt.Errorf("empty connection string")
	}
	params := map[string]string{}
	set := func(k, v string) error {
		k = strings.ToLower(strings.TrimSpace(k))
		if _, known := pgParamEnv[k]; !known {
			return fmt.Errorf("unsupported connection parameter %q", k)
		}
		if strings.ContainsAny(v, "\x00\n") {
			return fmt.Errorf("connection parameter %q has an invalid value", k)
		}
		if v != "" {
			params[k] = v
		}
		return nil
	}

	if strings.Contains(conn, "://") {
		u, err := url.Parse(conn)
		if err != nil {
			return nil, fmt.Errorf("parse connection URI: %w", err)
		}
		if s := strings.ToLower(u.Scheme); s != "postgres" && s != "postgresql" {
			return nil, fmt.Errorf("unsupported URI scheme %q", u.Scheme)
		}
		if u.User != nil {
			if err := set("user", u.User.Username()); err != nil {
				return nil, err
			}
			if pw, ok := u.User.Password(); ok {
				if err := set("password", pw); err != nil {
					return nil, err
				}
			}
		}
		if h := u.Hostname(); h != "" {
			if err := set("host", h); err != nil {
				return nil, err
			}
		}
		if p := u.Port(); p != "" {
			if err := set("port", p); err != nil {
				return nil, err
			}
		}
		if db := strings.TrimPrefix(u.Path, "/"); db != "" {
			if err := set("dbname", db); err != nil {
				return nil, err
			}
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("parse connection URI query: %w", err)
		}
		for k, vs := range q {
			if len(vs) == 0 {
				continue
			}
			if err := set(k, vs[len(vs)-1]); err != nil {
				return nil, err
			}
		}
	} else {
		// keyword=value pairs; a value may be single-quoted but must not
		// contain whitespace (libpq allows it, this file never needed it).
		for _, tok := range strings.Fields(conn) {
			k, v, ok := strings.Cut(tok, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("malformed connection parameter %q", tok)
			}
			if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
				v = v[1 : len(v)-1]
			}
			if err := set(k, v); err != nil {
				return nil, err
			}
		}
	}
	if len(params) == 0 {
		return nil, fmt.Errorf("connection string names no parameters")
	}

	env := make([]string, 0, len(params))
	for k, v := range params {
		env = append(env, pgParamEnv[k]+"="+v)
	}
	sort.Strings(env)
	return env, nil
}
