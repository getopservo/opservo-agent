package collectors

import (
	"reflect"
	"testing"
)

func TestPgConnEnv_URI(t *testing.T) {
	env, err := pgConnEnv("postgresql://monitor:s3cr%40t@db.internal:5433/app?sslmode=require&application_name=opservo")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PGAPPNAME=opservo",
		"PGDATABASE=app",
		"PGHOST=db.internal",
		"PGPASSWORD=s3cr@t",
		"PGPORT=5433",
		"PGSSLMODE=require",
		"PGUSER=monitor",
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %v, want %v", env, want)
	}
}

func TestPgConnEnv_URIDefaults(t *testing.T) {
	// No port / db / password: only what is present is exported, so libpq's
	// own defaults (5432, dbname = user) apply exactly as they did for the URI.
	env, err := pgConnEnv("postgres://ro@10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PGHOST=10.0.0.5", "PGUSER=ro"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %v, want %v", env, want)
	}
}

func TestPgConnEnv_Keywords(t *testing.T) {
	env, err := pgConnEnv("host=rds.internal port=5432 user=ro password='pa=ss' dbname=app sslmode=verify-full sslrootcert=/etc/ssl/rds.pem")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PGDATABASE=app",
		"PGHOST=rds.internal",
		"PGPASSWORD=pa=ss",
		"PGPORT=5432",
		"PGSSLMODE=verify-full",
		"PGSSLROOTCERT=/etc/ssl/rds.pem",
		"PGUSER=ro",
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %v, want %v", env, want)
	}
}

func TestPgConnEnv_Rejects(t *testing.T) {
	bad := []string{
		"",
		"mysql://u:p@h/db",
		"postgres://u:p@h/db?bogus=1", // unknown parameter is never dropped silently
		"host=h bogus=1",
		"host=h user",
		"postgres://u:p@h/db?sslmode=require%0APGOPTIONS=x", // newline injection
		"://nope",
	}
	for _, c := range bad {
		if env, err := pgConnEnv(c); err == nil {
			t.Fatalf("%q: expected error, got %v", c, env)
		}
	}
}
