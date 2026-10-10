package collectors

import (
	"regexp"
	"strings"
)

// Secret masking for log lines, run on the server BEFORE a line is buffered,
// hashed or shipped — so a password, token or private key printed into a log
// never leaves the box. Mirrors the API's free-log-explainer masker
// (maskSecrets) minus the IP rules: addresses in "connect to 10.0.0.5:6379
// refused" are what makes the diagnosis, so they stay readable. Emails are
// masked (personal data, never needed to explain an error). Deliberately
// aggressive: a masked value costs a little detail, a leaked key costs the
// customer their account.

var (
	pemKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	// scheme://user:pass@host
	urlCredRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@`)
	authHdrRe = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*["']?)(?:bearer|basic|token|digest)\s+[^\s"',;]+`)
	bearerRe  = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)

	// Known credential formats, checked before the generic rules.
	tokenRes = []*regexp.Regexp{
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
		regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b`),  // AWS key ids
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b`),                 // GitHub
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{30,}\b`),                             //
		regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),                                 // GitLab
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),                               // Slack
		regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`),              // Stripe
		regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`),                       // OpenAI / Anthropic
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),                                    // Google API key
		regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`),                 // SendGrid
		regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),                                      //
	}

	secretKeys = `password|passwd|pwd|pass|secret|client_secret|token|access_token|refresh_token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|auth|session(?:id)?|cookie|credentials?|signature|sig`
	// key=value / key: value / "key": "value" / 'key' => 'value'
	kvSecretRe   = regexp.MustCompile(`(?i)(["']?[\w.-]*?(?:` + secretKeys + `)["']?\s*(?:=>|[:=])\s*)(["']?)([^\s"',;&}]+)`)
	flagSecretRe = regexp.MustCompile(`(?i)(--(?:` + secretKeys + `)[\w-]*[ =])(["']?)[^\s"']+`)
	mysqlPassRe  = regexp.MustCompile(`(\bmysql(?:dump|admin)?\b[^\n]*?\s-p)([^\s]+)`)
	keptValueRe  = regexp.MustCompile(`(?i)^(?:null|none|true|false|\*+|""|\[redacted\]|\[token\]|\[password\]|\[PRIVATE KEY\])$`)

	emailRe   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	longHexRe = regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`)
	blobRe    = regexp.MustCompile(`[A-Za-z0-9+_=-]{32,}`)
)

// RedactSecrets replaces every secret-looking value in a log line. Pure.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	s = pemKeyRe.ReplaceAllString(s, "[PRIVATE KEY]")
	s = urlCredRe.ReplaceAllString(s, "${1}[user]:[password]@")
	s = authHdrRe.ReplaceAllString(s, "${1}[redacted]")
	s = bearerRe.ReplaceAllString(s, "${1}[redacted]")
	for _, re := range tokenRes {
		s = re.ReplaceAllString(s, "[token]")
	}
	s = kvSecretRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := kvSecretRe.FindStringSubmatch(m)
		if keptValueRe.MatchString(sub[3]) {
			return m
		}
		return sub[1] + sub[2] + "[redacted]"
	})
	s = flagSecretRe.ReplaceAllString(s, "${1}${2}[redacted]")
	s = mysqlPassRe.ReplaceAllString(s, "${1}[redacted]")
	s = emailRe.ReplaceAllString(s, "[email]")
	s = longHexRe.ReplaceAllString(s, "[token]")
	s = blobRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
			strings.ContainsAny(m, "abcdefghijklmnopqrstuvwxyz") &&
			strings.ContainsAny(m, "0123456789") {
			return "[token]"
		}
		return m
	})
	return s
}
