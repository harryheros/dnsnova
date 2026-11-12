package server

import (
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/harryheros/dnsnova/internal/config"
)

// hostFacts is what the security self-check looks at outside the
// configuration, gathered by gatherFacts (tests fill it in by hand).
type hostFacts struct {
	euid       int
	configPath string
	configMode fs.FileMode // 0 if unknown
	secrets    map[string]fs.FileMode
	keyMode    fs.FileMode // tls.key_file, 0 if unknown
	account    bool        // the administrator exists
	totp       bool        // and has two-step verification
}

// securityFindings lists settings and file permissions that weaken the
// server, worst first. Each is one line for the log, starting with
// "security:". None of them stops the server: they are things an operator
// should know about, and may have chosen on purpose.
func securityFindings(c *config.Config, f hostFacts) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, "security: "+fmt.Sprintf(format, a...)) }

	// A server for a home or office network (private mode) serves its admin
	// interface to that network over plain HTTP on purpose.
	if remote, port := reachableFromOthers(c.Admin.Listen); remote && c.Server.Mode == config.ModePublic {
		if c.TLS.Certificate == "off" {
			add("the admin interface listens on %s with no certificate, so other machines are refused (plain HTTP is answered only on this server); "+
				"reach it through an SSH tunnel (ssh -L %s:127.0.0.1:%s), or set up a domain for HTTPS. admin.listen = \"127.0.0.1:%s\" makes the tunnel the only way",
				c.Admin.Listen, port, port, port)
		}
		if f.account && !f.totp {
			add("two-step verification is off while the admin interface (%s) is reachable from other machines; turn it on under Account", c.Admin.Listen)
		}
	}
	for name, mode := range f.secrets {
		if mode&0o077 != 0 {
			add("%s can be read by other users (mode %04o); it holds the administrator's password hash and keys: chmod go-rwx %s", name, mode.Perm(), name)
		}
	}
	if f.keyMode&0o004 != 0 {
		add("the TLS private key %s can be read by every user (mode %04o): chmod o-r %s", c.TLS.KeyFile, f.keyMode.Perm(), c.TLS.KeyFile)
	}
	if f.configMode&0o002 != 0 {
		add("anyone on this machine can change the settings: %s is world-writable (mode %04o): chmod o-w %s", f.configPath, f.configMode.Perm(), f.configPath)
	}
	if remote, _ := reachableFromOthers(c.Metrics.Listen); remote {
		add("metrics.listen = %q is reachable from other machines and /metrics needs no password; prefer 127.0.0.1", c.Metrics.Listen)
	}
	if c.Server.Mode == config.ModePublic && len(c.Server.Listen) > 0 {
		if c.Limits.RRLRate == 0 {
			add("public mode without response rate limiting (limits.rrl_rate = 0): the server can be used to reflect traffic at others")
		}
		if c.Limits.ClientQPS == 0 && c.Limits.PrefixQPS == 0 {
			add("public mode without per-client limits (limits.client_qps and prefix_qps = 0): one client can use the whole server")
		}
		if !c.Limits.BlockANY {
			add("public mode answers ANY queries (limits.block_any = false): large answers make reflection attacks stronger")
		}
	}
	for _, p := range c.Server.ProxyProtocol {
		if p.Bits() < 8 {
			add("server.proxy_protocol includes %s: anyone in it can claim to be any client, past access lists and limits; list only the load balancers", p)
		}
	}
	if f.euid == 0 {
		add("running as root; the installed service runs as the dnsnova user with only the right to bind low ports")
	}
	return out
}

// reachableFromOthers reports whether a listen address accepts connections
// from other machines (anything but loopback), and its port.
func reachableFromOthers(listen string) (bool, string) {
	if listen == "" {
		return false, ""
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return true, ""
	}
	if host == "localhost" {
		return false, port
	}
	a, err := netip.ParseAddr(host)
	return err != nil || !a.Unmap().IsLoopback(), port
}

// gatherFacts reads what securityFindings needs from this machine.
func (s *Server) gatherFacts(c *config.Config) hostFacts {
	f := hostFacts{euid: os.Geteuid(), secrets: map[string]fs.FileMode{}}
	if s.Store != nil {
		f.configPath = s.Store.Path
		if fi, err := os.Stat(s.Store.Path); err == nil {
			f.configMode = fi.Mode()
		}
	}
	dir := filepath.Join(c.Server.DataDir, "secrets")
	if fi, err := os.Stat(dir); err == nil {
		f.secrets[dir] = fi.Mode().Perm()
		if ents, err := os.ReadDir(dir); err == nil {
			for _, e := range ents {
				if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
					f.secrets[filepath.Join(dir, e.Name())] = fi.Mode().Perm()
				}
			}
		}
	}
	if c.TLS.Certificate == "files" && c.TLS.KeyFile != "" {
		if fi, err := os.Stat(c.TLS.KeyFile); err == nil {
			f.keyMode = fi.Mode().Perm()
		}
	}
	if a := s.admin; a != nil {
		f.account, f.totp = a.AccountState()
	}
	return f
}

// selfCheck logs the security findings for c (with s.mu held, which
// guards s.admin): all of them at startup
// (all=true), and after a change only the ones that are new, so saving a
// setting does not repeat every warning. The log feeds the admin
// interface's event list too.
func (s *Server) selfCheck(c *config.Config, all bool) {
	found := securityFindings(c, s.gatherFacts(c))
	s.checkMu.Lock()
	prev := s.lastFindings
	s.lastFindings = found
	s.checkMu.Unlock()
	for _, f := range found {
		if all || !slices.Contains(prev, f) {
			s.Log.Warn(f)
		}
	}
}
