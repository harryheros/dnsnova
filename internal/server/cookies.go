package server

import (
	"path/filepath"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/cookie"
)

// applyCookies turns DNS Cookies on or off as c says. The secret is read
// (or made) the first time they are on and kept in data_dir/secrets, so
// clients' cookies survive a restart and nodes can share it.
func (s *Server) applyCookies(c *config.Config) {
	if !c.Server.Cookies {
		s.res.SetCookies(nil)
		return
	}
	if s.cookieJar == nil {
		path := filepath.Join(c.Server.DataDir, "secrets", "cookie-secret")
		secret, err := cookie.LoadSecret(path)
		if err != nil {
			s.Log.Error("DNS Cookies are off: cannot read or create the secret", "err", err)
			s.res.SetCookies(nil)
			return
		}
		s.cookieJar = cookie.NewJar(secret)
	}
	s.res.SetCookies(s.cookieJar)
}
