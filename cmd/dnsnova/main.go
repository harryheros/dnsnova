// Command dnsnova is a DNS server for public and private resolvers: it
// resolves names itself or forwards them to upstreams.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfgPath := flag.String("c", "/etc/dnsnova/dnsnova.toml", "configuration file")
	check := flag.Bool("t", false, "check the configuration file and exit")
	showVersion := flag.Bool("v", false, "print the version and exit")
	resetAdmin := flag.Bool("reset-admin", false, "forgot the password: remove the administrator account, then restart dnsnova")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: dnsnova [-c file] [-t] [-v] [-reset-admin]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("dnsnova", version)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store := config.NewStore(*cfgPath)

	if *resetAdmin {
		snap, err := store.Load()
		if err != nil {
			printConfigError(*cfgPath, err)
			os.Exit(1)
		}
		if err := admin.ResetAccount(snap.Config.Server.DataDir); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v (run it as root)\n", err)
			os.Exit(1)
		}
		fmt.Println("The administrator account was removed; settings are kept.")
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			if out, err := exec.Command("systemctl", "try-restart", "dnsnova").CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "could not restart dnsnova: %v %s\nRestart it yourself: systemctl restart dnsnova\n", err, out)
				os.Exit(1)
			}
			fmt.Println("dnsnova was restarted.")
		} else {
			fmt.Println("Restart dnsnova now.")
		}
		fmt.Println("Open the web interface and create the administrator again.")
		return
	}

	if *check {
		snap, err := store.Load()
		if err != nil {
			printConfigError(*cfgPath, err)
			os.Exit(1)
		}
		for _, w := range snap.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
		if c := snap.Config; c.TLS.Certificate == "files" {
			if _, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile); err != nil {
				fmt.Fprintf(os.Stderr, "%s: tls: %v\n", *cfgPath, err)
				os.Exit(1)
			}
		}
		fmt.Printf("%s: ok\n", *cfgPath)
		return
	}

	srv, err := server.New(store, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}
	srv.BuildVersion = version
	if err := srv.Start(); err != nil {
		printConfigError(*cfgPath, err)
		os.Exit(1)
	}
	log.Info("dnsnova " + version)
	go srv.WatchConfig(2 * time.Second)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			if err := srv.Reload(); err != nil {
				log.Error("reload failed; keeping the running configuration", "err", err)
			}
			continue
		}
		log.Info("shutting down", "signal", s.String())
		srv.Shutdown()
		return
	}
}

func printConfigError(path string, err error) {
	var pe *config.ParseError
	var es config.Errors
	switch {
	case errors.As(err, &pe):
		fmt.Fprintf(os.Stderr, "%s:%d: %s\n", path, pe.Line, pe.Msg)
	case errors.As(err, &es):
		for _, e := range es {
			if e.Line > 0 {
				fmt.Fprintf(os.Stderr, "%s:%d: %s: %s\n", path, e.Line, e.Key, e.Msg)
			} else {
				fmt.Fprintf(os.Stderr, "%s: %s\n", path, e.Error())
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "dnsnova: %v\n", err)
	}
}
