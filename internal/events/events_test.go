package events

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestTee(t *testing.T) {
	var out bytes.Buffer
	l := &Log{}
	log := slog.New(Tee(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn}), l))
	log.Debug("hidden")
	log.Info("listening", "addr", "x")
	log.Info("configuration applied", "mode", "public")
	log.With("upstream", "tls://9.9.9.9").Warn("unhealthy")
	log.Error("bind failed", "err", "in use")
	got := l.Recent(10)
	if len(got) != 3 {
		t.Fatalf("%d events: %+v", len(got), got)
	}
	if got[0].Level != "error" || got[0].Msg != "bind failed err=in use" {
		t.Fatalf("newest first: %+v", got[0])
	}
	if got[1].Msg != "unhealthy upstream=tls://9.9.9.9" || got[2].Msg != "configuration applied mode=public" {
		t.Fatalf("messages: %+v", got)
	}
	// the wrapped handler keeps its own level
	if strings.Contains(out.String(), "configuration applied") || !strings.Contains(out.String(), "bind failed") {
		t.Fatalf("passed through: %q", out.String())
	}
	for i := 0; i < Size+5; i++ {
		l.Add(Event{Msg: "x"})
	}
	if n := len(l.Recent(0)); n != Size {
		t.Fatalf("ring holds %d", n)
	}
}
