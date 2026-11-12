package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Secrets are where notifications go. Webhook addresses and bot tokens
// are credentials: they live in data_dir/secrets/alerts.json (mode 0600),
// not in the configuration, so they are not in its history, not synced to
// a cluster's followers, and never shown again once saved.
type Secrets struct {
	Webhook   WebhookSecret  `json:"webhook,omitzero"`
	Slack     URLSecret      `json:"slack,omitzero"`
	Discord   URLSecret      `json:"discord,omitzero"`
	Telegram  TelegramSecret `json:"telegram,omitzero"`
	Heartbeat URLSecret      `json:"heartbeat,omitzero"`
}

type URLSecret struct {
	URL string `json:"url"`
}

type WebhookSecret struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

type TelegramSecret struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
}

// Names of the destinations, as the admin API calls them.
var Names = []string{"webhook", "slack", "discord", "telegram", "heartbeat"}

// LoadSecrets reads the file; a missing one is empty.
func LoadSecrets(path string) (*Secrets, error) {
	s := &Secrets{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Save writes the file atomically, mode 0600.
func (s *Secrets) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Channels returns the channels that are set up.
func (s *Secrets) Channels() []Channel {
	var out []Channel
	if s.Webhook.URL != "" {
		out = append(out, Webhook{URL: s.Webhook.URL, Secret: s.Webhook.Secret})
	}
	if s.Slack.URL != "" {
		out = append(out, Slack{URL: s.Slack.URL})
	}
	if s.Discord.URL != "" {
		out = append(out, Discord{URL: s.Discord.URL})
	}
	if s.Telegram.Token != "" && s.Telegram.ChatID != "" {
		out = append(out, Telegram{Token: s.Telegram.Token, ChatID: s.Telegram.ChatID})
	}
	return out
}

// Shown is what the admin page may see of a destination: whether it is
// set, and a hint to recognise it (the host, the chat), never the secret.
type Shown struct {
	Set  bool   `json:"set"`
	Hint string `json:"hint,omitempty"`
}

// Show returns every destination as the admin page may see it.
func (s *Secrets) Show() map[string]Shown {
	host := func(u string) Shown {
		if u == "" {
			return Shown{}
		}
		p, err := url.Parse(u)
		if err != nil {
			return Shown{Set: true}
		}
		return Shown{Set: true, Hint: p.Scheme + "://" + p.Host + "/…"}
	}
	tg := Shown{}
	if s.Telegram.Token != "" {
		tg = Shown{Set: true, Hint: "chat " + s.Telegram.ChatID}
	}
	return map[string]Shown{"webhook": host(s.Webhook.URL), "slack": host(s.Slack.URL), "discord": host(s.Discord.URL),
		"telegram": tg, "heartbeat": host(s.Heartbeat.URL)}
}

var (
	telegramToken = regexp.MustCompile(`^[0-9]{3,15}:[A-Za-z0-9_-]{20,100}$`)
	telegramChat  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
)

// Set changes one destination from the fields the admin page sent (all
// empty: remove it). It checks them first.
func (s *Secrets) Set(name string, f map[string]string) error {
	empty := true
	for _, v := range f {
		if strings.TrimSpace(v) != "" {
			empty = false
		}
	}
	checkURL := func(u string, httpOK bool) error {
		p, err := url.Parse(u)
		if err != nil || p.Host == "" || (p.Scheme != "https" && !(httpOK && p.Scheme == "http")) {
			if httpOK {
				return fmt.Errorf("%s: an http:// or https:// address", name)
			}
			return fmt.Errorf("%s: an https:// address", name)
		}
		return nil
	}
	u := strings.TrimSpace(f["url"])
	switch name {
	case "webhook":
		if empty {
			s.Webhook = WebhookSecret{}
			return nil
		}
		if err := checkURL(u, true); err != nil {
			return err
		}
		s.Webhook = WebhookSecret{URL: u, Secret: strings.TrimSpace(f["secret"])}
	case "slack", "discord", "heartbeat":
		if !empty {
			if err := checkURL(u, name == "heartbeat"); err != nil {
				return err
			}
		}
		switch name {
		case "slack":
			s.Slack.URL = u
		case "discord":
			s.Discord.URL = u
		default:
			s.Heartbeat.URL = u
		}
	case "telegram":
		if empty {
			s.Telegram = TelegramSecret{}
			return nil
		}
		tok, chat := strings.TrimSpace(f["token"]), strings.TrimSpace(f["chat_id"])
		if !telegramToken.MatchString(tok) {
			return errors.New("telegram: the bot token from @BotFather, like 123456789:AA…")
		}
		if !telegramChat.MatchString(chat) {
			return errors.New("telegram: the chat ID (a number, negative for groups) or @channelname")
		}
		s.Telegram = TelegramSecret{Token: tok, ChatID: chat}
	default:
		return fmt.Errorf("unknown destination %q", name)
	}
	return nil
}

// Heartbeat requests url every interval while ctx lasts, so that an
// outside monitor (healthchecks.io, a company's own) notices when this
// server stops, which it cannot report itself. url is read each time.
func Heartbeat(ctx context.Context, url func() string, every time.Duration, log *slog.Logger) {
	failing := false
	for {
		if u := url(); u != "" {
			c, cancel := context.WithTimeout(ctx, sendTimeout)
			req, err := http.NewRequestWithContext(c, http.MethodGet, u, nil)
			var resp *http.Response
			if err == nil {
				req.Header.Set("User-Agent", "DNSNova-alerts/1")
				resp, err = client.Do(req)
			}
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode/100 != 2 {
					err = &httpError{code: resp.StatusCode}
				}
			}
			cancel()
			switch {
			case err != nil && !failing && ctx.Err() == nil:
				log.Warn("alert: heartbeat not delivered", "err", redact(err, u))
				failing = true
			case err == nil && failing:
				log.Info("alert: heartbeat delivered again")
				failing = false
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
