package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Channel delivers notifications somewhere.
type Channel interface {
	Name() string // webhook, slack, discord, telegram
	ID() string   // what makes two channels the same (its address)
	Send(ctx context.Context, n Notification) error
}

var client = &http.Client{Timeout: sendTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse // a webhook that redirects is misconfigured; do not follow it elsewhere
}}

// httpError is a channel's refusal.
type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string {
	if e.body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.code, e.body)
	}
	return fmt.Sprintf("HTTP %d", e.code)
}

// retryable: worth trying again (network trouble, 5xx, rate limited); a
// 4xx means the channel is set up wrong and will not get better.
func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.code >= 500 || he.code == http.StatusTooManyRequests
	}
	return true
}

func post(ctx context.Context, url string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DNSNova-alerts/1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return redact(err, url)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return &httpError{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return nil
}

// redact keeps a webhook's address (which is its secret) out of errors
// shown on the admin page and in the log.
func redact(err error, url string) error {
	return errors.New(strings.ReplaceAll(err.Error(), url, "(address)"))
}

// text is the plain message: a title line, the details, since when.
func text(n Notification) (title, body string) {
	label := strings.ToUpper(string(n.Severity))
	switch n.Status {
	case Resolved:
		label = "RESOLVED"
	case Reminder:
		label = "STILL " + label
	case Test:
		label = "TEST"
	}
	title = fmt.Sprintf("[%s] %s: %s", label, n.Node, n.Summary)
	var b strings.Builder
	for _, d := range n.Details {
		b.WriteString("• " + d + "\n")
	}
	if n.Status != Test {
		if n.Status == Resolved {
			fmt.Fprintf(&b, "Lasted %s (since %s)", n.Time.Sub(n.Since).Round(time.Second), n.Since.UTC().Format("2006-01-02 15:04 UTC"))
		} else {
			fmt.Fprintf(&b, "Since %s", n.Since.UTC().Format("2006-01-02 15:04 UTC"))
		}
	}
	body = b.String()
	if len(body) > 3500 { // well inside every platform's limit
		body = body[:3500] + "…"
	}
	return title, body
}

// Webhook posts the notification as JSON, signed: the header
// X-DNSNova-Signature is "sha256=" and the hex HMAC-SHA256, under the
// shared secret, of X-DNSNova-Timestamp, ".", and the body. A receiver
// checks it, and that the timestamp is recent, to know the message is
// DNSNova's and not played back.
type Webhook struct {
	URL    string
	Secret string
}

func (w Webhook) Name() string { return "webhook" }
func (w Webhook) ID() string   { return w.URL + "\x00" + w.Secret }

func (w Webhook) Send(ctx context.Context, n Notification) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	hdr := map[string]string{}
	if w.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		hdr["X-DNSNova-Timestamp"] = ts
		hdr["X-DNSNova-Signature"] = "sha256=" + Sign(w.Secret, ts, body)
	}
	return post(ctx, w.URL, body, hdr)
}

// Sign is the webhook signature of body sent at ts.
func Sign(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Slack posts to an incoming webhook.
type Slack struct{ URL string }

func (s Slack) Name() string { return "slack" }
func (s Slack) ID() string   { return s.URL }

func (s Slack) Send(ctx context.Context, n Notification) error {
	title, body := text(n)
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;") // Slack's markup: links and mentions stay text
	msg, _ := json.Marshal(map[string]any{"text": "*" + esc.Replace(title) + "*\n" + esc.Replace(body)})
	return post(ctx, s.URL, msg, nil)
}

// Discord posts to a channel webhook, as an embed coloured by severity.
type Discord struct{ URL string }

func (d Discord) Name() string { return "discord" }
func (d Discord) ID() string   { return d.URL }

func (d Discord) Send(ctx context.Context, n Notification) error {
	title, body := text(n)
	color := 0xE5A50A // warning: amber
	switch {
	case n.Status == Resolved:
		color = 0x2EA043
	case n.Status == Test:
		color = 0x3B82F6
	case n.Severity == Critical:
		color = 0xE5534B
	}
	if len(title) > 250 {
		title = title[:250] + "…"
	}
	msg, _ := json.Marshal(map[string]any{
		"username": "DNSNova",
		"embeds": []map[string]any{{"title": title, "description": body, "color": color,
			"timestamp": n.Time.UTC().Format(time.RFC3339), "footer": map[string]string{"text": "DNSNova · " + n.Server}}},
		// names in alerts come from the outside: never let one ping @everyone
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	return post(ctx, d.URL, msg, nil)
}

// Telegram sends through a bot to a chat.
type Telegram struct {
	Token, ChatID string
	API           string // default https://api.telegram.org (tests)
}

func (t Telegram) Name() string { return "telegram" }
func (t Telegram) ID() string   { return t.Token + "\x00" + t.ChatID }

func (t Telegram) Send(ctx context.Context, n Notification) error {
	title, body := text(n)
	api := t.API
	if api == "" {
		api = "https://api.telegram.org"
	}
	// plain text: nothing in a name can turn into markup
	msg, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": title + "\n" + body, "disable_web_page_preview": true})
	url := api + "/bot" + t.Token + "/sendMessage"
	err := post(ctx, url, msg, nil)
	var he *httpError
	if errors.As(err, &he) { // keep the type: whether to retry depends on it
		he.body = strings.ReplaceAll(he.body, t.Token, "(token)")
		return he
	}
	if err != nil {
		return errors.New(strings.ReplaceAll(err.Error(), t.Token, "(token)"))
	}
	return nil
}
