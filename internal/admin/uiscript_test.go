package admin

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// runJS runs script after the named top-level functions and constants of
// app.js, with Node, and returns what it prints; skipped without Node.
func runJS(t *testing.T, names []string, script string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, n := range names {
		m := regexp.MustCompile(`(?ms)^(?:function ` + n + `\(.*?^}|const ` + n + ` = \{.*?^};|const ` + n + ` = \[\n.*?^\];|const ` + n + ` = [^{\n][^\n]*;)$`).Find(src)
		if m == nil {
			t.Fatalf("%s not found in app.js", n)
		}
		b.Write(m)
		b.WriteString("\n")
	}
	out, err := exec.Command(node, "-e", b.String()+script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// The newest point of a chart covers only the seconds since the last
// sample; divided by a full step, it drew a drop at the end of every chart.
func TestUIChartRatesUseEachPointsOwnSpan(t *testing.T) {
	got := runJS(t, []string{"sum", "timed", "bucket"}, `
const from = "2026-11-19T10:00:00Z";
const pt = (min, sec, q) => ({ t: new Date(Date.UTC(2026, 10, 19, 10, min, sec)).toISOString(), queries: q, latency: { p50_ms: 1, p95_ms: 2 } });
// 60 q/s for three full minutes, then 40 s of the same rate still filling
let ser = timed([pt(1, 0, 3600), pt(2, 0, 3600), pt(3, 0, 3600), pt(3, 40, 2400)], from);
console.log(ser.map((p) => p.queries / p.secs).join(" "));
// a newest point of 5 s is left out of the chart
console.log(timed([pt(1, 0, 3600), pt(2, 0, 3600), pt(2, 5, 300)], from).length);
// merged points keep their seconds
const many = timed(Array.from({ length: 10 }, (_, i) => pt(i + 1, 0, 600)), from);
console.log(bucket(many, 5).map((p) => p.queries / p.secs).join(" "));
`)
	if want := "60 60 60 60\n2\n10 10 10 10 10"; got != want {
		t.Fatalf("rates:\n%s\nwant\n%s", got, want)
	}
}

// The dashboard's percentages never round a share to 100% or 0% unless it
// is: 99.6% of queries over DoH3 next to 0.4% over UDP read as 100% + 0.4%.
// Runs the formatter from app.js with Node, when it is installed.
func TestUIPercentNeverRoundsToWhole(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*pct: (\(r\) => .*),$`).FindSubmatch(src)
	if m == nil {
		t.Fatal("fmt.pct not found in app.js")
	}
	script := "const pct = " + string(m[1]) + ";\nconsole.log([0, 0.0004, 0.004, 0.3, 0.996, 0.9996, 1].map(pct).join(' '));"
	out, err := exec.Command(node, "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got, want := strings.TrimSpace(string(out)), "0% 0.1% 0.4% 30.0% 99.6% 99.9% 100%"; got != want {
		t.Fatalf("pct: %s, want %s", got, want)
	}
}

// Large numbers switch unit where they would round up: 999,960 is "1.00M",
// not "1000.0k", and 999,999 queries a second "1.0M", not "1000K".
func TestUINumberUnitsAtTheirBoundaries(t *testing.T) {
	got := runJS(t, []string{"fmt"}, `
console.log([9999, 12345, 999949, 999960, 999995000].map((n) => fmt.short(n)).join(" "));
console.log([9.94, 999.4, 999.6, 9949, 9951, 999499, 999999, 9949999, 9950001].map((n) => fmt.rate(n)).join(" "));
`)
	if want := "9,999 12.3k 999.9k 1.00M 1.00B\n9.9 999 1.0K 9.9K 10K 999K 1.0M 9.9M 10M"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// The query log, when off, links straight to the query records setting:
// "?focus=" in the address opens Settings › Logs & statistics at that
// setting. The link must name a setting that is there.
func TestUIQueryRecordsLinkOpensTheSetting(t *testing.T) {
	got := runJS(t, []string{"focusParam", "QUERY_RECORDS_LINK"}, `
console.log(QUERY_RECORDS_LINK.split("?")[0], focusParam(QUERY_RECORDS_LINK));
console.log(focusParam("#/settings/admin"), focusParam("#/settings/admin?focus=a.b&x=1"));
`)
	if want := "#/settings/logs log.query_days\nnull a.b"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	src, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?s)logs: \{.*?title: "Query records", fields: \[\s*\{ key: "log\.query_days", `).Match(src) {
		t.Fatal("log.query_days is not the first setting of Settings › Logs & statistics › Query records")
	}
}

// How long query records are kept is picked from 7, 30, 90 and 365 days
// (or off); any other number of days shows as "Custom", with the number.
func TestUIQueryDaysChoices(t *testing.T) {
	got := runJS(t, []string{"daysChoice", "QUERY_DAYS"}, `
console.log(QUERY_DAYS.map(([d]) => d).join(" "));
console.log([0, 7, 30, 90, 365, 14, 3650].map((d) => daysChoice(d, QUERY_DAYS)).join(" "));
`)
	if want := "0 7 30 90 365\n0 7 30 90 365 custom custom"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// Links that name a setting open the settings page at it ("?focus="), not at
// the top of a long page; each must name a setting, or a card marked with
// data-focus, that is there.
func TestUIFocusLinksNameASetting(t *testing.T) {
	src, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, m := range regexp.MustCompile(`\?focus=([A-Za-z0-9_.]+)`).FindAllSubmatch(src, -1) {
		k := string(m[1])
		found[k] = true
		if !strings.Contains(string(src), `key: "`+k+`"`) && !strings.Contains(string(src), `"data-focus": "`+k+`"`) {
			t.Errorf("?focus=%s: no such setting or card", k)
		}
	}
	for _, k := range []string{
		"log.query_days",    // query log, and the query records page
		"dnstap.target",     // the dnstap notice
		"recursion.enabled", // DNSSEC page, when forwarding
		"recursion.dnssec",  // DNSSEC page, when checking is off
		"nod.enabled",       // New domains
		"server.listen",     // DNS not served yet; setup guide
		"tls.domains",       // the overview's certificate card
		"upstream.primary",  // Upstreams page
		"account",           // the account menu: Password, two-step verification
	} {
		if !found[k] {
			t.Errorf("no link opens the settings at %s", k)
		}
	}
}

// Each page has its own browser tab title, for tabs, history and
// bookmarks, and for screen readers announcing the page.
func TestUIPageTitles(t *testing.T) {
	got := runJS(t, []string{"NAV", "pageTitle"}, `
console.log(["overview", "querylog", "settings/encryption", "settings/logs", "settings/admin", "tools/trace", "dnssec", "nodes", "locality", "nosuch"].map(pageTitle).join("|"));
`)
	want := "Overview · DNSNova|Query log · DNSNova|Addresses & encryption · DNSNova|Logs & statistics · DNSNova|Admin · DNSNova|Trace a lookup · DNSNova|DNSSEC · DNSNova|Nodes · DNSNova|Private locality · DNSNova|Overview · DNSNova"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// Plain DNS addresses are set on the same page as the encrypted protocols,
// so the page is named for both; Discovery (DDR), which tells clients the
// encrypted addresses, is set there too, not among DNS & upstreams. What is
// kept and where it is sent (statistics, query records, dnstap) has a page
// of its own, Logs & statistics; Admin keeps the admin page and the account.
func TestUISettingsPlacement(t *testing.T) {
	src, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	page := func(id string) string {
		m := regexp.MustCompile(`(?ms)^  ` + id + `: \{\n.*?^  \},?$`).FindString(s)
		if m == "" {
			t.Fatalf("settings page %s not found", id)
		}
		return m
	}
	enc, dns, admin, logs := page("encryption"), page("dns"), page("admin"), page("logs")
	if !strings.Contains(enc, `title: "Addresses & encryption"`) || !strings.Contains(enc, `key: "server.listen"`) {
		t.Error("plain DNS addresses are not on a page named Addresses & encryption")
	}
	if !strings.Contains(enc, `key: "ddr.enabled"`) || strings.Contains(dns, `key: "ddr.enabled"`) {
		t.Error("Discovery (DDR) is not with the encrypted protocols")
	}
	for _, k := range []string{"stats.retention", "log.query_days", "log.query_full_ip", "dnstap.target"} {
		if !strings.Contains(logs, `key: "`+k+`"`) || strings.Contains(admin, `key: "`+k+`"`) {
			t.Errorf("%s is not on Logs & statistics", k)
		}
	}
	if !strings.Contains(logs, `title: "Logs & statistics"`) || !strings.Contains(s, `["Logs & statistics", "settings/logs", `) || !strings.Contains(s, `"settings/logs": (m) => settingsPage(m, "logs")`) {
		t.Error("Logs & statistics is not a settings page in the menu")
	}
	if strings.Contains(admin, `"Clear statistics"`) {
		t.Error("Admin still offers Clear statistics")
	}
	if strings.Contains(admin, `title: "Access"`) {
		t.Error(`Admin has a section named "Access", next to the Access & limits page`)
	}
	if strings.Contains(s, `"Encrypted DNS ›`) || strings.Contains(s, `Settings › Encrypted DNS`) {
		t.Error("a reference to the old page name is left")
	}
}
