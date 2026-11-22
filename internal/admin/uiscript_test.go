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
		m := regexp.MustCompile(`(?ms)^(?:function ` + n + `\(.*?^}|const ` + n + ` = \{.*?^};|const ` + n + ` = [^{\n][^\n]*;)$`).Find(src)
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
// "?focus=" in the address opens Settings › Admin at that setting. The link
// must name a setting that is there.
func TestUIQueryRecordsLinkOpensTheSetting(t *testing.T) {
	got := runJS(t, []string{"focusParam", "QUERY_RECORDS_LINK"}, `
console.log(QUERY_RECORDS_LINK.split("?")[0], focusParam(QUERY_RECORDS_LINK));
console.log(focusParam("#/settings/admin"), focusParam("#/settings/admin?focus=a.b&x=1"));
`)
	if want := "#/settings/admin log.query_days\nnull a.b"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	src, err := os.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?s)admin: \{.*?title: "Query records", fields: \[\s*\{ key: "log\.query_days", `).Match(src) {
		t.Fatal("log.query_days is not the first setting of Settings › Admin › Query records")
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
