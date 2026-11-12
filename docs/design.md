# Interface design

The rules every DNSNova screen follows: the admin interface, the setup
wizard, and the public status page. The values live in one place,
`internal/admin/ui/app.css`; this page explains them. A new screen uses
these tokens and components rather than its own.

The reference for layout and visual weight is the overview mockup of
November 2026 ("Deep Ocean"): a dark brand rail on the left, a brand head,
four key figures, a large traffic chart beside a smaller topology panel,
then three lists. New pages keep that rhythm.

## Positioning

DNSNova should look like infrastructure people trust with a network: a
mature, professional DNS platform, not a consumer blocker. The interface
says so through restraint and precision, not decoration.

- **Presence in the brand, clarity in the work.** The mark, the wordmark
  and the rail carry the weight and the light. Everything people read for
  hours (figures, charts, tables, settings) is flat, high-contrast and
  calm: operators watch this screen for long shifts, so clarity comes
  before effect.
- **Dense but calm.** Many facts on one screen, each in a fixed place, with
  a clear order of importance.
- **Built for more than one node.** DNSNova runs as one server today and is
  heading toward managing several. Screens are laid out so a second node is
  an extra row or an extra column, not a redesign (see *Toward clusters*).

## Principles

1. **Facts first.** Numbers are shown as they are, with their unit and
   period. No judgments such as "excellent". A comparison (↑ 3.5%) is only
   shown when the previous period was really measured.
2. **Light belongs to the brand.** Glow is used only on the mark and the
   wordmark (and the faint swell at the foot of the rail). Gradients are
   allowed on the brand, the selected item (navigation, segmented controls,
   primary buttons, switches that are on), the area under a chart line and
   the bars in lists. Nothing that holds data glows: no halos on lines,
   icons, dots or bars. The light appearance drops the glow entirely.
3. **The important thing first.** Each page leads with what most people come
   for; details sit lower or behind a link.
4. **One product.** Every screen uses the same tokens, type and components,
   in both appearances.
5. **Nothing from elsewhere.** No web fonts, scripts, images or analytics
   from other sites. The Content Security Policy enforces it.
6. **Readable by everyone.** Text meets WCAG AA contrast in both
   appearances, everything works from the keyboard, state is never shown by
   color alone (a word goes with it).
7. **Nothing moves on its own.** No continuous animation anywhere: motion
   in the corner of the eye tires people who watch the screen all day.
   Color changes take 150 ms; values update in place.

## Appearance

Dark ("Deep Ocean") is the default; Light and Auto are chosen in the account
menu and remembered in the browser. The brand rail stays dark in both: it is
the product's signature. The page background is a deep navy with two very
soft light pools (top right, bottom right); cards are translucent navy with
a 1 px blue-tinted border.

## Color tokens

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--bg` | `#040a18` | `#eef3fb` | Page |
| `--surface`, `--surface-2` | navy, 78% | white | Cards (a top-to-bottom blend of the two) |
| `--solid` | `#0b1833` | white | Popovers, tooltips, inputs |
| `--border` | blue 15% | `#dbe4f2` | Card borders |
| `--hairline` | blue 8% | `#e9eff8` | Row dividers, grid lines |
| `--text` | `#e8effc` | `#13203a` | Body text |
| `--muted`, `--faint` | `#8ea2c4`, `#5e7194` | `#5a6a86`, `#8a98b1` | Labels, help; group titles |
| `--accent` | `#4b93ff` | `#1f6feb` | Links, selection, the main series |
| `--accent-2` | `#39d0f2` | `#0ea5c6` | Second series, live values, protocols |
| `--grad` | blue → deep blue | same | Selected item, primary button, switch on |
| `--grad-bar` | cyan → blue | same | Bars in lists |
| `--ok` `--warn` `--err` `--idle` | green, amber, red, grey | darker versions | State only |
| `--c1`…`--c4` | blue, cyan, green, violet | | One color per key figure or answer source |

Colors have jobs. Blue is the brand and "where you are"; cyan is "live";
green, amber, red and grey are state, and red is for errors only. Main
actions are blue (not green): green means *healthy*.

## Brand

- **Mark**: a trident on a 100-unit grid: three barbed prongs, a crescent,
  a guard and a diamond pommel. Filled, not outlined, with clean sides (no
  fins). Chrome at the tips going to deep blue at the grip, with a light
  left half and a shaded right half for the ridge (`--mk0`…`--mk5`). On
  dark brand surfaces it carries a soft blue glow. `logo.svg` is the
  favicon on a navy tile.
- **Wordmark**: "DNSN" in capitals and "OVA" in small capitals (76% of the
  cap height, one weight heavier so the strokes match), set in **Exo 2
  ExtraBold** with the font's own kerning. Exo 2 is by Natanael Gama under
  the SIL Open Font License 1.1 (github.com/google/fonts). The letters are
  stored as outlines in `app.js` and `status.js`, so no font is loaded and
  the wordmark is identical on every system. Brushed chrome with a dark
  edge on dark backgrounds, solid navy on light (`--wm0`…`--wm4`). Size it
  with `font-size`; its height is 0.8 em. To redraw it, set the text in
  Exo 2 (wght 800, small capitals wght 900) and export the outlines with
  the cap height scaled to 100 and the baseline at 100.
- **Tagline**: *Rule the Domain Ocean*, italic, light weight, muted.
- The full lock-up (mark, wordmark, tagline) appears in the rail, on the
  sign-in page and as the overview's head. Elsewhere the compact brand
  (mark + wordmark) is used.

## Type

- System fonts only: `system-ui` for text and figures (tabular numbers),
  the system monospace for domains, addresses, versions and code.
- Sizes: 48 px brand head, 34 px key figures, 24 px page titles, 17 px card
  titles, 14 px body, 13 px dense rows, 12 px notes, 10.5 px group titles
  (upper case, spaced).

## Space and shape

- Spacing in steps of 4 px; the overview grid gap is 18 px.
- Radius: 8 px small controls, 10 px buttons, inputs and navigation, 16 px
  cards. Pills are fully round.
- Controls are at least 32 px high (40 px for inputs, 44 px for the sign-in
  button).

## Icons

Line icons on a 24 px grid, 2 px stroke, round ends, in the style of
[Lucide](https://lucide.dev) (ISC license, notice in `app.js`). Navigation
at 19 px, card titles at 20 px, key figures at 46 px in the figure's
color. No glow on icons. Icons never replace a label.

## Layout

- **Shell**: the brand rail (256 px) with the lock-up, grouped navigation
  (Status, Settings, Tools) and the version at the foot; a sticky top bar
  with search (`/`), the system state ("System Online", or what is wrong)
  and the account menu (appearance, account, API docs, sign out). Below
  800 px the rail folds into a bar with a Menu button.
- **Overview grid**: 12 columns.
  1. Brand head with identity chips: domain and state, public or private,
     version and uptime.
  2. Four key figures (`s3`): queries per second, response time, cache hit
     rate, uptime. Each has an icon, value, unit, a delta when the previous
     period exists, a note, and a visual (sparkline, answer-source bar or
     protocol chips).
  3. DNS Traffic (`s8`): queries per second or response time, range 1h /
     24h / 7d (/ 30d), y and x axes, a readout under the pointer, a lit
     point at "now". Beside it Traffic Flow (`s4`).
  4. Top Domains, Upstream Servers (or Resolution with recursion), Recent
     Activity (`s4` each, five rows).
  5. Details (`s3` each): Not Found, Rejected, Certificate, Privacy.
  Below 1360 px figures go two per row and the chart and flow stack; below
  1000 px everything is one column; below 560 px figures are one per row.
- Every list has a fixed number of rows; missing rows are faint
  placeholders, so the page looks as orderly empty as full.

## Components

- **Key figure** (`kpiCard`): see above. Deltas: ↑/↓ with one decimal;
  green when the change is good (latency down), red when bad, cyan when
  neither (traffic). The previous period is read from the next longer
  range and only shown when it covers at least 80% of the period.
- **Traffic chart** (`trafficChart`): a crisp smooth line (Catmull-Rom,
  never below zero, no glow) over a vertical gradient, axes in round steps, the 95th
  percentile dashed in latency mode. With too little data a dashed frame
  says why.
- **Traffic Flow** (`flowCard`): clients by protocol (share of queries) →
  the node → upstreams or authoritative servers (health, latency, share).
  Link width follows the share; failing links are red, standby links
  dashed grey. The diagram is static. The legend counts healthy, standby, slow and failing.
- **Lists**: rank, name in monospace, gradient bar, count, share.
- **Upstream rows**: state dot, name and role, success rate, a latency
  trend sampled while the page is open, smoothed latency.
- **Activity**: a state dot, message, repeat count, time ago.
- **Settings**: label and help on the left, control on the right; changes
  are collected in the floating review panel before anything is applied.
- **Toasts**: bottom right, a state dot, errors stay longer.

## Toward clusters

The interface is shaped for the multi-node DNSNova so that the step is
additive. These are design commitments, not features of this release; none
of them is shown in the interface until it works.

| Area | Today | With several nodes |
| --- | --- | --- |
| Top bar state | this server | the fleet: "3 of 3 nodes online" |
| Identity chips | one domain | fleet name, node selector ("All nodes") |
| Key figures | this node | fleet totals, per-node breakdown on hover |
| Traffic Flow | one node in the middle column | the middle column lists nodes; links show load balance |
| Upstream Servers | this node's upstreams | per node, with a node filter |
| Navigation | Status, Settings, Tools | a **Nodes** page under Status (inventory, version, region, health); Settings gain a scope: fleet or node |
| Recent Activity | this node | events tagged with the node |

Diagnostics: **Trace a lookup** (Tools) shows a resolution step by step,
nested lookups indented, DNSSEC verdicts as state words with their dot;
the **DNSSEC** page (Status, only with recursion) lists failures with the
action that fixes each (trace, or stop validating the domain).

Done so far: the **Nodes** page (shown only on a node of a cluster) with
each node's state, region, settings version, anycast state, version and
certificate; configuration sync with per-node overrides; the settings pages
of a follower say where its settings come from. See docs/cluster.md.

Features worth planning for, in this order, each because a DNS operator
needs it, not to fill the screen:

1. **Nodes** page and node identity (name, region, role) in the API, with
   the overview's "1 node" chip linking to it.
2. **Configuration sync**: one configuration applied to several nodes with
   the existing preview / apply / history flow, per-node overrides shown as
   such.
3. **Fleet health**: per-node reachability, version drift, certificate
   expiry across nodes, shown in the top bar and on the Nodes page.
4. **Anycast / geography**: only when nodes carry a region, a map of node
   locations with health replaces nothing; it is added beside Traffic Flow.
5. **Alerts**: thresholds on the key figures (latency, failing upstreams,
   certificate days) delivered by webhook, listed in Recent Activity.

## Writing

Plain, short English. Say what something does and what happens, not how
good it is. Units always: ms, q/s, queries, minutes. Times in 24-hour
format. Title Case for card titles, sentence case everywhere else.
