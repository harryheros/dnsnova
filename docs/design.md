# Interface design

The rules every DNSNova screen follows: the admin interface, the setup
wizard, and the public status page. The values live in one place,
`internal/admin/ui/app.css`; this page explains them. A new screen uses
these tokens and components rather than its own.

## Principles

1. **Facts, not decoration.** Numbers are shown as they are, with their unit
   and period. No judgments such as "excellent", no animations that carry
   no information, no glow, no gradients.
2. **The important thing first.** Each page leads with what most people come
   for; details sit behind a link or lower on the page.
3. **One product.** Every screen uses the same colors, type, spacing and
   components, in both appearances.
4. **Nothing from elsewhere.** No web fonts, scripts, images or analytics
   from other sites. The Content Security Policy enforces it.
5. **Readable by everyone.** Text meets WCAG AA contrast in both
   appearances, everything works from the keyboard, state is never shown by
   color alone (a label or icon goes with it).

## Appearance

Light is the default. Dark and Auto (follow the system) are chosen in the
sidebar and remembered in the browser. Dark is a blue-grey, not black:
cards are slightly lighter than the page, text is a soft white, and the
accent stays blue.

## Color tokens

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--bg` | `#f4f6fa` | `#121821` | Page background, inputs |
| `--surface` | `#ffffff` | `#19202b` | Cards, sidebar |
| `--raised` | `#eef1f6` | `#232c39` | Hover, empty bar tracks |
| `--border` | `#e2e6ed` | `#2c3644` | Card borders, dividers, grid lines |
| `--text` | `#2d3440` | `#dfe5ec` | Body text (a deep grey, not black) |
| `--muted` | `#636c7b` | `#9aa6b6` | Labels, help, secondary text |
| `--accent` | `#3769b5` | `#78aef5` | Links, selected navigation, chart median |
| `--soft` | `#edf3fc` | `#1c3150` | Selected item background |
| `--go` | `#2b8443` | `#2b8443` | Main action buttons and switches that are on (white text) |
| `--ok` | `#1f7a3e` | `#5cc27a` | Healthy |
| `--warn` | `#a15f0e` | `#f0ad4e` | Slow, attention needed |
| `--err` | `#c0392b` | `#f2726b` | Failing, errors only |
| `--idle` | `#626c7b` | `#8b97a8` | Standing by, inactive |
| `--c1` `--c2` `--c3` | blue, purple, orange | lighter versions | Marks of the three key figures |

Colors have jobs, as in AdGuard Home: green for the main action on a page
(sign in, apply, continue) and switches that are on, blue for links and
where you are, green/amber/red/grey for state, and one color mark per key
figure. Red is for errors only.

## Type

- Text: the system font (`system-ui`: SF on Apple, Segoe UI on Windows,
  Roboto on Android). 14 px body, 1.45 line height.
- Numbers, addresses, domains and code: the system monospace font, with
  tabular figures so columns line up. The hero number is the exception: it
  uses the text font with tabular figures, because at 52 px monospace
  spreads short values such as "<0.1" apart.
- Sizes: 52 px hero number, 26 px key figures, 22 px page title, 15 px card
  title, 14 px body, 13 px dense text, 12 px labels and notes, 10.5 px group
  titles (upper case, spaced).
- Weights: 600 for titles and figures, 500 for labels, 400 for text.

## Space and shape

- Spacing comes in steps of 4 px: 4, 8, 12, 16, 20, 24.
- Radius: 6 px for small controls and nav items, 8 px for buttons, inputs
  and choices, 12 px for cards.
- Cards have a 1 px border and a very light shadow; floating layers (the
  chart readout, search results) a stronger one.
- Controls are at least 32 px high (38 px for main buttons and inputs).
- Motion: color changes take 150 ms. Nothing else moves.

## Icons

Line icons on a 24 px grid with a 2 px stroke and round ends, in the style
of [Lucide](https://lucide.dev) (ISC license, notice in `app.js`), drawn at
15–16 px. Navigation items, event types and nothing else: icons never
replace a label.

## Components

- **Overview grid**: a 12-column grid. Cards in a row are the same height,
  and every list shows a fixed number of rows (six); rows without data are
  drawn as faint placeholder bars. A footer line closes each card. The page
  looks the same, and as orderly, with no data as with a lot. Four cards a
  row on wide screens, two below 1440 px, one on phones.
- **Sidebar**: brand, search (`/`), groups Status, Settings and Tools, then
  appearance and the server line. On narrow screens it folds into a Menu
  button.
- **Summary**: a status bar (upstream health, open protocols, version and
  uptime), then the median response as the hero and three key figures, each
  with a label above and a note below.
- **Chart**: median as a 2 px accent line over a light area, the 95th
  percentile dashed and muted. The pointer shows time, both values and the
  query count. With too little data, a dashed frame says why.
- **Health**: Healthy (green), Slow (amber), Failing (red), Standby (grey),
  always with the word.
- **Lists**: rank in muted monospace, name in monospace, count right
  aligned, a 4 px bar below.
- **Events**: an icon for the kind, repeated events folded into one with a
  count, time right aligned.
- **Settings**: label and help on the left, control on the right; changes
  are listed in the review panel before anything is applied.
- **Public status page**: the same tokens and cards on a centered page,
  no sidebar. A hero with the state, the domain and the check; a tabbed
  setup guide that opens on the visitor's platform; addresses with copy
  buttons; what the server keeps. Numbered steps use small accent circles.
- **Toasts**: short confirmations at the bottom right; errors stay longer.

## Writing

Plain, short English. Say what something does and what happens, not how
good it is. Units always: ms, queries, minutes. Times in 24-hour format.
