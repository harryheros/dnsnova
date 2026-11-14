// DNSNova admin interface. Plain JavaScript, no framework and no build step:
// every screen is drawn from the admin API (docs/api.md), and the interface
// holds no privileges of its own. Text from the server is always inserted as
// text, never as HTML.

import { guides, tabs, filtered } from "./guides.js";

// ---------- small helpers ----------

const SVGNS = "http://www.w3.org/2000/svg";

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  add(el, kids);
  return el;
}

function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  setAttrs(el, attrs);
  add(el, kids);
  return el;
}

function setAttrs(el, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(el.style, v);
    else if (k === "class") el.setAttribute("class", v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}

function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

function put(el, ...kids) { add(el, kids); return el; }
function fill(el, ...kids) { el.replaceChildren(); add(el, kids); return el; }

// Line icons in the style of Lucide (https://lucide.dev), drawn on a 24px
// grid with a 2px stroke. Lucide is ISC licensed:
//   Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2022 as
//   part of Feather (MIT). All other copyright (c) for Lucide are held by
//   Lucide Contributors 2022. Permission to use, copy, modify, and/or
//   distribute this software for any purpose with or without fee is hereby
//   granted, provided that the above copyright notice and this permission
//   notice appear in all copies.
const LINE = {
  overview: [["rect", { x: 3, y: 3, width: 7, height: 9, rx: 1 }], ["rect", { x: 14, y: 3, width: 7, height: 5, rx: 1 }], ["rect", { x: 14, y: 12, width: 7, height: 9, rx: 1 }], ["rect", { x: 3, y: 16, width: 7, height: 5, rx: 1 }]],
  upstreams: [["rect", { x: 2, y: 2, width: 20, height: 8, rx: 2 }], ["rect", { x: 2, y: 14, width: 20, height: 8, rx: 2 }], ["path", { d: "M6 6h.01M6 18h.01" }]],
  querylog: [["path", { d: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" }]],
  dns: [["circle", { cx: 12, cy: 12, r: 10 }], ["path", { d: "M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20M2 12h20" }]],
  lock: [["rect", { x: 3, y: 11, width: 18, height: 11, rx: 2 }], ["path", { d: "M7 11V7a5 5 0 0 1 10 0v4" }]],
  shield: [["path", { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }]],
  bell: [["path", { d: "M10.268 21a2 2 0 0 0 3.464 0" }], ["path", { d: "M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326" }]],
  user: [["path", { d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" }], ["circle", { cx: 12, cy: 7, r: 4 }]],
  compare: [["path", { d: "M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4" }]],
  filter: [["path", { d: "M10 20a1 1 0 0 0 .553.895l2 1A1 1 0 0 0 14 21v-7a2 2 0 0 1 .517-1.341L21.74 4.67A1 1 0 0 0 21 3H3a1 1 0 0 0-.742 1.67l7.225 7.989A2 2 0 0 1 10 14z" }]],
  sliders: [["path", { d: "M20 7h-9M14 17H5" }], ["circle", { cx: 17, cy: 17, r: 3 }], ["circle", { cx: 7, cy: 7, r: 3 }]],
  power: [["path", { d: "M12 2v10M18.4 6.6a9 9 0 1 1-12.77.04" }]],
  alert: [["path", { d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3M12 9v4M12 17h.01" }]],
  info: [["circle", { cx: 12, cy: 12, r: 10 }], ["path", { d: "M12 16v-4M12 8h.01" }]],
  phone: [["rect", { x: 5, y: 2, width: 14, height: 20, rx: 2 }], ["path", { d: "M12 18h.01" }]],
  home: [["path", { d: "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z" }]],
  bolt: [["path", { d: "M13 2 4 14h7l-1 8 9-12h-7z" }]],
  shieldcheck: [["path", { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }], ["path", { d: "m9 12 2 2 4-4" }]],
  layers: [["path", { d: "m12 2 10 5-10 5L2 7z" }], ["path", { d: "m2 12 10 5 10-5M2 17l10 5 10-5" }]],
  bars: [["path", { d: "M5 21V14M10 21V9M15 21V12M20 21V4" }]],
  trophy: [["path", { d: "M8 21h8M12 17v4M7 4h10v5a5 5 0 0 1-10 0z" }], ["path", { d: "M7 6H4a3 3 0 0 0 3 4M17 6h3a3 3 0 0 1-3 4" }]],
  file: [["path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" }], ["path", { d: "M14 2v6h6M8 13h8M8 17h6" }]],
  network: [["circle", { cx: 12, cy: 5, r: 2.5 }], ["circle", { cx: 5, cy: 19, r: 2.5 }], ["circle", { cx: 19, cy: 19, r: 2.5 }], ["path", { d: "M12 7.5v4M12 11.5 6.5 17M12 11.5l5.5 5.5" }]],
  chevron: [["path", { d: "m6 9 6 6 6-6" }]],
  arrow: [["path", { d: "M5 12h14M13 6l6 6-6 6" }]],
  logout: [["path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" }]],
  book: [["path", { d: "M4 19.5V5a2 2 0 0 1 2-2h14v16H6.5A2.5 2.5 0 0 0 4 21.5zM4 19.5A2.5 2.5 0 0 1 6.5 17H20" }]],
};

// The DNSNova mark (docs/design.md, Brand): the metal-and-light drawing,
// mark.svg. The browser tab icon is a solid silhouette instead (logo.svg).
// The drawing leaves room for its glow, so it is set a little larger than a
// plain icon would be.
let markSeq = 0;
function stops(prefix, offsets) {
  return offsets.map((o, i) => s("stop", { offset: o, class: prefix + i }));
}
function brandMark(size = 28, glow = false) {
  return h("img", { src: "/assets/mark.svg", width: size, height: size, alt: "", "aria-hidden": "true", class: "mark" + (glow ? " glow" : ""), decoding: "async" });
}

// The wordmark: "DNSN" and small capitals "OVA" set in Exo 2 ExtraBold
// (SIL Open Font License 1.1, github.com/google/fonts) with its own kerning,
// stored as outlines so no font is loaded. Cap height 100, baseline 100.
const WORDMARK_PATH = "M49.9 -1.4Q62.2 -1.4 70.8 1Q79.4 3.5 84.7 9.3Q90 15.1 92.4 25Q94.8 34.9 94.8 50Q94.8 65.1 92.4 75Q90 84.9 84.7 90.7Q79.4 96.5 70.8 99Q62.2 101.4 49.9 101.4Q37.8 101.4 27.8 101Q17.7 100.6 8.7 100L19.9 80.4Q25.1 80.9 32.8 81.1Q40.4 81.3 49.9 81.3Q56.1 81.3 59.6 78.7Q63.2 76.1 64.6 69.3Q66.1 62.5 66.1 50Q66.1 37.5 64.6 30.7Q63.2 23.9 59.6 21.3Q56.1 18.7 49.9 18.7Q41 18.7 34.1 18.7Q27.2 18.7 20.9 18.7L8.7 0Q17.8 -0.6 27.8 -1Q37.7 -1.4 49.9 -1.4ZM35.9 0V100H8.7V0Z M203.7 0V90.4Q203.7 100 194.3 100H182.1Q177.7 100 175.6 98Q173.5 95.9 171.4 92L146.9 49.4Q145.1 45.8 143.4 41.6Q141.7 37.4 140.5 33.2H139.2Q139.8 37.4 140.1 41.8Q140.5 46.2 140.5 50.3V100H115.1V9.6Q115.1 0 124.7 0H136.7Q141.1 0 143.1 2Q145.1 4.1 147.4 8L170.9 49Q173 52.5 174.8 56.7Q176.7 60.9 178.5 65.5H179.8Q179.3 61 179 56.7Q178.8 52.3 178.8 48L178.6 0Z M262.7 -2Q270.4 -1.9 279.7 -1Q289 -0.1 297.7 2.6L295.9 20.3Q289.5 20.1 280.3 20Q271.1 19.9 262.3 19.9Q259 19.9 256.7 20.1Q254.5 20.3 253.1 20.9Q251.7 21.6 251.1 22.8Q250.6 24.1 250.6 26.2Q250.6 29.7 252.7 31.5Q254.8 33.3 260.1 35.2L278.8 42.2Q291 47 295.8 54Q300.7 61 300.7 72.2Q300.7 80.6 298.7 86.4Q296.6 92.2 292.1 95.5Q287.5 98.8 280 100.4Q272.6 102 261.6 102Q256.5 102 246.7 101.3Q236.9 100.6 224.6 97.5L226.2 78.4Q234.9 78.6 241.6 78.8Q248.4 79 253.4 79.1Q258.4 79.1 261.3 79.1Q266.2 79.1 268.8 78.6Q271.4 78.1 272.4 76.7Q273.4 75.4 273.4 72.8Q273.4 70.3 272.7 68.8Q272 67.4 270.2 66.4Q268.4 65.4 265.3 64.3L245.3 56.4Q233.4 51.4 228.5 44.6Q223.6 37.8 223.6 26.8Q223.6 18.1 225.8 12.6Q227.9 7.1 232.5 3.9Q237.1 0.7 244.6 -0.7Q252.1 -2 262.7 -2Z M408.4 0V90.4Q408.4 100 399 100H386.8Q382.5 100 380.4 98Q378.3 95.9 376.1 92L351.6 49.4Q349.9 45.8 348.1 41.6Q346.4 37.4 345.2 33.2H343.9Q344.5 37.4 344.9 41.8Q345.2 46.2 345.2 50.3V100H319.9V9.6Q319.9 0 329.4 0H341.5Q345.8 0 347.9 2Q349.9 4.1 352.2 8L375.7 49Q377.7 52.5 379.6 56.7Q381.5 60.9 383.2 65.5H384.5Q384.1 61 383.8 56.7Q383.5 52.3 383.5 48L383.4 0Z M462 22.5Q471.8 22.5 478.6 24.3Q485.4 26.1 489.5 30.5Q493.7 34.9 495.6 42.6Q497.5 50.2 497.5 62Q497.5 73.7 495.6 81.4Q493.7 89.1 489.5 93.5Q485.4 97.9 478.6 99.7Q471.8 101.5 462 101.5Q452.3 101.5 445.5 99.7Q438.8 97.9 434.6 93.5Q430.4 89.1 428.5 81.4Q426.7 73.7 426.7 62Q426.7 50.2 428.5 42.6Q430.4 34.9 434.6 30.5Q438.8 26.1 445.5 24.3Q452.3 22.5 462 22.5ZM462 40.2Q457.9 40.2 455.7 42Q453.5 43.7 452.6 48.5Q451.8 53.2 451.8 62Q451.8 70.8 452.6 75.5Q453.5 80.3 455.7 82Q457.9 83.8 462 83.8Q466.1 83.8 468.3 82Q470.5 80.3 471.4 75.5Q472.3 70.8 472.3 62Q472.3 53.2 471.4 48.5Q470.5 43.7 468.3 42Q466.1 40.2 462 40.2Z M578.5 24 560 93.6Q559.3 96.5 557.1 98.2Q554.9 100 551.8 100H530.9Q527.8 100 525.6 98.2Q523.4 96.5 522.7 93.6L504.2 24H528.8L538.6 73.5Q539 75.5 539.4 77.8Q539.7 80.1 540 82.2H542.7Q542.9 80.1 543.3 77.8Q543.7 75.5 544.1 73.5L553.9 24Z M627.1 24Q630 24 632.2 25.7Q634.4 27.3 635.1 30.2L654.9 100H630.5L619.1 50.5Q618.6 48.5 618.3 46.2Q618 43.9 617.7 41.8H614.8Q614.5 43.9 614.2 46.2Q613.9 48.5 613.4 50.5L602 100H577.6L597.4 30.2Q598.1 27.3 600.3 25.7Q602.5 24 605.4 24ZM636.5 66.8V83.6H596V66.8Z";
const WORDMARK_WIDTH = 653.9;
function wordmark(cls = "") {
  const id = "dnw" + ++markSeq;
  return s("svg", { class: "wordmark " + cls, viewBox: `-4 -4 ${WORDMARK_WIDTH + 8} 108`, role: "img", "aria-label": "DNSNova" },
    s("defs", null, s("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 100, gradientUnits: "userSpaceOnUse" }, stops("w", [0, 0.44, 0.5, 0.56, 1]))),
    s("path", { d: WORDMARK_PATH, fill: `url(#${id})`, class: "wm-edge" }));
}
const TAGLINE = "Rule the Domain Ocean";

function line(name, size = 16) {
  return s("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ic" },
    (LINE[name] || LINE.info).map(([tag, a]) => s(tag, a)));
}

const icon = {
  logo: (size = 24) => brandMark(size),
  sun: () => s("svg", { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "aria-hidden": "true" },
    s("circle", { cx: 12, cy: 12, r: 4 }), s("path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" })),
  moon: () => s("svg", { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linejoin": "round", "aria-hidden": "true" },
    s("path", { d: "M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11z" })),
  auto: () => s("svg", { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "aria-hidden": "true" },
    s("circle", { cx: 12, cy: 12, r: 8.5 }), s("path", { d: "M12 3.5a8.5 8.5 0 0 1 0 17z", fill: "currentColor", stroke: "none" })),
  search: () => s("svg", { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "aria-hidden": "true" },
    s("circle", { cx: 11, cy: 11, r: 7 }), s("path", { d: "M20 20l-3.5-3.5" })),
};

const fmt = {
  int: (n) => (n ?? 0).toLocaleString("en-US"),
  short(n) {
    n = n ?? 0;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (n >= 1e4) return (n / 1e3).toFixed(1) + "k";
    return fmt.int(n);
  },
  ms(v) {
    if (!v) return "–";
    if (v < 0.1) return "<0.1";
    if (v < 10) return v.toFixed(1);
    return Math.round(v).toString();
  },
  rate(n) {
    n = n ?? 0;
    if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + "K";
    if (n >= 10) return Math.round(n).toString();
    return n ? n.toFixed(1) : "0";
  },
  pct: (r) => (r * 100).toFixed(r >= 0.995 || r === 0 ? 0 : 1) + "%",
  ago(t) {
    if (!t) return "never";
    const d = (Date.now() - new Date(t).getTime()) / 1000;
    if (d < 60) return "just now";
    if (d < 3600) return Math.floor(d / 60) + " min ago";
    if (d < 86400) return Math.floor(d / 3600) + " h ago";
    return Math.floor(d / 86400) + " days ago";
  },
  time(t, withDate) {
    const d = new Date(t);
    const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
    if (!withDate) return hm;
    return d.toLocaleDateString([], { month: "short", day: "numeric" }) + (withDate === "full" ? " " + hm : "");
  },
  uptime(sec) {
    const d = Math.floor(sec / 86400), hr = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return d ? `${d}d ${hr}h` : hr ? `${hr}h ${m}m` : `${m}m`;
  },
  value(v) {
    if (Array.isArray(v)) return v.length ? v.join(", ") : "(none)";
    if (v === true) return "on";
    if (v === false) return "off";
    if (v === "") return "(empty)";
    return String(v);
  },
};

function toast(msg, kind) {
  const t = h("div", { class: "toast" + (kind === "err" ? " err" : "") }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), kind === "err" ? 7000 : 3500);
}

// ---------- API ----------

const state = { session: null, status: null, timer: null, config: null };

class APIError extends Error {
  constructor(status, data) {
    super((data && data.error) || `request failed (${status})`);
    this.status = status;
    this.data = data || {};
  }
}

async function api(method, path, body) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  if (method !== "GET" && state.session) opt.headers["X-CSRF-Token"] = state.session.csrf;
  let r;
  try {
    r = await fetch("/api/v1" + path, opt);
  } catch (e) {
    throw new APIError(0, { error: "DNSNova is not reachable. Is it running?" });
  }
  let data = null;
  if (r.status !== 204) {
    try { data = await r.json(); } catch (e) { data = null; }
  }
  if (r.status === 401 && state.session && !path.startsWith("/login")) {
    state.session = null;
    showLogin("Your session ended. Sign in again.");
    throw new APIError(401, data);
  }
  if (!r.ok) throw new APIError(r.status, data);
  return data;
}

function copy(text) {
  navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => toast("Could not copy", "err"));
}

// ---------- boot ----------

const app = document.getElementById("app");

function mount(...nodes) {
  stopTimer();
  fill(app, ...nodes);
}

function stopTimer() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
}

async function boot() {
  try {
    const st = await api("GET", "/setup");
    if (st.needed) return showWizard(setupCodeFromURL(), st.code_required);
    try {
      state.session = await api("GET", "/session");
    } catch (e) {
      return showLogin();
    }
    showApp();
  } catch (e) {
    mount(h("div", { class: "signpage" }, h("div", { class: "center" }, h("div", { class: "signin plain" }, brandBig(), h("p", { class: "notice err" }, e.message)))));
  }
}

function setupCodeFromURL() {
  const m = /setup=([A-Za-z0-9-]{8,40})/.exec(location.hash + location.search);
  if (m) history.replaceState(null, "", location.pathname); // keep the code out of history
  return m ? m[1] : "";
}

function brandBig() {
  return h("div", { class: "signhero" }, brandMark(104, true), wordmark(), h("div", { class: "tagline" }, TAGLINE));
}

function appearance() {
  const pref = window.dnsnovaTheme.get();
  const btn = (id, label, ic) => h("button", {
    type: "button", "aria-pressed": String(pref === id), title: label + " appearance",
    onclick: () => { window.dnsnovaTheme.set(id); wrap.replaceWith(appearance()); },
  }, ic(), label);
  const wrap = h("div", { class: "seg appearance", role: "group", "aria-label": "Appearance" },
    btn("light", "Light", icon.sun), btn("dark", "Dark", icon.moon), btn("auto", "Auto", icon.auto));
  return wrap;
}

// ---------- sign in ----------

function showLogin(note) {
  let needCode = false;
  const err = h("p", { class: "err small", role: "alert" });
  const user = h("input", { type: "text", name: "username", autocomplete: "username", placeholder: "Enter user name", required: true });
  const pass = h("input", { type: "password", name: "password", autocomplete: "current-password", placeholder: "Enter password", required: true });
  const code = h("input", { type: "text", name: "totp", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]*" });
  const codeRow = h("label", { hidden: true }, "Code from your authenticator app", code);
  const submit = h("button", { type: "submit", class: "btn primary" }, "Sign in");
  const form = h("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      submit.disabled = true;
      try {
        state.session = await api("POST", "/login", { username: user.value, password: pass.value, totp: needCode ? code.value : "" });
        showApp();
      } catch (e) {
        if (e.data.totp_required) {
          needCode = true;
          codeRow.hidden = false;
          code.focus();
          if (code.value) err.textContent = e.message;
        } else {
          err.textContent = e.message;
        }
      } finally {
        submit.disabled = false;
      }
    },
  },
    h("label", null, "User name", user),
    h("label", null, "Password", pass),
    codeRow, err, submit);
  const insecure = location.protocol !== "https:" && !/^(localhost|127\.|\[::1\])/.test(location.host);
  const help = h("p", { class: "notice small", hidden: true },
    "On the server, as root, run ", h("code", null, "dnsnova -reset-admin"),
    ". DNSNova restarts and this page offers to create the administrator again. Your settings are kept.");
  mount(h("div", { class: "signpage" },
    h("main", { class: "center" }, h("div", { class: "signin plain" },
      brandBig(),
      h("div", { class: "card" }, note ? h("p", { class: "small muted", style: { margin: 0, textAlign: "center" } }, note) : null, form),
      h("div", { class: "forgot" }, h("button", { type: "button", onclick: () => { help.hidden = !help.hidden; } }, "Forgot password?")),
      help,
      insecure ? h("p", { class: "foot" }, "Not encrypted until a domain is set up.") : null)),
    signFooter()));
  user.focus();
}

const PROJECT = "https://github.com/harryheros/dnsnova";

// signFooter: links, and the appearance as three icons, as on the sign-in
// page of AdGuard Home.
// themeIcons: the appearance as three small icon buttons.
function themeIcons() {
  const seg = h("div", { class: "iconseg", role: "group", "aria-label": "Appearance" });
  const draw = () => fill(seg, ...[["auto", "Follow the system", icon.auto], ["dark", "Dark", icon.moon], ["light", "Light", icon.sun]].map(([id, label, ic]) =>
    h("button", { type: "button", title: label, "aria-label": label, "aria-pressed": String(window.dnsnovaTheme.get() === id), onclick: () => { window.dnsnovaTheme.set(id); draw(); } }, ic())));
  draw();
  return seg;
}

function signFooter() {
  const seg = themeIcons();
  return h("footer", { class: "signfoot" }, h("div", { class: "inner" },
    h("nav", { class: "links", "aria-label": "About DNSNova" },
      h("a", { href: PROJECT, rel: "noopener noreferrer", target: "_blank" }, "Homepage"),
      h("a", { href: PROJECT + "/blob/main/PRIVACY.md", rel: "noopener noreferrer", target: "_blank" }, "Privacy"),
      h("a", { class: "outline", href: PROJECT + "/issues", rel: "noopener noreferrer", target: "_blank" }, "Report an issue")),
    seg,
    h("div", { class: "copy" }, "DNSNova · free software under the AGPL-3.0")));
}

// ---------- setup wizard ----------

const WIZ_STEPS = ["Administrator", "Addresses", "Resolution", "Encrypted DNS", "Filtering", "Review"];

async function showWizard(code, codeRequired) {
  const w = { step: 0, code, codeRequired, cfg: null, hash: "", values: {}, addrs: [], clientIP: "" };
  const render = () => {
    const body = h("section", { class: "card wizbody", "aria-labelledby": "step-h" });
    const steps = h("ol", { class: "steps", "aria-label": "Steps" }, WIZ_STEPS.map((t, i) =>
      h("li", { class: i < w.step ? "done" : "", "aria-current": i === w.step ? "step" : null },
        h("span", { class: "n" }, i < w.step ? "✓" : String(i + 1)), h("span", { class: "t" }, t))));
    mount(h("main", { class: "wizard" }, h("div", { class: "inner" },
      h("div", { class: "wizhead" }, h("div", { class: "brand" }, brandMark(40, true), wordmark(), h("span", { class: "sub" }, "Setup")), themeIcons()),
      h("div", { class: "row" }, steps, body))));
    WIZ_VIEWS[w.step](w, body, render);
  };
  render();
}

function wizHead(w, title, desc) {
  return h("div", null,
    h("div", { class: "small muted mono" }, `Step ${w.step + 1} of ${WIZ_STEPS.length}`),
    h("h1", { id: "step-h", style: { margin: "4px 0 2px" } }, title),
    desc ? h("p", { class: "muted", style: { margin: 0 } }, desc) : null);
}

function wizNav(w, render, next, nextLabel = "Next") {
  const err = h("p", { class: "err small", role: "alert" });
  const nb = h("button", { type: "button", class: "btn primary" }, nextLabel);
  nb.addEventListener("click", async () => {
    err.textContent = "";
    nb.disabled = true;
    try {
      if ((await next()) !== false) { w.step++; render(); }
    } catch (e) {
      err.textContent = e.message;
    } finally {
      nb.disabled = false;
    }
  });
  return [err, h("div", { class: "wiznav" },
    w.step > 1 ? h("button", { type: "button", class: "btn", onclick: () => { w.step--; render(); } }, "Back") : h("span"),
    nb)];
}

async function wizLoad(w) {
  const [cfg, addrs] = await Promise.all([api("GET", "/config"), api("GET", "/system/addresses")]);
  w.hash = cfg.hash;
  w.cfg = Object.fromEntries(cfg.settings.map((x) => [x.key, x.value]));
  w.values = { ...w.cfg };
  w.addrs = addrs.addresses;
}

const hostOf = (a) => { const i = a.lastIndexOf(":"); return a.slice(0, i).replace(/^\[|\]$/g, ""); };
const withPort = (ip, port) => (ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);
// the networks a home or office server answers in private mode
const PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"];
const isAllAddr = (a) => /^(:|0\.0\.0\.0:|\[::\]:)/.test(a);
const isLocalAddr = (a) => /^(127\.|\[::1\]:|localhost:)/.test(a);
// encryptedListen puts DoT, DoQ and DoH on the plain DNS addresses; when
// plain DNS stays on this machine (or listens everywhere), on all addresses.
const encryptedListen = (plain) => {
  let hosts = (plain || []).filter((a) => !isLocalAddr(a)).map(hostOf);
  if (!hosts.length) hosts = [""];
  return {
    "dot.listen": hosts.map((x) => withPort(x, 853)), "doq.listen": hosts.map((x) => withPort(x, 853)),
    "doh.https_listen": hosts.map((x) => withPort(x, 443)),
  };
};

const WIZ_VIEWS = [
  // 0: administrator
  (w, body, render) => {
    const codeIn = h("input", { type: "text", class: "mono", value: w.code, autocomplete: "off", spellcheck: "false" });
    const user = h("input", { type: "text", value: "admin", autocomplete: "username" });
    const pass = h("input", { type: "password", autocomplete: "new-password" });
    const pass2 = h("input", { type: "password", autocomplete: "new-password" });
    const port = h("input", { type: "number", min: 1, max: 65535, value: location.port || (location.protocol === "https:" ? 443 : 80), inputmode: "numeric" });
    port.style.maxWidth = "140px";
    const portRow = h("label", { class: "block" }, "Port", port);
    const access = h("div", { class: "choices", role: "radiogroup", "aria-label": "Who can open this web interface" });
    const drawAccess = () => fill(access, ...[
      [false, "From the network", "Open it from other computers and phones with your password: directly on your home or office network, or over HTTPS for a server on the internet, once a domain's certificate is ready."],
      [true, "Only through an SSH tunnel", "More secure on a server on the internet. You will need: ssh -L port:127.0.0.1:port user@server"],
    ].map(([local, t, d]) => h("button", {
      type: "button", class: "choice", role: "radio", "aria-checked": String(!!w.adminLocal === local),
      onclick: () => { w.adminLocal = local; drawAccess(); },
    }, h("strong", null, t), h("span", null, d))));
    w.adminLocal = /^(127\.|\[::1\]|localhost)/.test(location.hostname);
    drawAccess();
    put(body, wizHead(w, "Create the administrator", "Only this account can sign in to DNSNova."),
      w.code || !w.codeRequired ? null : h("label", { class: "block" }, ["Setup code: the installer printed it, or run ", h("code", null, "cat /var/lib/dnsnova/secrets/setup-code"), " on the server. It is asked unless this page is opened on the server itself, through an SSH tunnel, or from your own network on a home or office server."], codeIn),
      h("label", { class: "block" }, "User name", user),
      h("label", { class: "block" }, "Password (at least 10 characters)", pass),
      h("label", { class: "block" }, "Password again", pass2),
      h("h2", { style: { margin: "8px 0 0", fontSize: "15px" } }, "This web interface"),
      access, portRow,
      wizNav(w, render, async () => {
        if (pass.value !== pass2.value) throw new Error("The passwords do not match.");
        const p = Number(port.value);
        if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error("The port must be a number from 1 to 65535.");
        state.session = await api("POST", "/setup", { code: (w.code || codeIn.value).trim(), username: user.value.trim(), password: pass.value });
        w.clientIP = state.session.client_ip;
        await wizLoad(w);
        w.values["admin.listen"] = (w.adminLocal ? "127.0.0.1:" : ":") + p;
      }));
    user.focus();
  },
  // 1: addresses
  (w, body, render) => {
    const cur = w.values["server.listen"];
    const allNow = cur.length > 0 && cur.every(isAllAddr);
    const localNow = cur.length > 0 && cur.every(isLocalAddr);
    const current = new Set(allNow || localNow ? [] : cur.map(hostOf));
    const virtual = /^(docker|veth|br-|virbr|cni|flannel|lxc|lxd|vmnet|vboxnet|zt)/;
    const usable = w.addrs.filter((a) => !a.loopback && !/^fe80/i.test(a.address));
    // this machine's own address too: programs on it (its own resolver,
    // proxies) ask 127.0.0.1 and would otherwise get no answer
    const list = [...new Set([...usable.map((a) => a.address), "127.0.0.1", ...current])];
    const curPort = cur.length ? cur[0].slice(cur[0].lastIndexOf(":") + 1) : "53";
    // who it is for: the one installing chooses. Public by default, never
    // guessed: home networks use every kind of address, cloud servers often
    // see only a private one, and taking a server for a home network would
    // shut the internet out
    let audience = w.audience || (w.values["server.mode"] === "private" ? "net" : "internet");
    // Plain HTTP from another machine works only for a home or office
    // server: choosing the internet closes this page to this browser.
    const plainRemote = location.protocol !== "https:" && !/^(127\.|\[::1\]|localhost)/.test(location.hostname);
    const lockNote = h("p", { class: "notice warn small", style: { margin: 0 } },
      "On an internet server, plain HTTP is served only to the server itself. After setup, this page will not open from here: use an SSH tunnel (ssh -L port:127.0.0.1:port user@server), or HTTPS once the certificate is ready.");
    const lockSync = () => { lockNote.hidden = !(plainRemote && audience === "internet"); };
    const who = (value, title, help) => {
      const r = h("input", { type: "radio", name: "audience", value, checked: audience === value });
      r.addEventListener("change", () => { audience = value; lockSync(); });
      return h("label", { class: "check" }, r, h("span", null, h("strong", null, title), h("span", { class: "small muted", style: { display: "block" } }, help)));
    };
    const audienceBox = h("div", { role: "radiogroup", "aria-label": "Who it is for", style: { display: "flex", flexDirection: "column", gap: "8px" } },
      who("internet", "Anyone on the internet (public DNS)", "Answers everyone, with limits against abuse."),
      who("net", "My network (home or office)", "Answers devices on private networks (192.168.x.x, 10.x.x.x and the like, VPNs included) and this machine, no one else. The web interface opens directly from those networks."));
    lockSync();
    const port = h("input", { type: "number", min: 1, max: 65535, value: curPort, inputmode: "numeric", "aria-label": "Port" });
    port.style.maxWidth = "120px";
    // any port but 53 is unusable for most things: say so while it is typed
    const portNote = h("p", { class: "notice warn small", style: { margin: 0 } },
      "Devices, routers (DHCP) and /etc/resolv.conf can only use port 53. Choose another port only if another DNS server here answers on 53 and forwards to DNSNova.");
    const portSync = () => { portNote.hidden = String(port.value).trim() === "53"; };
    port.addEventListener("input", portSync);
    portSync();
    const boxes = list.map((ip) => {
      const info = w.addrs.find((a) => a.address === ip);
      const pre = current.size ? current.has(ip) : ip === "127.0.0.1" || (info && !virtual.test(info.interface));
      const cb = h("input", { type: "checkbox", value: ip, checked: pre });
      return h("label", { class: "check" }, cb, h("span", { class: "mono" }, ip),
        h("span", { class: "small muted", style: { marginLeft: "auto" } }, ip === "127.0.0.1" ? "this machine" : info ? `${info.public ? "public" : "private"} · ${info.interface}` : "configured"));
    });
    const listBox = h("fieldset", { style: { border: 0, margin: "0 0 0 28px", padding: 0, display: "flex", flexDirection: "column", gap: "8px" } },
      h("legend", { class: "sr-only" }, "Addresses"), boxes);
    // who may use plain DNS: everyone, chosen addresses, or only this server
    let mode = localNow ? "local" : allNow || !list.length ? "all" : "some";
    const option = (value, title, help) => {
      const r = h("input", { type: "radio", name: "plain-who", value, checked: mode === value });
      r.addEventListener("change", () => { mode = value; sync(); });
      return h("label", { class: "check" }, r, h("span", null, h("strong", null, title), h("span", { class: "small muted", style: { display: "block" } }, help)));
    };
    const sync = () => { listBox.hidden = mode !== "some"; };
    const choices = h("div", { role: "radiogroup", "aria-label": "Who can use plain DNS", style: { display: "flex", flexDirection: "column", gap: "8px" } },
      option("all", "All addresses", "Every address of this server, also ones it gets later. For a public resolver, or when the address can change."),
      boxes.length ? [option("some", "Chosen addresses", "Only the addresses ticked below, for a server with several. Keep 127.0.0.1 ticked so programs on this machine can use it too."), listBox] : null,
      option("local", "Only this server (encrypted DNS only)", "Plain DNS stays on 127.0.0.1; devices connect over DNS over HTTPS, TLS or QUIC. The safest choice for a server on the internet."));
    sync();
    put(body, wizHead(w, "Addresses", "Who this server is for, and where plain DNS (UDP and TCP, what routers and most devices use) answers."),
      h("h3", { class: "small", style: { margin: "4px 0 0" } }, "Who it is for"),
      audienceBox, lockNote,
      h("h3", { class: "small", style: { margin: "8px 0 0" } }, "Plain DNS answers on"),
      choices,
      h("label", { class: "block" }, "Port (53 is the standard DNS port; devices and routers expect it)", port),
      portNote,
      h("p", { class: "small muted", style: { margin: 0 } }, "If another DNS server already uses this port, stop it first or choose another port."),
      wizNav(w, render, () => {
        const p = Number(port.value);
        if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error("The port must be a number from 1 to 65535.");
        if (audience === "net" && mode === "local") throw new Error("With plain DNS only on this server, your network cannot use it, and private mode refuses everyone else. For an encrypted-only server, choose Anyone on the internet; otherwise answer plain DNS on your network's address.");
        w.audience = audience;
        if (audience === "net") Object.assign(w.values, { "server.mode": "private", "access.allow": PRIVATE_NETS });
        else w.values["server.mode"] = "public";
        if (mode === "all") { w.values["server.listen"] = [":" + p]; return; }
        if (mode === "local") { w.values["server.listen"] = [withPort("127.0.0.1", p)]; return; }
        const ips = boxes.map((b) => b.querySelector("input")).filter((c) => c.checked).map((c) => c.value);
        if (!ips.length) throw new Error("Tick at least one address, or choose All addresses.");
        w.values["server.listen"] = ips.map((ip) => withPort(ip, p));
      }));
  },
  // 2: upstreams
  (w, body, render) => {
    const prim = h("textarea", { "aria-label": "Primary upstreams" });
    prim.value = (w.values["upstream.primary"].length ? w.values["upstream.primary"] : ["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"]).join("\n");
    const fb = h("textarea", { "aria-label": "Fallback upstreams" });
    fb.value = w.values["upstream.fallback"].join("\n");
    const presets = [
      ["Cloudflare", ["https://cloudflare-dns.com/dns-query", "tls://one.one.one.one"]],
      ["Google", ["https://dns.google/dns-query", "tls://dns.google"]],
      ["Quad9", ["https://dns.quad9.net/dns-query", "tls://dns.quad9.net"]],
    ];
    const rec = h("input", { type: "checkbox", checked: !!w.values["recursion.enabled"] });
    const primLabel = h("span");
    const sync = () => {
      primLabel.textContent = rec.checked ? "Upstreams, asked only when a domain\u2019s name servers cannot be reached (optional)" : "Primary, one per line: https://…/dns-query, h3://…/dns-query, tls://host, quic://host or an IP address";
      fbLabel.hidden = rec.checked;
    };
    const fbLabel = h("label", { class: "block" }, "Fallback, used only if all primaries fail (optional)", fb);
    rec.addEventListener("change", sync);
    put(body, wizHead(w, "Resolution", "Where answers come from when they are not cached."),
      h("label", { class: "check" }, rec, h("span", null, h("strong", null, "Resolve names itself"),
        h("span", { class: "small muted", style: { display: "block" } }, "Ask the root servers and each domain\u2019s own name servers, with DNSSEC checks, so no third party sees the queries. Otherwise the upstreams below answer (Cloudflare and Quad9, encrypted, preset)."))),
      h("div", { class: "chips" }, h("span", { class: "small muted" }, "Add:"), presets.map(([n, list]) =>
        h("button", { type: "button", class: "btn small", onclick: () => { prim.value = [...new Set([...lines(prim.value), list[0]])].join("\n"); } }, n))),
      h("label", { class: "block" }, primLabel, prim),
      fbLabel,
      wizNav(w, render, () => {
        w.values["recursion.enabled"] = rec.checked;
        w.values["upstream.primary"] = lines(prim.value);
        w.values["upstream.fallback"] = rec.checked ? [] : lines(fb.value);
        if (!rec.checked && !w.values["upstream.primary"].length) throw new Error("Add at least one primary upstream, or let DNSNova resolve names itself.");
      }));
    sync();
  },
  // 3: encrypted DNS
  (w, body, render) => {
    const dom = h("input", { type: "text", class: "mono", value: w.values["tls.domains"][0] || "", placeholder: "dns.example.com", spellcheck: "false" });
    const mail = h("input", { type: "email", value: w.values["tls.email"] || "", placeholder: "optional" });
    put(body, wizHead(w, "Encrypted DNS", "With a domain pointing to this server, phones and browsers can use DNS over TLS, QUIC and HTTPS. A Let's Encrypt certificate is requested and renewed automatically."),
      h("label", { class: "block" }, "Domain (leave empty to skip; you can add it later)", dom),
      h("label", { class: "block" }, "Email for expiry notices", mail),
      h("div", { class: "chips" }, ["DoT · TCP 853", "DoQ · UDP 853", "DoH · TCP 443", "HTTP/3 · UDP 443"].map((c) => h("span", { class: "chip" }, c))),
      h("p", { class: "muted small", style: { margin: 0 } }, "Ports 443 (or 80) must be reachable from the internet while the certificate is issued."),
      wizNav(w, render, () => {
        const d = dom.value.trim().toLowerCase().replace(/\.$/, "");
        if (!d) return;
        Object.assign(w.values, { "tls.certificate": "acme", "tls.domains": [d], "tls.email": mail.value.trim() }, encryptedListen(w.values["server.listen"]));
      }));
  },
  // 4: filtering. With a domain the filtered address is simply offered: it
  // changes nothing for the usual addresses. The real choice is whether
  // everyone should be filtered (a home or office server).
  (w, body, render) => {
    const domain = (w.values["tls.domains"] || [])[0] || "";
    const encrypted = domain && (w.values["doh.https_listen"] || []).length > 0;
    const path = w.values["filter.doh_path"] || "/filtered";
    const touched = w.filterSeen;
    const door = h("input", { type: "checkbox", checked: touched ? !!w.values["filter.enabled"] && !w.values["filter.all"] : true });
    const all = h("input", { type: "checkbox", checked: !!w.values["filter.all"] });
    const doorBox = encrypted ? h("label", { class: "check" }, door, h("span", null,
      h("strong", null, "Offer a filtered address"),
      h("span", { class: "small muted", style: { display: "block" } }, "For people who want ads, trackers and malicious sites blocked. The usual address answers as always."),
      h("code", { class: "small", style: { display: "block", marginTop: "6px" } }, `https://${domain}${path}`))) : null;
    const sync = () => { if (doorBox) doorBox.hidden = all.checked; };
    all.addEventListener("change", sync);
    put(body, wizHead(w, "Filtering", "Blocking of ads, trackers and malicious sites. It can be changed any time in Settings › Filtering."),
      doorBox,
      h("label", { class: "check" }, all, h("span", null, h("strong", null, "Filter everyone"),
        h("span", { class: "small muted", style: { display: "block" } }, "Every address blocks, with no unfiltered way in. For a home or office server."))),
      h("p", { class: "small muted", style: { margin: 0 } }, "Blocking uses the ShieldNova list: few false positives, free to use in DNSNova, commercially too. A wrongly blocked site is allowed again with one click in the query log."),
      wizNav(w, render, () => {
        w.filterSeen = true;
        const on = all.checked || (!!doorBox && door.checked);
        Object.assign(w.values, { "filter.enabled": on, "filter.all": all.checked });
      }));
    sync();
  },
  // 5: review
  async (w, body, render) => {
    put(body, wizHead(w, "Ready to start", "Check the changes. Everything can be changed later in Settings."));
    const set = changedValues(w.cfg, w.values);
    const box = h("div", null, h("p", { class: "muted" }, "Checking…"));
    put(body, box);
    let ok = true;
    if (!Object.keys(set).length) {
      fill(box, h("p", null, "The installer's settings are kept as they are."));
    } else {
      try {
        const p = await api("POST", "/config/preview", { hash: w.hash, set });
        fill(box, changeList(p.changes, labelFor), p.warnings.length ? h("ul", { class: "small warn" }, p.warnings.map((x) => h("li", null, x))) : null);
      } catch (e) {
        ok = false;
        fill(box, problemsBox(e));
      }
    }
    put(body, wizNav(w, render, async () => {
      if (!ok) return false;
      if (Object.keys(set).length) {
        try {
          await api("PATCH", "/config", { hash: w.hash, set });
        } catch (e) {
          fill(box, problemsBox(e, labelFor));
          return false;
        }
      }
      wizDone(w);
      return false;
    }, "Start DNSNova"));
  },
];

// wizDone tells the user what to do next: point devices at DNSNova, and
// open the dashboard (on its new address if setup moved it).
function wizDone(w) {
  const plain = w.values["server.listen"] || [];
  const localOnly = plain.length > 0 && plain.every(isLocalAddr);
  let ips = plain.map(hostOf).filter((x) => x && x !== "0.0.0.0" && x !== "::" && !/^(127\.|::1$)/.test(x));
  if (!ips.length && !localOnly) ips = w.addrs.filter((a) => !a.loopback && !/^fe80/i.test(a.address)).map((a) => a.address);
  if (localOnly) ips = [];
  const domain = (w.values["tls.domains"] || [])[0] || "";
  const dohURL = domain ? `https://${domain}${w.values["doh.path"] || "/dns-query"}` : "";
  const filteredURL = domain && w.values["filter.enabled"] && !w.values["filter.all"] ? `https://${domain}${w.values["filter.doh_path"] || "/filtered"}` : "";
  const l0 = (w.values["server.listen"] || [""])[0] || ":53";
  const dnsPort = l0.slice(l0.lastIndexOf(":") + 1);
  const adminL = w.values["admin.listen"] || "";
  const port = adminL.slice(adminL.lastIndexOf(":") + 1);
  const local = adminL.startsWith("127.") || adminL.startsWith("[::1]");
  const herePort = location.port || (location.protocol === "https:" ? "443" : "80");
  const hereLocal = /^(127\.|\[::1\]|localhost)/.test(location.hostname);
  const stays = !adminL || (port === herePort && local === hereLocal);
  const url = local ? `http://127.0.0.1:${port}/` : `${location.protocol}//${location.hostname}:${port}/`;
  const open = h("button", {
    type: "button", class: "btn primary", onclick: () => {
      if (stays) { location.hash = "#/overview"; showApp(); } else location.href = url;
    },
  }, "Open the dashboard");
  const ssh = local && !hereLocal ? `ssh -L ${port}:127.0.0.1:${port} user@${location.hostname}` : "";
  mount(h("main", { class: "wizard" }, h("div", { class: "inner" },
    h("div", { class: "wizhead" }, h("div", { class: "brand" }, brandMark(40, true), wordmark())),
    h("section", { class: "card wizbody done" },
      h("div", { class: "result ok" }, h("span", { class: "badge" }, s("svg", { width: 22, height: 22, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" }, s("path", { d: "M20 6 9 17l-5-5" }))),
        h("div", null, h("h1", { style: { margin: 0 } }, "DNSNova is running"), h("div", { class: "muted" }, "Now point your devices at it."))),
      ips.length ? [
        h("p", { style: { margin: 0 } }, "Use this as the DNS server:"),
        dnsPort !== "53" ? h("p", { class: "notice warn small", style: { margin: 0 } }, `On port ${dnsPort}. Most devices and routers can only use port 53.`) : null,
        ips.map((ip) => h("div", { class: "copyrow" }, h("span", { class: "k" }, "DNS server"), h("code", null, ip), h("button", { type: "button", class: "btn small", onclick: () => copy(ip) }, "Copy"))),
        h("ul", { class: "small", style: { margin: 0, paddingLeft: "18px", display: "flex", flexDirection: "column", gap: "6px" } },
          h("li", null, h("strong", null, "Every device at once: "), "in your router's settings, set this address as the DNS server it hands out (often under DHCP or LAN)."),
          h("li", null, h("strong", null, "One device: "), "in its network or Wi-Fi settings, change DNS from automatic to manual and enter this address."),
          (w.values["tls.domains"] || []).length ? h("li", null, h("strong", null, "Encrypted DNS: "), "once the certificate is issued, Settings › Encrypted DNS lists the addresses for phones and browsers.") : null),
      ] : null,
      localOnly ? [
        h("p", { style: { margin: 0 } }, "Plain DNS answers only on this server. Devices use encrypted DNS:"),
        domain ? [
          h("div", { class: "copyrow" }, h("span", { class: "k" }, "DNS over HTTPS"), h("code", null, dohURL), h("button", { type: "button", class: "btn small", onclick: () => copy(dohURL) }, "Copy")),
          h("div", { class: "copyrow" }, h("span", { class: "k" }, "DNS over TLS"), h("code", null, domain), h("button", { type: "button", class: "btn small", onclick: () => copy(domain) }, "Copy")),
          filteredURL ? h("div", { class: "copyrow" }, h("span", { class: "k" }, "With filtering"), h("code", null, filteredURL), h("button", { type: "button", class: "btn small", onclick: () => copy(filteredURL) }, "Copy")) : null,
          h("p", { class: "small muted", style: { margin: 0 } }, "They work once the certificate is issued, usually within a minute. The setup guide in the dashboard has steps for each kind of device."),
        ] : h("p", { class: "notice warn small", style: { margin: 0 } }, "No domain is set yet, so devices cannot connect. Add one in Settings › Encrypted DNS."),
      ] : null,
      stays ? null : h("p", { class: "notice" }, local
        ? ["The web interface now listens only on this server. ", ssh ? ["Open a tunnel first: ", h("code", null, ssh), ", then "] : "", "open ", h("code", null, url), "."]
        : ["The web interface moved to ", h("code", null, url), "."]),
      h("div", { class: "wiznav" }, h("span"), open)))));
}

const lines = (t) => t.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function changedValues(before, after) {
  const out = {};
  for (const [k, v] of Object.entries(after)) {
    if (JSON.stringify(v) !== JSON.stringify(before[k])) out[k] = v;
  }
  return out;
}

// ---------- the app shell ----------

const NAV = [
  ["Status", [["Overview", "overview", "home"], ["Upstreams", "upstreams", "upstreams"], ["Query log", "querylog", "querylog"]]],
  ["Settings", [["DNS & upstreams", "settings/dns", "dns"], ["Filtering", "settings/filter", "filter"], ["Encrypted DNS", "settings/encryption", "lock"], ["Access & limits", "settings/access", "shield"], ["Alerts", "settings/alerts", "bell"], ["Admin", "settings/admin", "user"]]],
  ["Tools", [["Setup guide", "tools/guide", "phone"], ["Compare upstreams", "tools/lookup", "compare"], ["Trace a lookup", "tools/trace", "arrow"]]],
];

function route() {
  return (location.hash.replace(/^#\/?/, "") || "overview").split("?")[0];
}

// health sums up the server in one line, for the top bar and the overview:
// resolution from the root servers, or the state of the upstreams.
function health(st, ups) {
  const rec = st && st.recursion && st.recursion.enabled ? st.recursion : null;
  if (st && st.serves_dns === false) return ["warn", "Not serving DNS"];
  if (rec && rec.intercepted) return ["err", "DNS intercepted by the network"];
  if (rec) return rec.healthy ? ["ok", "System Online"] : ["err", "Name servers unreachable"];
  const states = ups.map((u) => upState(u, ups).cls);
  const failing = states.filter((x) => x === "err").length, slow = states.filter((x) => x === "warn").length;
  if (ups.length && failing === ups.length) return ["err", "All upstreams failing"];
  if (failing) return ["warn", `${failing} of ${ups.length} upstreams failing`];
  if (slow) return ["warn", `${slow} upstream${slow === 1 ? "" : "s"} slow`];
  return ["ok", "System Online"];
}

// fleetState sums up a cluster for the top bar (docs/design.md, Toward
// clusters), or null on a server alone.
function fleetState(cl) {
  if (!cl || !cl.role) return null;
  if (cl.role === "follower") return cl.sync_error ? ["warn", "Not in touch with the primary"] : null;
  const nodes = cl.nodes || [];
  const online = nodes.filter((n) => n.online).length;
  const behind = nodes.filter((n) => n.online && !n.in_sync).length;
  const sick = nodes.filter((n) => n.online && n.status === "unhealthy").length;
  if (online < nodes.length) return ["warn", `${online} of ${nodes.length} nodes online`];
  if (sick) return ["warn", `${sick} of ${nodes.length} nodes unhealthy`];
  if (behind) return ["warn", `${behind} node${behind === 1 ? "" : "s"} behind on settings`];
  return ["ok", `${online} of ${nodes.length} nodes online`];
}

async function showApp() {
  const main = h("main", { class: "main", id: "main", tabindex: "-1" });
  const nav = h("nav", { class: "nav", "aria-label": "Main" });
  const ver = h("div", { class: "ver" }, "DNSNova");
  const menu = h("button", { type: "button", class: "btn small menu", "aria-expanded": "false", "aria-controls": "sidebody" }, "Menu");
  // the brand goes home, as on routers and firewalls; on the overview it
  // shows the overview afresh rather than doing nothing
  const home = (e) => { if (route() === "overview") { e.preventDefault(); window.onhashchange(); } };
  const side = h("aside", { class: "side" },
    h("a", { class: "railbrand", href: "#/overview", title: "Overview", "aria-label": "DNSNova: go to the overview", onclick: home, style: { textDecoration: "none" } }, brandMark(96, true), wordmark("rail"), h("div", { class: "tagline" }, TAGLINE)),
    h("div", { class: "railtop" },
      h("a", { class: "railhome", href: "#/overview", title: "Overview", "aria-label": "DNSNova: go to the overview", onclick: home }, brandMark(34, true), wordmark("rail")),
      menu),
    h("div", { class: "sidebody", id: "sidebody" }, nav, h("div", { class: "sidefoot" }, ver)));
  const setMenu = (open) => { side.classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); menu.textContent = open ? "Close" : "Menu"; };
  menu.addEventListener("click", () => setMenu(!side.classList.contains("open")));
  const top = topBar();
  mount(h("div", { class: "shell" }, side, main));
  // Nodes appears only on a node of a cluster (docs/design.md, Toward clusters)
  const navItems = (title, items) => {
    if (title !== "Status") return items;
    const out = [...items];
    if (state.dnssec && state.dnssec.recursion) out.push(["DNSSEC", "dnssec", "shieldcheck"]); // only when resolving from the root
    if (state.cluster && state.cluster.role) out.push(["Nodes", "nodes", "network"]);
    return out;
  };
  const drawNav = () => fill(nav, ...NAV.map(([title, items]) => h("div", { class: "navgroup" },
    h("div", { class: "navtitle" }, title),
    navItems(title, items).map(([label, r, ic]) => h("a", { href: "#/" + r, "aria-current": route() === r ? "page" : null }, line(ic, 19), h("span", null, label))))));
  try { state.cluster = await api("GET", "/cluster"); } catch (e) { state.cluster = null; }
  try { state.dnssec = await api("GET", "/dnssec"); } catch (e) { state.dnssec = null; }
  const go = () => {
    setMenu(false);
    top.closeMenu();
    drawNav();
    stopTimer();
    main.classList.remove("narrow"); // only settings and the guide use the narrow layout
    fill(main, top.el);
    const page = PAGES_BY_ROUTE[route()] || PAGES_BY_ROUTE.overview;
    page(main);
    main.focus({ preventScroll: true });
  };
  window.onhashchange = go;
  go();
  // the top bar and the rail keep their own, slower refresh
  const refresh = async () => {
    try {
      const [st, ups] = await Promise.all([api("GET", "/status"), api("GET", "/upstreams")]);
      state.status = st;
      if (state.cluster && state.cluster.role) {
        try { state.cluster = await api("GET", "/cluster"); } catch (e) { /* keep the last */ }
      }
      top.update(st, ups.upstreams);
      ver.textContent = `DNSNova ${st.version}`;
    } catch (e) { /* the page shows the error */ }
  };
  refresh();
  if (state.shellTimer) clearInterval(state.shellTimer);
  state.shellTimer = setInterval(() => { if (document.visibilityState === "visible" && state.session) refresh(); }, 30000);
}

// topBar: search, the system state and the account menu.
function topBar() {
  const stDot = h("span", { class: "dot idle" });
  const stTxt = h("span", { class: "txt" }, "Checking…");
  const sys = h("a", { class: "sysstate", href: "#/upstreams", title: "Server state", style: { color: "inherit", textDecoration: "none" } }, stDot, stTxt);
  const pop = h("div", { class: "menu-pop", role: "menu", hidden: true });
  const name = (state.session && state.session.username) || "admin";
  const btn = h("button", { type: "button", class: "userbtn", "aria-haspopup": "menu", "aria-expanded": "false" },
    h("span", { class: "avatar" }, line("user", 18)), h("span", null, name), line("chevron", 15));
  const who = h("div", { class: "who" }, h("strong", null, name), h("span", null, "Administrator"));
  const draw = () => fill(pop, who,
    h("div", { class: "lab" }, "Appearance"), appearance(),
    h("a", { class: "item", href: "#/settings/admin", role: "menuitem" }, line("user", 16), "Account & security"),
    h("a", { class: "item", href: PROJECT + "/blob/main/docs/api.md", target: "_blank", rel: "noopener noreferrer", role: "menuitem" }, line("book", 16), "API documentation"),
    h("button", { type: "button", class: "item", role: "menuitem", onclick: logout }, line("logout", 16), "Sign out"));
  const setOpen = (open) => {
    if (open) draw();
    pop.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
  };
  btn.addEventListener("click", (ev) => { ev.stopPropagation(); setOpen(pop.hidden); });
  pop.addEventListener("click", (ev) => ev.stopPropagation());
  // one pair of document listeners, however often the shell is drawn
  if (state.topOff) state.topOff();
  const onDoc = () => setOpen(false);
  const onKey = (ev) => { if (ev.key === "Escape" && !pop.hidden) { setOpen(false); btn.focus(); } };
  document.addEventListener("click", onDoc);
  document.addEventListener("keydown", onKey);
  state.topOff = () => { document.removeEventListener("click", onDoc); document.removeEventListener("keydown", onKey); };
  const el = h("header", { class: "topbar" }, searchBox(), h("span", { class: "grow" }), sys, h("span", { class: "vsep", "aria-hidden": "true" }),
    h("div", { class: "usermenu" }, btn, pop));
  return {
    el,
    closeMenu: () => setOpen(false),
    update(st, ups) {
      // this server's own trouble first, then the fleet's
      let [cls, text] = health(st, ups);
      const fleet = fleetState(state.cluster);
      if (fleet && cls !== "err" && (fleet[0] !== "ok" || cls === "ok")) [cls, text] = fleet;
      sys.setAttribute("href", fleet ? "#/nodes" : "#/upstreams");
      stDot.className = "dot lit " + cls;
      stTxt.textContent = text;
      fill(who, h("strong", null, name), h("span", null, (st.domains[0] || location.hostname)), h("span", { class: "mono" }, `${st.version} · up ${fmt.uptime(st.uptime_seconds)}`));
    },
  };
}

async function logout() {
  if (state.shellTimer) clearInterval(state.shellTimer);
  state.shellTimer = null;
  try { await api("POST", "/logout"); } catch (e) { /* ignore */ }
  state.session = null;
  showLogin("You are signed out.");
}

// "/" jumps to any page or setting.
function searchBox() {
  const input = h("input", { type: "search", placeholder: "Search settings", "aria-label": "Search settings and tools", autocomplete: "off", role: "combobox", "aria-expanded": "false", "aria-controls": "search-results" });
  const list = h("div", { class: "results", id: "search-results", role: "listbox", hidden: true });
  let items = [], sel = 0;
  const index = () => {
    const out = [];
    for (const [g, its] of NAV) for (const [label, r] of its) out.push({ label, where: g, r });
    for (const [r, page] of Object.entries(SETTINGS)) {
      for (const sec of page.sections) for (const f of sec.fields || []) {
        out.push({ label: f.label, where: page.title + " › " + sec.title, r: "settings/" + r, key: f.key, words: (f.key || "") + " " + (f.help || "") });
      }
      for (const x of page.extra || []) out.push({ label: x, where: page.title, r: "settings/" + r });
    }
    return out;
  };
  const show = () => {
    const q = input.value.trim().toLowerCase();
    if (!q) { list.hidden = true; input.setAttribute("aria-expanded", "false"); return; }
    items = index().filter((x) => (x.label + " " + (x.words || "")).toLowerCase().includes(q)).slice(0, 12);
    sel = 0;
    fill(list, ...(items.length ? items.map((x, i) => h("button", {
      type: "button", role: "option", "aria-selected": String(i === sel), onmousedown: (ev) => { ev.preventDefault(); pick(x); },
    }, x.label, h("span", { class: "where" }, x.where))) : [h("div", { class: "empty small", style: { padding: "6px 8px" } }, "Nothing found")]));
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
  };
  const pick = (x) => {
    input.value = "";
    show();
    input.blur();
    state.focusKey = x.key;
    if (route() === x.r) window.onhashchange(); else location.hash = "#/" + x.r;
  };
  input.addEventListener("input", show);
  input.addEventListener("blur", () => setTimeout(() => { list.hidden = true; }, 100));
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
      ev.preventDefault();
      if (!items.length) return;
      sel = (sel + (ev.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
      [...list.children].forEach((c, i) => c.setAttribute("aria-selected", String(i === sel)));
    } else if (ev.key === "Enter" && items[sel]) {
      ev.preventDefault();
      pick(items[sel]);
    } else if (ev.key === "Escape") {
      input.value = "";
      show();
      input.blur();
    }
  });
  return h("div", { class: "search" }, h("label", null, icon.search(), input, h("kbd", { "aria-hidden": "true" }, "/")), list);
}

document.addEventListener("keydown", (ev) => {
  if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const t = ev.target;
  if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || t.isContentEditable) return;
  const s = document.querySelector(".search input");
  if (s) { ev.preventDefault(); s.focus(); }
});

function pageHead(title, crumb, right) {
  return h("header", { class: "pagehead" }, h("div", null, crumb ? h("div", { class: "crumb" }, crumb) : null, h("h1", null, title)), right || null);
}

function errorBox(e) {
  return h("p", { class: "notice err", role: "alert" }, e.message);
}

// ---------- overview ----------

const PROTOS = [["udp", "UDP", "53"], ["tcp", "TCP", "53"], ["dot", "DoT", "TCP 853"], ["doh", "DoH", "HTTP/2"], ["doh3", "DoH", "HTTP/3"], ["doq", "DoQ", "UDP 853"]];
const REJECT_NAMES = {
  acl: "Access list", client_limit: "Per-client limit", network_limit: "Per-network limit", global_limit: "Server limit",
  rrl_drop: "Rate limiting, dropped", rrl_slip: "Rate limiting, truncated", overload: "Overload",
  upstream_busy: "Upstreams busy", zone_busy: "One domain too busy", malformed: "Malformed",
};

// The overview follows the reference layout: brand head, four key figures,
// traffic with the flow of queries through this node, then the three lists
// people look at most, then the details.
const RANGE_LABEL = { "1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" };
const RANGE_SECONDS = { "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000 };
// the previous period of a range is read from the next longer range
const LONGER = { "1h": "24h", "24h": "7d", "7d": "30d" };

function overview(main) {
  let range = sessionStorage.getItem("dnsnova-range") || "24h";
  let metric = sessionStorage.getItem("dnsnova-metric") || "traffic";
  const ident = h("div", { class: "ident" });
  const head = h("header", { class: "hero-head" }, h("h1", { class: "sr-only" }, "Overview"), wordmark(), h("span", { class: "divider", "aria-hidden": "true" }), h("span", { class: "tagline" }, TAGLINE), ident);
  const body = h("div", null, h("p", { class: "muted" }, "Loading…"));
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Time range" });
  const mseg = h("div", { class: "seg", role: "group", "aria-label": "Chart" });
  const ranges = () => ({ "24h": ["1h", "24h"], "30d": ["1h", "24h", "7d", "30d"] })[state.status?.retention] || ["1h", "24h", "7d"];
  const drawSeg = () => fill(seg, ...ranges().map((r) => h("button", {
    type: "button", "aria-pressed": String(r === range),
    onclick: () => { range = r; sessionStorage.setItem("dnsnova-range", r); drawSeg(); load(); },
  }, r)));
  const drawMseg = () => fill(mseg, ...[["traffic", "Traffic"], ["latency", "Latency"]].map(([m, t]) => h("button", {
    type: "button", "aria-pressed": String(m === metric),
    onclick: () => { metric = m; sessionStorage.setItem("dnsnova-metric", m); drawMseg(); if (last) draw(); },
  }, t)));
  drawSeg();
  drawMseg();
  main.append(head, body);
  let last = null;
  const draw = () => fill(body, ...drawOverview(last, { range, metric, seg, mseg }));
  const load = async () => {
    try {
      const st = await api("GET", "/status");
      state.status = st;
      const [stats, ups, ev, prev] = await Promise.all([api("GET", "/stats?range=" + range), api("GET", "/upstreams"), api("GET", "/events?limit=40"), previous(range)]);
      drawSeg();
      noteLatency(ups.upstreams);
      fill(ident,
        h("span", { class: "idchip" }, h("span", { class: "dot lit " + health(st, ups.upstreams)[0] }), h("strong", { class: "mono" }, st.domains[0] || location.hostname)),
        h("span", { class: "idchip" }, st.mode === "private" ? "Private resolver" : "Public resolver"),
        h("span", { class: "idchip mono" }, `${st.version} · up ${fmt.uptime(st.uptime_seconds)}`));
      last = { st, stats, ups: ups.upstreams, events: ev.events, prev };
      draw();
    } catch (e) {
      if (e.status !== 401) fill(body, errorBox(e));
    }
  };
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible") load(); }, 15000);
}

// previous loads the longer range once every five minutes, to compare the
// chosen range with the one before it. Statistics live in memory, so there
// is nothing to compare until the server has run for two ranges.
async function previous(range) {
  const longer = LONGER[range];
  const ret = state.status?.retention || "7d";
  if (!longer || RANGE_SECONDS[longer] > RANGE_SECONDS[ret]) return null;
  if ((state.status?.uptime_seconds || 0) < RANGE_SECONDS[range] * 1.8) return null;
  const c = state.prev;
  if (c && c.range === range && Date.now() - c.at < 300e3) return c.data;
  try {
    const data = await api("GET", "/stats?range=" + longer);
    state.prev = { range, at: Date.now(), data };
    return data;
  } catch (e) { return null; }
}

// Upstream latency samples taken while the overview is open, for the small
// trend lines. Kept for this browser tab only.
function noteLatency(ups) {
  if (!state.upHist) {
    try { state.upHist = JSON.parse(sessionStorage.getItem("dnsnova-uphist") || "{}"); } catch (e) { state.upHist = {}; }
  }
  for (const u of ups) {
    if (!u.latency_ms) continue;
    const l = (state.upHist[u.address] ||= []);
    l.push(Math.round(u.latency_ms * 10) / 10);
    if (l.length > 40) l.splice(0, l.length - 40);
  }
  try { sessionStorage.setItem("dnsnova-uphist", JSON.stringify(state.upHist)); } catch (e) { /* private window */ }
}

// upState describes an upstream: healthy, slow (three times slower than
// the median of the healthy primaries and over 50 ms, or over 500 ms),
// failing, or standing by (a healthy fallback).
function upState(u, ups) {
  if (!u.healthy) return { cls: "err", label: "Failing" };
  if (u.role === "fallback") return { cls: "idle", label: "Standby" };
  const lat = ups.filter((x) => x.healthy && x.role === "primary" && x.latency_ms > 0).map((x) => x.latency_ms).sort((a, b) => a - b);
  const med = lat.length ? lat[Math.floor(lat.length / 2)] : 0;
  if (u.latency_ms > 500 || (lat.length > 1 && u.latency_ms > 3 * med && u.latency_ms > 50)) return { cls: "warn", label: "Slow" };
  return { cls: "ok", label: "Healthy" };
}

function successRate(u) {
  if (!u.queries) return "–";
  const r = 1 - u.errors / u.queries;
  return (r >= 0.9995 ? "100" : (r * 100).toFixed(1)) + "%";
}

// mergeEvents folds consecutive identical events into one with a count.
function mergeEvents(events) {
  const out = [];
  for (const e of events) {
    const last = out[out.length - 1];
    if (last && last.message === e.message && last.level === e.level) last.count++;
    else out.push({ ...e, count: 1 });
  }
  return out;
}

function eventIcon(e) {
  if (e.level === "error" || e.level === "warn") return "alert";
  const m = e.message;
  if (/certificate|acme|tls/i.test(m)) return "lock";
  if (/^admin: (login|logout|administrator|password|two-step)/.test(m)) return "user";
  if (/query log/.test(m)) return "querylog";
  if (/settings|configuration|cache/.test(m)) return "sliders";
  if (/started|stopping|shutting/.test(m)) return "power";
  return "info";
}

// Every card in a row has the same height and every list a fixed number of
// rows, so the page looks the same with little data as with a lot. Missing
// rows are drawn as faint placeholders.
const SLOTS = 5;

function slots(items, n, row, cls) {
  const out = items.slice(0, n).map(row);
  while (out.length < n) {
    const sk = h("span", { class: "skel" });
    sk.style.width = [46, 62, 38, 54, 70, 42][out.length % 6] + "%";
    out.push(h("li", { class: "slot ph", "aria-hidden": "true" }, sk));
  }
  return h("ul", { class: "slots" + (cls ? " " + cls : "") }, out);
}

function card(span, title, ic, right, ...body) {
  return h("section", { class: "card dcard " + span, "aria-label": title },
    h("header", { class: "dhead" }, line(ic, 20), h("h2", null, title), right ? h("div", { class: "dright" }, right) : null),
    ...body);
}

function more(href, text = "More") {
  return h("a", { class: "more", href }, text, line("arrow", 15));
}

function meter(frac) {
  const bar = h("div");
  bar.style.width = Math.max(0, Math.min(1, frac)) * 100 + "%";
  return h("div", { class: "meter" }, bar);
}

// series helpers
const stepSeconds = (ser) => (ser.length > 1 ? (new Date(ser[1].t) - new Date(ser[0].t)) / 1000 : 60);
const sum = (a) => a.reduce((x, y) => x + y, 0);
function weightedP50(ser) {
  const q = sum(ser.map((p) => p.queries));
  return q ? sum(ser.map((p) => p.latency.p50_ms * p.queries)) / q : 0;
}
// windowBefore: the points of a longer series in the period just before the
// current one, when they cover at least 80% of it.
function windowBefore(prev, ser, range) {
  if (!prev || !prev.series || !prev.series.length || !ser.length) return null;
  const from = new Date(ser[0].t).getTime(), span = RANGE_SECONDS[range] * 1000;
  const pts = prev.series.filter((p) => { const t = new Date(p.t).getTime(); return t >= from - span && t < from; });
  if (pts.length < 2 || pts.length * stepSeconds(prev.series) < 0.8 * span / 1000 || !sum(pts.map((p) => p.queries))) return null;
  return pts;
}
// bucket merges points so a line has at most max of them
function bucket(ser, max) {
  if (ser.length <= max) return ser;
  const k = Math.ceil(ser.length / max), out = [];
  for (let i = 0; i < ser.length; i += k) {
    const g = ser.slice(i, i + k), q = sum(g.map((p) => p.queries));
    out.push({ t: g[0].t, n: g.length, queries: q, latency: {
      p50_ms: q ? sum(g.map((p) => p.latency.p50_ms * p.queries)) / q : sum(g.map((p) => p.latency.p50_ms)) / g.length,
      p95_ms: Math.max(...g.map((p) => p.latency.p95_ms)),
    } });
  }
  return out;
}
// smooth draws a line through points as gentle curves (Catmull-Rom), never
// overshooting below the baseline.
function smooth(pts, base) {
  if (pts.length < 3) return "M" + pts.map((p) => p.join(",")).join("L");
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    const c1 = [p1[0] + (p2[0] - p0[0]) / 6, Math.min(base, p1[1] + (p2[1] - p0[1]) / 6)];
    const c2 = [p2[0] - (p3[0] - p1[0]) / 6, Math.min(base, p2[1] - (p3[1] - p1[1]) / 6)];
    d += `C${c1[0].toFixed(1)},${c1[1].toFixed(1)} ${c2[0].toFixed(1)},${c2[1].toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}
let gradSeq = 0;
function vgrad(top, bottom) {
  const id = "vg" + ++gradSeq;
  const a = s("stop", { offset: 0 }), b = s("stop", { offset: 1 });
  a.style.stopColor = top;
  b.style.stopColor = bottom;
  return [id, s("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 }, a, b)];
}

// sparkline: a small area under a line, filling the bottom of a key figure.
function sparkline(values) {
  const W = 300, H = 52, top = 6;
  if (values.length < 2 || !values.some((v) => v > 0)) return s("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", "aria-hidden": "true", class: "spark" });
  const max = Math.max(...values) * 1.08 || 1, min = Math.min(...values) * 0.85;
  const pts = values.map((v, i) => [(i * W) / (values.length - 1), H - ((v - min) / (max - min || 1)) * (H - top)]);
  const [id, grad] = vgrad("color-mix(in srgb, var(--kc, var(--accent)) 45%, transparent)", "color-mix(in srgb, var(--kc, var(--accent)) 0%, transparent)");
  const d = smooth(pts, H);
  return s("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", "aria-hidden": "true", class: "spark" },
    s("defs", null, grad), s("path", { class: "a", d: `${d}L${W},${H}L0,${H}Z`, fill: `url(#${id})` }),
    s("path", { class: "l", d, "vector-effect": "non-scaling-stroke" }));
}

// delta: the change against the previous period. good says which way is
// good: "up", "down", or "" when the direction is neither (traffic).
function delta(cur, prev, good, range) {
  if (!prev || !cur) return null;
  const d = ((cur - prev) / prev) * 100;
  const flat = Math.abs(d) < 0.05;
  const cls = flat ? "flat" : !good ? "neutral" : (d > 0) === (good === "up") ? "good" : "bad";
  return h("span", { class: "delta " + cls, title: `Compared with the ${RANGE_LABEL[range].replace("last", "previous")}` },
    flat ? "±" : d > 0 ? "↑" : "↓", " ", Math.abs(d) >= 100 ? Math.round(Math.abs(d)) + "%" : Math.abs(d).toFixed(1) + "%");
}

function kpiCard(color, ic, label, value, unit, dl, note, vis, visPad) {
  const c = h("section", { class: "card kcard s3", "aria-label": label },
    h("div", { class: "ktop" }, h("span", { class: "kicon" }, line(ic, 46)),
      h("div", { style: { minWidth: 0 } }, h("div", { class: "klabel" }, label),
        h("div", { class: "kval" }, h("span", { class: "big" }, value, unit ? h("span", { class: "unit" }, unit) : null), dl),
        h("div", { class: "knote" }, note))),
    h("div", { class: "kvis" + (visPad ? " pad" : "") }, vis));
  c.style.setProperty("--kc", color);
  return c;
}

function drawOverview(d, { range, metric, seg, mseg }) {
  const { st, stats, ups, events, prev } = d;
  const label = RANGE_LABEL[range];
  const total = sum(Object.values(stats.queries));
  const rejected = sum(Object.values(stats.rejected));
  const answered = sum(Object.values(stats.answers));
  const ser = stats.series || [];
  const step = stepSeconds(ser);
  const rates = ser.map((p) => p.queries / step);
  const before = windowBefore(prev, ser, range);
  const rec = st.recursion && st.recursion.enabled ? st.recursion : null;
  const open = PROTOS.map(([k]) => k).filter((k) => (st.listeners || {})[k] || (k === "doh" && (st.listeners || {}).doh_proxy));

  // ---- key figures ----
  // the newest point is still filling, so "now" is the one before it
  const nowRate = rates.length > 1 ? rates[rates.length - 2] : rates[0] || 0;
  const avgRate = ser.length ? total / (ser.length * step) : 0;
  const prevRate = before ? sum(before.map((p) => p.queries)) / (before.length * stepSeconds(prev.series)) : 0;
  const peak = Math.max(0, ...rates);
  const sparkRates = bucket(ser, 48).map((p) => p.queries / (step * (p.n || 1)));
  const k1 = kpiCard("var(--c1)", "bolt", "Queries / sec", total ? fmt.rate(nowRate) : "–", null, delta(avgRate, prevRate, "", range),
    total ? `avg ${fmt.rate(avgRate)} · peak ${fmt.rate(peak)}` : "Waiting for the first queries", sparkline(sparkRates));

  const p50 = stats.latency.all.p50_ms;
  const k2 = kpiCard("var(--c3)", "shieldcheck", "Response time", total ? fmt.ms(p50) : "–", total ? "ms" : null,
    before ? delta(weightedP50(ser), weightedP50(before), "down", range) : null,
    total ? `median · 95th percentile ${fmt.ms(stats.latency.all.p95_ms)} ms` : "median, all answers", sparkline(bucket(ser, 48).map((p) => p.latency.p50_ms)));

  const parts = [["cache", (stats.answers.cache || 0) + (stats.answers.stale || 0), "var(--c1)", "cache"], ["upstream", stats.answers.upstream || 0, "var(--c2)", rec ? "resolved" : "upstream"],
    ["local", stats.answers.local || 0, "var(--c4)", "local"], ["blocked", stats.answers.blocked || 0, "var(--warn)", "blocked"]].filter(([, v]) => v > 0);
  const mix = h("div", null,
    h("div", { class: "mixbar", role: "img", "aria-label": parts.map(([, v, , n]) => `${n} ${fmt.pct(v / answered)}`).join(", ") },
      parts.map(([, v, c]) => { const e = h("span"); e.style.flex = String(v); e.style.background = c; return e; })),
    h("div", { class: "mixleg" }, parts.map(([, v, c, n]) => { const i = h("i"); i.style.background = c; return h("span", null, i, n, " ", fmt.pct(v / answered)); })));
  const k3 = kpiCard("var(--c2)", "layers", "Cache hit rate", answered ? fmt.pct(stats.cache_ratio).replace("%", "") : "–", answered ? "%" : null, null,
    answered ? `${fmt.short(answered)} answers · ${label}` : "share answered from memory", answered ? mix : h("div", { class: "mixbar" }), true);

  const since = new Date(st.started);
  const k4 = kpiCard("var(--c1)", "bars", "Uptime", fmt.uptime(st.uptime_seconds), null, null,
    `since ${since.toLocaleDateString([], { month: "short", day: "numeric" })} · ${st.version}`,
    h("div", { class: "protos", "aria-label": "Protocols" }, PROTOS.map(([k, n]) => h("span", { class: open.includes(k) ? "on" : "", title: open.includes(k) ? "listening" : "off" }, k === "doh3" ? "H3" : n))), true);

  // ---- traffic ----
  const chart = card("s8", "DNS Traffic", "bars", [mseg, seg],
    h("div", { class: "sub", style: { marginTop: "-8px" } }, total ? `${fmt.int(total)} queries · ${label}` + (rejected ? ` · ${fmt.short(rejected)} rejected` : "") : label),
    trafficChart(ser, total, range, label, metric));

  // ---- flow through this node ----
  const flow = flowCard(st, stats, ups, total, open, rec, nowRate);

  // ---- the three lists ----
  const most = Math.max(1, ...(stats.top_domains || []).map((x) => x.count));
  const privacyNote = "Only names asked from at least 5 different networks are listed, so no one person's browsing shows up.";
  const top = (stats.top_domains || []).length
    ? card("s4", "Top Domains", "trophy", h("span", { class: "small muted", title: privacyNote }, "asked from 5+ networks"),
      slots(stats.top_domains, SLOTS, (x, i) => h("li", { class: "slot" }, h("span", { class: "rank" }, i + 1), h("span", { class: "nm mono ellipsis", title: x.name }, x.name),
        meter(x.count / most), h("span", { class: "num" }, fmt.short(x.count)), h("span", { class: "share" }, total ? fmt.pct(x.count / total) : "")), "toprows"))
    : card("s4", "Top Domains", "trophy", null, h("p", { class: "empty small muted" }, "No domains to show yet. ", privacyNote));

  const upCard = rec ? recCard(rec) : card("s4", "Upstream Servers", "shield", more("#/upstreams"),
    slots(ups, SLOTS, (u) => {
      const us = upState(u, ups);
      return h("li", { class: "slot", title: `${u.address} · ${us.label}` }, h("span", { class: "dot lit " + us.cls }),
        h("span", { class: "nm" }, h("span", { class: "ellipsis", style: { display: "block" } }, upName(u.address)), h("span", { class: "role" }, `${us.label} · ${u.role}`)),
        h("span", { class: "rate" }, successRate(u)), miniTrend((state.upHist || {})[u.address] || []),
        h("span", { class: "lat" }, u.latency_ms ? fmt.ms(u.latency_ms) + " ms" : "–"));
    }, "uprows"));

  const merged = mergeEvents(events);
  const evCard = card("s4 last", "Recent Activity", "file", null,
    slots(merged, SLOTS, (e) => h("li", { class: "slot" },
      h("span", { class: "dot lit " + (e.level === "error" ? "err" : e.level === "warn" ? "warn" : eventIcon(e) === "sliders" || eventIcon(e) === "user" ? "cyan" : "ok") }),
      h("span", { class: "nm ellipsis" + (e.level === "error" ? " err" : ""), title: e.message }, e.message),
      e.count > 1 ? h("span", { class: "count", title: `${e.count} times in a row` }, "×" + e.count) : h("span"),
      h("span", { class: "when", title: new Date(e.time).toString() }, fmt.ago(e.time)))
    , "actrows"),
    h("footer", { class: "dfoot" }, h("span", null, "Starts, errors, sign-ins and setting changes; never queries")));

  // ---- details ----
  const topCard = (title, ic, list, emptyNote) => {
    const m = Math.max(1, ...list.map((x) => x.count));
    if (!list.length) return card("s3", title, ic, null, h("p", { class: "empty small muted" }, emptyNote, " ", privacyNote));
    return card("s3", title, ic, null,
      slots(list, SLOTS, (x, i) => h("li", { class: "slot" }, h("span", { class: "rank" }, i + 1), h("span", { class: "nm mono ellipsis", title: x.name }, x.name),
        meter(x.count / m), h("span", { class: "num" }, fmt.short(x.count)))),
      h("footer", { class: "dfoot" }, h("span", null, `Top ${Math.min(list.length, SLOTS)} of ${list.length}`), h("span", { class: "muted", title: privacyNote }, "5+ networks")));
  };
  const rej = Object.entries(stats.rejected).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  const rejMax = Math.max(1, ...rej.map(([, v]) => v));
  const limited = stats.top_limited_networks || [];
  const rejCard = !rej.length ? card("s3", "Rejected", "shield", null, h("p", { class: "empty small muted" }, "Nothing rejected. Queries over the limits or from blocked clients would be counted here.")) : card("s3", "Rejected", "shield", null,
    slots(rej, SLOTS, ([k, v]) => h("li", { class: "slot" }, h("span", { class: "nm ellipsis" }, REJECT_NAMES[k] || k), meter(v / rejMax), h("span", { class: "num" }, fmt.short(v)))),
    h("footer", { class: "dfoot" }, limited.length
      ? [h("span", null, "Busiest network"), h("span", { class: "mono" }, limited[0].name)]
      : [h("span", null, "No network over the limits"), h("span")]));

  const c = st.certificate;
  const days = c.not_after ? Math.floor((new Date(c.not_after) - Date.now()) / 86400e3) : null;
  const certRows = [
    ["Status", c.ready ? (days >= 0 ? "Valid" : "Expired") : c.mode === "off" || !c.mode ? "None" : "Not issued yet", c.ready && days >= 0 ? "ok" : c.mode === "off" || !c.mode ? "" : "warn"],
    ["Name", (c.names || [])[0] || "–"],
    [c.mode === "acme" ? "Renews in" : "Expires in", c.ready ? (c.mode === "acme" ? Math.max(0, days - 30) : days) + " days" : "–"],
    ["Issuer", c.issuer || (c.mode === "acme" ? "Let's Encrypt" : "–")],
    ["Encrypted DNS", ["dot", "doq", "doh", "doh3"].filter((k) => open.includes(k)).map((k) => ({ dot: "DoT", doq: "DoQ", doh: "DoH", doh3: "H3" })[k]).join(" · ") || "off"],
  ];
  const certCard = card("s3", "Certificate", "lock", null,
    h("dl", { class: "kvs" }, certRows.map(([k, v, cls]) => h("div", null, h("dt", null, k), h("dd", { class: (cls || "") + " ellipsis", title: v }, v)))),
    h("footer", { class: "dfoot" }, c.last_error ? h("span", { class: "err ellipsis", title: c.last_error }, c.last_error) : h("span", null, c.mode === "acme" ? "Renewed automatically" : ""),
      h("a", { href: "#/settings/encryption" }, c.ready ? "Settings" : "Set it up")));
  const pv = st.privacy;
  const privRows = [
    ["Query log", pv.query_log ? (pv.query_log_full_ip ? "On, full addresses" : "On") : "Off", pv.query_log ? "warn" : "ok"],
    ["Queries on disk", "Never", "ok"],
    ["Addresses on disk", "Never", "ok"],
    ["Client addresses sent on", "Never", "ok"],
    ["Telemetry", "None", "ok"],
  ];
  const privCard = card("s3", "Privacy", "shieldcheck", null,
    h("dl", { class: "kvs" }, privRows.map(([k, v, cls]) => h("div", null, h("dt", null, k), h("dd", { class: cls }, v)))),
    h("footer", { class: "dfoot" }, h("span", null, "In memory only"), h("a", { href: "#/querylog" }, "Query log")));

  const notServing = st.serves_dns === false ? h("p", { class: "notice warn s12" }, "DNS is not served yet: no address is set. Choose addresses in ", h("a", { href: "#/settings/encryption" }, "Encrypted DNS › Protocols"), " and where answers come from in ", h("a", { href: "#/settings/dns" }, "DNS & upstreams"), ".") : null;
  return [h("div", { class: "dash" }, notServing, k1, k2, k3, k4, chart, flow, top, upCard, evCard,
    topCard("Not Found", "alert", stats.top_nxdomains || [], "Names that do not exist will appear here."),
    rejCard, certCard, privCard)];
}

// with recursion, the upstream card shows resolution instead
function recCard(rec) {
  const checked = rec.secure + rec.insecure + rec.bogus;
  const share = (n) => (checked ? fmt.pct(n / checked) : "–");
  const rows = [
    ["ok", "Signed and verified", rec.dnssec ? share(rec.secure) : "off", "DNSSEC"],
    ["idle", "Not signed", rec.dnssec ? share(rec.insecure) : "–", "the domain does not use DNSSEC"],
    [rec.bogus ? "warn" : "idle", "Failed the check", fmt.short(rec.bogus), "refused (SERVFAIL)"],
    ["cyan", "Queries to name servers", fmt.short(rec.queries), rec.queries ? `${fmt.pct(rec.timeouts / rec.queries)} timed out` : "since start"],
  ];
  if (rec.fallback) rows.push(["idle", "Answered by upstreams", fmt.short(rec.fallbacks), "when no name server answered"]);
  if (rec.intercepted) rows.unshift(["err", "Network answers for name servers", fmt.short(rec.rewritten), "port 53 intercepted: use your own DNSNova elsewhere as upstream"]);
  if (rec.forged) rows.push(["warn", "Forged answers dropped", fmt.short(rec.forged), "a censor on the path; the genuine answers were used"]);
  if (rec.spoofed) rows.push(["warn", "Forged answers stopped", fmt.short(rec.spoofed), "someone sent fake answers; asked again over TCP"]);
  return card("s4", "Resolution", "network", more("#/settings/dns", "Settings"),
    h("ul", { class: "slots" }, rows.slice(0, SLOTS).map(([cls, name, value, note]) => h("li", { class: "slot tall", style: { minHeight: "44px" } },
      h("span", { class: "dot lit " + cls }),
      h("div", { class: "grow" }, h("div", null, name), h("div", { class: "small muted" }, note)),
      h("span", { class: "num strong" }, value)))),
    h("footer", { class: "dfoot" }, h("span", null, "From the root servers"),
      h("span", { class: "num" }, `${fmt.short(rec.cache.zones)} zones · ${fmt.short(rec.cache.servers)} servers`)));
}

// upName: an upstream address as people say it.
function upName(a) {
  try { if (/^\w+:\/\//.test(a)) return new URL(a.replace(/^(tls|quic|udp|tcp):/, "https:")).hostname; } catch (e) { /* fall through */ }
  return a;
}

function miniTrend(vals) {
  const W = 78, H = 24;
  // samples are taken while the overview is open; a dashed line until there are a few
  if (vals.length < 3) return s("svg", { class: "mini", viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true" }, s("line", { class: "base", x1: 2, x2: W - 2, y1: H / 2, y2: H / 2 }));
  const max = Math.max(...vals), min = Math.min(...vals), r = max - min || 1;
  const pts = vals.map((v, i) => [2 + (i * (W - 4)) / (vals.length - 1), H - 3 - ((v - min) / r) * (H - 6)]);
  return s("svg", { class: "mini", viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true" }, s("path", { class: "l", d: smooth(pts, H) }));
}

// flowCard draws how queries move through this node: protocols in, the node,
// and where answers come from. The middle column is where more nodes go when
// DNSNova manages a cluster.
function flowCard(st, stats, ups, total, open, rec, nowRate) {
  const W = 400, H = 262, cx = 196, cy = 120;
  const ins = PROTOS.filter(([k]) => open.includes(k) || stats.queries[k]);
  const inList = ins.length ? ins : PROTOS.slice(0, 2);
  const outs = rec
    ? [{ name: "Root & authoritative", sub: `${fmt.short(rec.cache.servers)} servers`, cls: rec.healthy && !rec.intercepted ? "ok" : "err", w: Math.max(1, rec.queries - (rec.fallbacks || 0)) },
      ...(rec.fallback ? ups.slice(0, 3).map((u) => ({ name: upName(u.address), sub: "fallback", cls: "idle", w: rec.fallbacks || 0 })) : [])]
    : ups.slice(0, 6).map((u) => { const us = upState(u, ups); return { name: upName(u.address), sub: `${u.latency_ms ? fmt.ms(u.latency_ms) + " ms" : "–"} · ${u.role}`, cls: us.cls, w: u.queries }; });
  const outTotal = Math.max(1, sum(outs.map((o) => o.w)));
  const ys = (n) => Array.from({ length: n }, (_, i) => (n === 1 ? cy : 42 + (i * (H - 62)) / (n - 1)));
  const iy = ys(inList.length), oy = ys(Math.max(1, outs.length));
  const links = [], marks = [];
  const trunc = (t, n) => (t.length > n ? t.slice(0, n - 1) + "…" : t);
  inList.forEach(([k, n, d], i) => {
    const c = stats.queries[k] || 0, share = total ? c / total : 0, y = iy[i], on = open.includes(k);
    const path = `M74,${y} C126,${y} 136,${cy} ${cx - 34},${cy}`;
    links.push(s("path", { class: "link cyan", d: path, "stroke-width": (1 + share * 10).toFixed(2) }));
    marks.push(s("circle", { class: "port" + (on ? " on" : ""), cx: 70, cy: y, r: 4 }),
      s("text", { class: "lab", x: 60, y: y - 2, "text-anchor": "end" }, k === "doh3" ? "DoH3" : n),
      s("text", { class: "sub", x: 60, y: y + 11, "text-anchor": "end" }, total ? fmt.pct(share) : on ? d : "off"));
  });
  outs.forEach((o, i) => {
    const y = oy[i], share = o.w / outTotal;
    const path = `M${cx + 34},${cy} C${cx + 58},${cy} ${cx + 66},${y} 290,${y}`;
    links.push(s("path", { class: "link " + (o.cls === "ok" ? "" : o.cls), d: path, "stroke-width": (1 + share * 8).toFixed(2) }));
    marks.push(s("circle", { class: "up " + o.cls, cx: 296, cy: y, r: 6 }),
      s("text", { class: "lab", x: 308, y: y - 2 }, trunc(o.name, 15)),
      s("text", { class: "sub", x: 308, y: y + 11 }, o.sub));
  });
  const [gid, grad] = vgrad("#3b82f6", "#1d4ed8");
  const node = s("g", null,
    s("circle", { class: "node-ring dash", cx, cy, r: 50 }), s("circle", { class: "node-ring", cx, cy, r: 41 }),
    s("circle", { class: "node", cx, cy, r: 32, fill: `url(#${gid})` }),
    // the trident, small, inside the node
    s("g", { transform: `translate(${cx - 16},${cy - 17}) scale(0.5)` },
      s("path", { class: "glyph", d: "M32 13v46M18 17v9c0 7 6 10 14 10s14-3 14-10v-9M25 49h14" }),
      s("path", { class: "glyphf", d: "M32 3l5.5 10h-11zM18 7l4.5 9h-9zM46 7l4.5 9h-9z" })),
    s("text", { class: "lab", x: cx, y: cy + 68, "text-anchor": "middle" }, trunc(st.domains[0] || location.hostname, 26)),
    s("text", { class: "sub", x: cx, y: cy + 81, "text-anchor": "middle" }, `${total ? fmt.rate(nowRate) + " q/s · " : ""}${st.mode}`));
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Queries arrive over ${inList.map(([, n]) => n).join(", ")}; answers come from ${outs.map((o) => o.name).join(", ") || "nowhere yet"}` },
    s("defs", null, grad),
    s("text", { class: "colh", x: 44, y: 14, "text-anchor": "middle" }, "CLIENTS"),
    s("text", { class: "colh", x: cx, y: 14, "text-anchor": "middle" }, "NODE"),
    s("text", { class: "colh", x: 340, y: 14, "text-anchor": "middle" }, rec ? "RESOLUTION" : "UPSTREAMS"),
    links, node, marks);
  const counts = { ok: 0, warn: 0, err: 0, idle: 0 };
  outs.forEach((o) => counts[o.cls]++);
  const rowsL = [["ok", "Healthy", counts.ok], ["warn", "Slow", counts.warn], ["err", "Failing", counts.err]];
  if (counts.idle) rowsL.splice(1, 0, ["idle", rec ? "Fallback" : "Standby", counts.idle]);
  return card("s4 flowcard", "Traffic Flow", "network", h("span", { class: "nodechip", title: "DNSNova runs as one node today" }, h("span", { class: "dot lit ok" }), "1 node"),
    h("div", { class: "flow" }, svg),
    h("div", { class: "legend3" }, rowsL.map(([cls, t, n]) => h("div", null, h("span", { class: "dot lit " + cls }), t, h("span", { class: "num" }, n)))));
}

// trafficChart draws queries per second (or response times) as an area with
// a glowing line, with readable axes and a readout under the pointer.
function trafficChart(ser0, total, range, label, metric) {
  if (ser0.length < 2 || !total) {
    return h("div", { class: "chartempty" },
      s("svg", { viewBox: "0 0 600 120", preserveAspectRatio: "none", "aria-hidden": "true" },
        s("path", { d: "M0 92 C 80 88, 120 60, 200 66 S 330 96, 400 70 S 520 40, 600 52", class: "ghost", "vector-effect": "non-scaling-stroke" })),
      h("div", null, h("strong", null, "Not enough data yet"),
        h("div", { class: "small muted" }, range === "1h" ? "The first points appear after a minute or two of traffic." : "Points here are " + (range === "24h" ? "five minutes" : "an hour") + " apart. Choose 1h to see the first minutes.")));
  }
  const step = stepSeconds(ser0);
  const ser = bucket(ser0, 150);
  const lat = metric === "latency";
  const val = (p) => (lat ? p.latency.p50_ms : p.queries / (step * (p.n || 1)));
  const raw = Math.max(...ser.map((p) => (lat ? p.latency.p95_ms : val(p))), lat ? 1 : 1);
  // four even steps of a round size
  const mag = 10 ** Math.floor(Math.log10(raw / 4)), stepY = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((m) => m * 4 >= raw * 1.05) || 10 * mag;
  const yMax = stepY * 4;
  const W = 1000, H = 300;
  const x = (i) => (i * W) / (ser.length - 1);
  const y = (v) => H - (v / yMax) * H;
  const pts = ser.map((p, i) => [x(i), y(val(p))]);
  const d = smooth(pts, H);
  const [gid, grad] = vgrad("var(--area-top)", "var(--area-bottom)");
  const cursor = s("line", { class: "cursor", x1: 0, x2: 0, y1: 0, y2: H, "vector-effect": "non-scaling-stroke", visibility: "hidden" });
  const xt = [0, 0.2, 0.4, 0.6, 0.8, 1];
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": `${lat ? "Median response time" : "Queries per second"}, ${label}; highest ${lat ? fmt.ms(raw) + " ms" : fmt.rate(raw)}` },
    s("defs", null, grad),
    [0, 1, 2, 3, 4].map((k) => s("line", { class: "grid", x1: 0, x2: W, y1: y(k * stepY), y2: y(k * stepY), "vector-effect": "non-scaling-stroke" })),
    xt.slice(1, -1).map((f) => s("line", { class: "vgrid", x1: f * W, x2: f * W, y1: 0, y2: H, "vector-effect": "non-scaling-stroke" })),
    s("path", { class: "area", d: `${d}L${W},${H}L0,${H}Z`, fill: `url(#${gid})` }),
    lat ? s("path", { class: "p95", d: smooth(ser.map((p, i) => [x(i), y(p.latency.p95_ms)]), H), "vector-effect": "non-scaling-stroke" }) : null,
    s("path", { class: lat ? "p50" : "traffic", d, "vector-effect": "non-scaling-stroke" }),
    cursor);
  const unitOf = (v) => (lat ? (v ? fmt.ms(v) + " ms" : "0") : fmt.rate(v));
  const yaxis = h("div", { class: "yaxis", "aria-hidden": "true" }, [0, 1, 2, 3, 4].map((k) => { const e = h("span", null, unitOf(k * stepY)); e.style.top = (100 - k * 25) + "%"; return e; }));
  const ends = pts[pts.length - 1];
  const endPin = h("span", { class: "pin" });
  endPin.style.left = "100%";
  endPin.style.top = (ends[1] / H) * 100 + "%";
  const hover = h("span", { class: "pin", hidden: true });
  const tip = h("div", { class: "tip", hidden: true });
  const wrap = h("div", { class: "chartwrap" }, svg, endPin, hover, tip);
  const full = range === "7d" || range === "30d" ? "full" : false;
  const xaxis = h("div", { class: "xaxis", "aria-hidden": "true" }, xt.map((f, i) => {
    const p = ser[Math.round(f * (ser.length - 1))];
    const e = h("span", { class: i === 0 ? "first" : i === xt.length - 1 ? "last" : "" }, i === xt.length - 1 ? "now" : fmt.time(p.t, full ? true : false));
    e.style.left = f * 100 + "%";
    return e;
  }));
  const show = (ev) => {
    const r = svg.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width));
    const i = Math.round(f * (ser.length - 1));
    const p = ser[i];
    cursor.setAttribute("x1", x(i));
    cursor.setAttribute("x2", x(i));
    cursor.setAttribute("visibility", "visible");
    hover.hidden = false;
    hover.style.left = (i / (ser.length - 1)) * 100 + "%";
    hover.style.top = (pts[i][1] / H) * 100 + "%";
    fill(tip, h("div", { class: "mono small" }, fmt.time(p.t, full)),
      h("div", null, h("span", { class: "swatch" }), lat ? " median " : " ", h("strong", { class: "num" }, lat ? fmt.ms(p.latency.p50_ms) + " ms" : fmt.rate(val(p)) + " q/s")),
      lat ? h("div", null, h("span", { class: "swatch dash" }), " 95th ", h("strong", { class: "num" }, fmt.ms(p.latency.p95_ms) + " ms")) : h("div", { class: "muted" }, "median " + fmt.ms(p.latency.p50_ms) + " ms"),
      h("div", { class: "muted" }, fmt.int(p.queries) + " queries"));
    tip.hidden = false;
    const left = (i / (ser.length - 1)) * r.width;
    tip.style.left = Math.min(Math.max(0, left - tip.offsetWidth / 2), r.width - tip.offsetWidth) + "px";
  };
  svg.addEventListener("pointermove", show);
  svg.addEventListener("pointerdown", show);
  svg.addEventListener("pointerleave", () => { tip.hidden = true; hover.hidden = true; cursor.setAttribute("visibility", "hidden"); });
  return [h("div", { class: "plot" }, yaxis, wrap, xaxis),
    lat ? h("div", { class: "legend" }, h("span", null, h("span", { class: "swatch" }), "median"), h("span", null, h("span", { class: "swatch dash" }), "95th percentile")) : null];
}

// ---------- upstreams and lookup ----------

function upstreamsPage(main) {
  const body = h("div", { style: { display: "flex", flexDirection: "column", gap: "18px" } }, h("p", { class: "muted" }, "Loading…"));
  main.append(pageHead("Upstreams", "Status"), body);
  const load = async () => {
    try {
      const { upstreams } = await api("GET", "/upstreams");
      noteLatency(upstreams);
      const q = sum(upstreams.map((u) => u.queries)), errs = sum(upstreams.map((u) => u.errors));
      const healthyN = upstreams.filter((u) => u.healthy).length;
      const lats = upstreams.filter((u) => u.healthy && u.role === "primary" && u.latency_ms).map((u) => u.latency_ms);
      const tile = (color, ic, label, value, unit, note) => kpiCard(color, ic, label, value, unit, null, note, null, true);
      fill(body, h("div", { class: "dash" },
        tile("var(--c3)", "shieldcheck", "Healthy", `${healthyN}/${upstreams.length}`, null, healthyN === upstreams.length ? "every upstream answers" : "some upstreams fail"),
        tile("var(--c1)", "bolt", "Primary latency", lats.length ? fmt.ms(sum(lats) / lats.length) : "–", lats.length ? "ms" : null, "average, smoothed"),
        tile("var(--c2)", "layers", "Success rate", q ? fmt.pct(1 - errs / q) : "–", null, `${fmt.int(errs)} errors`),
        tile("var(--c1)", "bars", "Queries sent", fmt.short(q), null, "since start")),
        h("section", { class: "card" }, h("div", { class: "tablewrap" }, h("table", { class: "stack" },
        h("thead", null, h("tr", null, ["State", "Upstream", "Role", "Trend", "Latency", "Queries", "Errors", "Last error"].map((t, i) => h("th", { scope: "col", class: i >= 4 && i <= 6 ? "r" : "" }, t)))),
        h("tbody", null, upstreams.map((u) => h("tr", null,
          h("td", { "data-label": "State" }, (() => { const st = upState(u, upstreams); return h("span", { class: "state " + st.cls }, h("span", { class: "dot " + st.cls }), st.label); })()),
          h("td", { class: "mono head" }, u.address), h("td", { class: "muted", "data-label": "Role" }, u.role),
          h("td", { "data-label": "Trend", title: "Latency while this page is open" }, miniTrend((state.upHist || {})[u.address] || [])),
          h("td", { class: "r num", "data-label": "Latency" }, u.latency_ms ? fmt.ms(u.latency_ms) + " ms" : "–"),
          h("td", { class: "r num", "data-label": "Queries" }, fmt.int(u.queries)),
          h("td", { class: "r num", "data-label": "Errors" }, fmt.int(u.errors) + (u.queries ? ` · ${successRate(u)} ok` : "")),
          h("td", { class: "muted", "data-label": "Last error" }, u.last_error ? fmt.ago(u.last_error) : "never"))))))),
        h("p", { class: "small muted" }, "Latency is smoothed over recent queries. Slow means over 500 ms, or three times slower than the other primaries and over 50 ms. Standby: a fallback, used only when the primaries fail. Change the list in ", h("a", { href: "#/settings/dns" }, "DNS & upstreams"), "; ask each one the same question in ", h("a", { href: "#/tools/lookup" }, "Compare upstreams"), "."));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  };
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible") load(); }, 15000);
}

// ---------- trace and DNSSEC ----------

// hashParams reads ?name=…&type=… after the route.
function hashParams() {
  const q = location.hash.split("?")[1] || "";
  return Object.fromEntries(new URLSearchParams(q));
}

const SEC_STATE = { secure: ["ok", "Secure"], insecure: ["idle", "Not signed"], bogus: ["err", "Failed"], unchecked: ["idle", "Not checked"], exempt: ["warn", "Exempt"] };
// a domain under a negative trust anchor is signed, just not checked
const secOf = (sec, why) => sec === "insecure" && /negative trust anchor/.test(why || "") ? "exempt" : sec;
const secPill = (sec) => { const [cls, label] = SEC_STATE[sec] || ["idle", sec]; return h("span", { class: "state " + cls }, h("span", { class: "dot " + cls }), label); };

function tracePage(main) {
  const p = hashParams();
  const name = h("input", { type: "text", class: "mono", value: p.name || "example.com", "aria-label": "Domain name", spellcheck: "false" });
  name.style.maxWidth = "none";
  const type = h("select", { "aria-label": "Record type" }, ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "HTTPS", "CAA", "SOA", "DS", "DNSKEY", "PTR"].map((t) => h("option", { selected: (p.type || "A") === t }, t)));
  type.style.maxWidth = "120px";
  const subnet = h("input", { type: "text", class: "mono", value: p.subnet || "", placeholder: "e.g. 219.141.140.0/24", "aria-label": "As seen from network (optional)", spellcheck: "false" });
  subnet.style.maxWidth = "220px";
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "18px" } });
  const btn = h("button", { type: "submit", class: "btn primary" }, "Trace");
  const run = async () => {
    btn.disabled = true;
    fill(out, h("p", { class: "muted" }, "Asking the name servers… this can take a few seconds."));
    try {
      const r = await api("POST", "/tools/trace", { name: name.value, type: type.value, subnet: subnet.value });
      fill(out, traceView(r));
    } catch (e) { fill(out, errorBox(e)); }
    btn.disabled = false;
  };
  main.append(pageHead("Trace a lookup", "Tools"),
    h("section", { class: "card" },
      h("p", { class: "muted", style: { margin: 0 } }, "Resolves the name from scratch, without the cache, and shows every step: which server was asked, what it answered, and the DNSSEC check of each zone. Use it to see why a name fails."),
      h("form", { class: "row", style: { alignItems: "center" }, onsubmit: (ev) => { ev.preventDefault(); run(); } },
        h("div", { style: { flex: "1 1 260px" } }, name), type, btn),
      h("details", { class: "adv", open: !!p.subnet }, h("summary", null, "As seen from another network"),
        h("label", { class: "small", style: { display: "grid", gap: "6px", marginTop: "8px" } },
          "Client network sent to name servers (EDNS Client Subnet), to see what they answer for it. An address stands for its /24 or /56.", subnet))),
    out);
  if (p.name) run(); else name.focus();
}

function traceView(r) {
  const ok = !r.error && r.rcode !== "SERVFAIL";
  const summary = h("section", { class: "card" },
    h("h2", null, h("span", { class: "mono" }, r.name), " ", h("span", { class: "muted small" }, r.type)),
    h("dl", { class: "kvs" },
      h("div", null, h("dt", null, "Result"), h("dd", { class: ok ? "ok" : "err" }, r.rcode + (r.error ? " · " + r.error : ""))),
      h("div", null, h("dt", null, "DNSSEC"), h("dd", null, secPill(secOf(r.dnssec, r.why)), r.ede ? h("span", { class: "muted small" }, " " + r.ede) : null)),
      r.why ? h("div", null, h("dt", null, "Why"), h("dd", { class: "small", style: { whiteSpace: "normal" } }, r.why)) : null,
      h("div", null, h("dt", null, r.dnssec === "bogus" ? "Answer (refused: clients get SERVFAIL)" : "Answer"), h("dd", { class: "mono small", style: { whiteSpace: "normal" } }, (r.answers || []).length ? r.answers.map((a) => h("div", null, a)) : "none")),
      r.subnet ? h("div", null, h("dt", null, "As seen from"), h("dd", { class: "mono" }, r.subnet)) : null,
      h("div", null, h("dt", null, "Work"), h("dd", null, `${fmt.int(r.queries)} queries · ${fmt.ms(r.ms)} ms`))));
  const kindLabel = { query: "Asked", cname: "Alias", keys: "Keys", validate: "Checked" };
  const rows = (r.steps || []).map((s) => h("tr", null,
    h("td", { class: "r num muted", "data-label": "At" }, fmt.ms(s.ms) + " ms"),
    h("td", { "data-label": "Step", style: { paddingLeft: 12 + 18 * s.depth + "px" } }, h("strong", null, kindLabel[s.kind] || s.kind),
      s.zone ? h("span", { class: "muted small" }, " " + s.zone) : null),
    h("td", { class: "mono small", "data-label": "Server" }, s.server || ""),
    h("td", { class: "mono small", "data-label": "Question" }, s.name ? `${s.name} ${s.type || ""}` : ""),
    h("td", { "data-label": "Outcome", style: { whiteSpace: "normal" } }, s.dnssec ? [secPill(secOf(s.dnssec, s.why)), " "] : null, s.result,
      s.why ? h("div", { class: "small muted" }, s.why) : null),
    h("td", { class: "r num", "data-label": "Time" }, s.rtt_ms ? fmt.ms(s.rtt_ms) + " ms" : "")));
  return [summary,
    h("section", { class: "card" }, h("h2", null, "Steps"),
      h("div", { class: "tablewrap" }, h("table", { class: "stack" },
        h("thead", null, h("tr", null, ["At", "Step", "Server", "Question", "Outcome", "Time"].map((t, i) => h("th", { scope: "col", class: i === 0 || i === 5 ? "r" : "" }, t)))),
        h("tbody", null, rows))),
      r.truncated ? h("p", { class: "small muted" }, "Only the first steps are shown.") : null,
      h("p", { class: "small muted" }, "Indented steps were needed on the way: name server addresses, and each zone's DS and DNSKEY records. A zone's keys are trusted when they match the DS record signed by its parent; a failed check stops there."))];
}

// setList changes one list setting through the normal path (preview, history).
async function setList(key, fn) {
  const cfg = await api("GET", "/config");
  const cur = (cfg.settings.find((x) => x.key === key) || {}).value || [];
  await api("PATCH", "/config", { hash: cfg.hash, set: { [key]: fn(cur) } });
}

// ntaGuess suggests the domain to exempt: the failing name's last two
// labels (three under a short second level such as co.uk).
function ntaGuess(name) {
  const l = name.replace(/\.$/, "").split(".");
  const keep = l.length >= 3 && l[l.length - 2].length <= 3 && l[l.length - 1].length === 2 ? 3 : 2;
  return l.slice(-keep).join(".");
}

function dnssecPage(main) {
  const body = h("div", { style: { display: "flex", flexDirection: "column", gap: "18px" } }, h("p", { class: "muted" }, "Loading…"));
  main.append(pageHead("DNSSEC", "Status"), body);
  const load = async () => {
    try {
      const d = await api("GET", "/dnssec");
      state.dnssec = d;
      if (!d.recursion) {
        fill(body, h("section", { class: "card" }, h("p", { style: { margin: 0 } }, "This server forwards to upstreams, which check DNSSEC themselves. Turn on ", h("a", { href: "#/settings/dns" }, "Resolve names itself"), " to check it here.")));
        return;
      }
      const total = d.secure + d.insecure + d.bogus;
      const share = (n) => total ? fmt.pct(n / total) : "–";
      const tile = (color, ic, label, value, note) => kpiCard(color, ic, label, value, null, null, note, null, true);
      const editor = (f, row) => {
        const input = h("input", { type: "text", class: "mono", value: ntaGuess(f.name), "aria-label": "Domain to stop validating" });
        input.style.maxWidth = "220px";
        const save = h("button", { type: "button", class: "btn small primary", onclick: async () => {
          save.disabled = true;
          try {
            const dom = input.value.trim().replace(/\.$/, "").toLowerCase();
            await setList("recursion.negative_trust_anchors", (cur) => cur.includes(dom) ? cur : [...cur, dom]);
            toast(`${dom}: no longer validated`);
            load();
          } catch (e) { toast(e.message, "err"); save.disabled = false; }
        } }, "Stop validating");
        fill(row, h("td", { colspan: 6 }, h("div", { class: "row", style: { alignItems: "center", gap: "8px" } },
          h("span", { class: "small" }, "Stop validating this domain and everything under it:"), input, save,
          h("button", { type: "button", class: "btn small", onclick: () => load() }, "Cancel")),
          h("p", { class: "small muted", style: { margin: "6px 0 0" } }, "Only when the domain's own DNSSEC is broken and its owner is fixing it: its answers then reach clients unchecked, so a forged one would too. Remove it once the domain validates again.")));
      };
      fill(body,
        h("div", { class: "dash" },
          tile("var(--c3)", "shieldcheck", "Secure", share(d.secure), `${fmt.int(d.secure)} answers signed and checked`),
          tile("var(--c1)", "layers", "Not signed", share(d.insecure), `${fmt.int(d.insecure)} answers from unsigned domains`),
          tile("var(--c4)", "alert", "Failed", share(d.bogus), `${fmt.int(d.bogus)} answers refused`),
          tile("var(--c2)", "file", "Exempt domains", String(d.negative_trust_anchors.length), "not validated, on purpose")),
        d.enabled ? null : h("p", { class: "notice warn" }, "DNSSEC checking is off: answers are not checked, so forged ones can get through. Turn it on in ", h("a", { href: "#/settings/dns" }, "DNS & upstreams"), "."),
        h("section", { class: "card" },
          h("div", { class: "row", style: { alignItems: "center", justifyContent: "space-between" } }, h("h2", { style: { margin: 0 } }, "Names that failed"),
            d.failures.length ? h("button", { type: "button", class: "btn small", onclick: async () => { await api("DELETE", "/dnssec/failures"); load(); } }, "Clear list") : null),
          d.failures.length ? h("div", { class: "tablewrap" }, h("table", { class: "stack" },
            h("thead", null, h("tr", null, ["Name", "Reason", "Refused", "Last", "", ""].map((t, i) => h("th", { scope: "col", class: i === 2 ? "r" : "" }, t)))),
            h("tbody", null, d.failures.map((f) => {
              const row = h("tr", null,
                h("td", { class: "mono head" }, f.name, h("span", { class: "muted small" }, " " + f.type)),
                h("td", { "data-label": "Reason", style: { whiteSpace: "normal" } }, h("strong", { class: "err" }, f.ede), h("div", { class: "small muted" }, f.why)),
                h("td", { class: "r num", "data-label": "Refused" }, fmt.int(f.count) + "×"),
                h("td", { class: "muted", "data-label": "Last" }, fmt.ago(f.last)),
                h("td", null, h("a", { class: "btn small", href: `#/tools/trace?name=${encodeURIComponent(f.name)}&type=${encodeURIComponent(f.type)}` }, "Trace")),
                h("td", null, h("button", { type: "button", class: "btn small", onclick: () => editor(f, row) }, "Stop validating…")));
              return row;
            })))) : h("p", { class: "muted", style: { margin: 0 } }, "None since the server started (or since the list was cleared)."),
          h("p", { class: "small muted" }, "Names whose answers failed the DNSSEC check (clients got SERVFAIL). Usually the owner broke it: expired signatures, a failed key rollover. Several unrelated domains at once can mean answers are tampered with on the way. No client addresses are kept.")),
        h("section", { class: "card" }, h("h2", null, "Domains not validated"),
          d.negative_trust_anchors.length ? h("div", { class: "tablewrap" }, h("table", null, h("tbody", null, d.negative_trust_anchors.map((n) => h("tr", null,
            h("td", { class: "mono" }, n),
            h("td", { class: "r" }, h("button", { type: "button", class: "btn small", onclick: async () => {
              try { await setList("recursion.negative_trust_anchors", (cur) => cur.filter((x) => x !== n)); toast(`${n}: validated again`); load(); } catch (e) { toast(e.message, "err"); }
            } }, "Validate again")))))))
            : h("p", { class: "muted", style: { margin: 0 } }, "None. Every signed domain is checked."),
          h("p", { class: "small muted" }, "Negative trust anchors (RFC 7646): domains whose answers are passed on without the DNSSEC check. They are kept in recursion.negative_trust_anchors, with the other settings and their history.")));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  };
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible" && !body.querySelector("input")) load(); }, 15000);
}

// ---------- nodes (cluster) ----------

function nodesPage(main) {
  const body = h("div", { style: { display: "flex", flexDirection: "column", gap: "18px" } }, h("p", { class: "muted" }, "Loading…"));
  main.append(pageHead("Nodes", "Status"), body);
  const stateOf = (n) => !n.online ? ["err", "Offline"] : n.status === "ok" ? ["ok", "Healthy"] : n.status === "setup" ? ["idle", "Not set up"] : ["err", "Unhealthy"];
  const pill = ([cls, label]) => h("span", { class: "state " + cls }, h("span", { class: "dot " + cls }), label);
  const certCell = (t) => {
    if (!t) return h("span", { class: "muted" }, "–");
    const days = Math.floor((new Date(t).getTime() - Date.now()) / 86400000);
    return h("span", { class: days < 14 ? "warn" : "" }, days < 0 ? "expired" : `${days} days`);
  };
  const load = async () => {
    try {
      const c = await api("GET", "/cluster");
      state.cluster = c;
      if (!c.role) {
        fill(body, h("section", { class: "card" }, h("p", { style: { margin: 0 } }, "This server runs on its own. To share its settings with other DNSNova servers, make it a cluster primary in its configuration file; see docs/cluster.md.")));
        return;
      }
      if (c.role === "follower") {
        const ok = !c.sync_error;
        fill(body, h("section", { class: "card" },
          h("h2", null, c.name, c.region ? h("span", { class: "muted small" }, " · " + c.region) : null),
          h("dl", { class: "kvs" },
            h("div", null, h("dt", null, "Follows"), h("dd", { class: "mono" }, (c.primary_name ? c.primary_name + " · " : "") + c.primary)),
            h("div", null, h("dt", null, "Last sync"), h("dd", null, pill(ok ? ["ok", "In touch"] : ["err", "Not in touch"]), " ", fmt.ago(c.last_sync))),
            h("div", null, h("dt", null, "Settings version"), h("dd", { class: "mono" }, c.config_hash ? c.config_hash.slice(0, 12) : "–")),
            h("div", null, h("dt", null, "Set on this node"), h("dd", { class: "mono small" }, (c.overrides || []).join(", ") || "nothing"))),
          ok ? null : h("p", { class: "notice warn small" }, c.sync_error, " This node keeps answering with the last settings it had.")));
        return;
      }
      const nodes = c.nodes || [];
      const online = nodes.filter((n) => n.online).length, insync = nodes.filter((n) => n.in_sync).length;
      const versions = [...new Set(nodes.map((n) => n.version))];
      const tile = (color, ic, label, value, note) => kpiCard(color, ic, label, value, null, null, note, null, true);
      fill(body, h("div", { class: "dash" },
        tile("var(--c3)", "network", "Online", `${online}/${nodes.length}`, online === nodes.length ? "every node checks in" : "some nodes missed their syncs"),
        tile("var(--c1)", "file", "Same settings", `${insync}/${nodes.length}`, insync === nodes.length ? "every node runs the current settings" : "some nodes are behind or refused them"),
        tile("var(--c2)", "layers", "Versions", String(versions.length), versions.length === 1 ? versions[0] : versions.join(", ")),
        tile("var(--c4)", "shieldcheck", "Healthy", String(nodes.filter((n) => n.online && n.status === "ok").length), "can resolve")),
        h("section", { class: "card" }, h("div", { class: "tablewrap" }, h("table", { class: "stack" },
          h("thead", null, h("tr", null, ["State", "Node", "Region", "Address", "Settings", "Anycast", "Version", "Certificate", "Last seen"].map((t) => h("th", { scope: "col" }, t)))),
          h("tbody", null, nodes.map((n) => h("tr", null,
            h("td", { "data-label": "State" }, pill(stateOf(n))),
            h("td", { class: "head" }, n.name, n.self ? h("span", { class: "muted small" }, " (this node)") : null),
            h("td", { class: "muted", "data-label": "Region" }, n.region || "–"),
            h("td", { class: "mono small", "data-label": "Address" }, n.address || "–"),
            h("td", { "data-label": "Settings", title: n.config_error || (n.overrides || []).join(", ") }, n.config_error ? h("span", { class: "err" }, "Refused") : n.in_sync ? "Current" : h("span", { class: "warn" }, "Behind")),
            h("td", { "data-label": "Anycast" }, n.anycast === "announced" ? pill(["ok", "Announced"]) : n.anycast === "withdrawn" ? pill(["warn", "Withdrawn"]) : h("span", { class: "muted" }, "–")),
            h("td", { class: "mono small" + (versions.length > 1 && n.version !== nodes[0].version ? " warn" : ""), "data-label": "Version" }, n.version),
            h("td", { "data-label": "Certificate" }, certCell(n.cert_until)),
            h("td", { class: "muted", "data-label": "Last seen" }, n.self ? "now" : fmt.ago(n.last_seen)))))))),
        h("p", { class: "small muted" }, "Followers sync every few seconds and are offline after three missed syncs. Settings changed here reach every node; settings in a node's own file stay its own. Behind: not yet on the current settings. Refused: they do not work on that node (hover for why); it keeps the last working ones."));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  };
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible") load(); }, 10000);
}

function lookupTable(results) {
  return h("div", { class: "tablewrap" }, h("table", null,
    h("thead", null, h("tr", null, h("th", { scope: "col" }, "Upstream"), h("th", { scope: "col" }, "Result"), h("th", { scope: "col", class: "r" }, "Time"))),
    h("tbody", null, results.map((r) => h("tr", null,
      h("td", { class: "mono small" }, r.upstream),
      h("td", null, r.error ? h("span", { class: "err" }, r.error)
        : [h("strong", { class: r.rcode === "NOERROR" ? "ok" : "warn" }, r.rcode), (r.answers || []).length ? h("div", { class: "mono small" }, r.answers.map((a) => h("div", null, a))) : h("div", { class: "small muted" }, "no records")]),
      h("td", { class: "r num" }, r.error && !r.ms ? "–" : fmt.ms(r.ms) + " ms"))))));
}

function lookupPage(main) {
  const name = h("input", { type: "text", class: "mono", value: "example.com", "aria-label": "Domain name", spellcheck: "false" });
  name.style.maxWidth = "none";
  const type = h("select", { "aria-label": "Record type" }, ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "HTTPS", "CAA", "SOA", "PTR"].map((t) => h("option", null, t)));
  type.style.maxWidth = "120px";
  const out = h("div");
  const btn = h("button", { type: "submit", class: "btn primary" }, "Ask every upstream");
  main.append(pageHead("Compare upstreams", "Tools"),
    h("section", { class: "card" },
      h("p", { class: "muted", style: { margin: 0 } }, "Sends the question to each upstream directly, without the cache, and shows what each one answers and how long it takes."),
      h("form", {
        class: "row", style: { alignItems: "center" }, onsubmit: async (ev) => {
          ev.preventDefault();
          btn.disabled = true;
          fill(out, h("p", { class: "muted" }, "Asking…"));
          try {
            const r = await api("POST", "/tools/lookup", { name: name.value, type: type.value });
            fill(out, lookupTable(r.results));
          } catch (e) { fill(out, errorBox(e)); }
          btn.disabled = false;
        },
      }, h("div", { style: { flex: "1 1 260px" } }, name), type, btn), out));
  name.focus();
}

// ---------- query log ----------

const QL_LENGTHS = [[15, "15 minutes"], [60, "1 hour"], [360, "6 hours"], [1440, "24 hours"]];

function queryLogPage(main) {
  const head = h("section", { class: "card" });
  const filter = h("input", { type: "search", placeholder: "Filter by domain or client", "aria-label": "Filter by domain or client", spellcheck: "false" });
  const table = h("div");
  main.append(pageHead("Query log", "Status"), head, h("section", { class: "card" }, h("div", { class: "row", style: { alignItems: "center" } }, h("div", { style: { flex: "1 1 260px" } }, filter)), table));
  let st = null, timer = null;
  const drawHead = () => {
    if (st.on) {
      fill(head,
        h("div", { class: "pagehead" }, h("h2", null, h("span", { class: "dot warn", style: { marginRight: "8px" } }), "Recording"),
          h("button", { type: "button", class: "btn danger", onclick: stop }, "Stop and delete")),
        h("p", { style: { margin: 0 } }, `Stops by itself at ${fmt.time(st.until, "full")}. `,
          st.full_ip ? h("strong", { class: "warn" }, "Full client addresses are being kept.") : "Client addresses are shortened (203.0.113.x, 2001:db8:1::/48)."),
        h("p", { class: "small muted", style: { margin: 0 } }, `Kept in memory only, at most ${fmt.int(10000)} queries. Starting it is recorded in the service log, and the overview shows that it is on.`));
      return;
    }
    const len = h("select", { "aria-label": "How long" }, QL_LENGTHS.map(([v, t]) => h("option", { value: v }, t)));
    len.value = "60";
    len.style.maxWidth = "160px";
    const full = h("input", { type: "checkbox" });
    const err = h("p", { class: "err small", role: "alert" });
    fill(head,
      h("h2", null, "The query log is off"),
      h("p", { style: { margin: 0 } }, "Turn it on to see each query as it arrives, for troubleshooting. It runs for the time you choose and then stops by itself. Nothing is written to disk, and a restart clears it."),
      st.count ? h("p", { class: "small muted", style: { margin: 0 } }, `The ${fmt.int(st.count)} queries below are from the last run; they are deleted an hour after it stopped.`) : null,
      h("div", { class: "row", style: { alignItems: "center" } }, h("label", { class: "small" }, "Run for "), len,
        h("label", { class: "check", style: { flex: "1 1 260px" } }, full, h("span", null, "Keep full client addresses (normally the last part is hidden)"))),
      err,
      h("div", null, h("button", {
        type: "button", class: "btn primary", onclick: async () => {
          try {
            const r = await api("POST", "/querylog", { minutes: Number(len.value), full_ip: full.checked });
            st = r.state;
            drawHead();
            load();
          } catch (e) { err.textContent = e.message; }
        },
      }, "Start the query log")));
  };
  const stop = async () => {
    try { await api("DELETE", "/querylog"); toast("Query log stopped and deleted"); load(); } catch (e) { toast(e.message, "err"); }
  };
  const load = async () => {
    try {
      const r = await api("GET", "/querylog?limit=500&q=" + encodeURIComponent(filter.value));
      const was = st && st.on;
      st = r.state;
      if (!head.childNodes.length || was !== st.on) drawHead();
      fill(table, r.entries.length ? h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Time", "Client", "Protocol", "Domain", "Type", "Result", "From", "Time taken"].map((t, i) => h("th", { scope: "col", class: i === 7 ? "r" : "" }, t)))),
        h("tbody", null, r.entries.map((q) => h("tr", null,
          h("td", { class: "mono small" }, new Date(q.time).toLocaleTimeString([], { hour12: false })),
          h("td", { class: "mono small" }, q.client), h("td", { class: "small" }, q.proto, q.filtered ? h("span", { class: "tag", title: "Through the filtered service" }, "filtered") : null),
          h("td", { class: "mono small ellipsis", title: q.name }, q.name), h("td", { class: "small" }, q.type),
          h("td", { class: "small " + (q.rcode === "NOERROR" ? "" : "warn") }, q.rcode),
          h("td", { class: "small " + (q.source === "blocked" ? "warn" : "muted") }, q.source,
            q.source === "blocked" ? h("button", { type: "button", class: "btn link small", title: "Never block " + q.name, onclick: () => allowDomain(q.name).catch((e) => toast(e.message, "err")) }, "Allow") : null),
          h("td", { class: "r num small" }, (q.ms ? fmt.ms(q.ms) : "<0.1") + " ms"))))))
        : h("p", { class: "empty small", style: { margin: 0 } }, st.on ? (filter.value ? "No queries match." : "Waiting for queries…") : "No queries recorded."));
    } catch (e) { if (e.status !== 401) fill(table, errorBox(e)); }
  };
  let deb;
  filter.addEventListener("input", () => { clearTimeout(deb); deb = setTimeout(load, 250); });
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible" && st && st.on) load(); }, 5000);
}

// ---------- setup guide ----------

function guidePage(main) {
  const body = h("div", { style: { display: "flex", flexDirection: "column", gap: "16px" } }, h("p", { class: "muted" }, "Loading…"));
  main.classList.add("narrow");
  main.append(pageHead("Setup guide", "Tools"), body);
  const copyrow = (k, v) => h("div", { class: "copyrow" }, h("span", { class: "k" }, k), h("code", null, v), h("button", { type: "button", class: "btn small", onclick: () => copy(v) }, "Copy"));
  (async () => {
    try {
      const info = await api("GET", "/guide");
      if (!(info.plain || []).length && !info.doh && !info.dot) {
        fill(body, h("p", { class: "notice" }, "DNS is not listening on any address yet. Choose addresses in ", h("a", { href: "#/settings/access" }, "Access & limits"), "."));
        return;
      }
      const addrs = [...(info.plain || []).map((ip) => ["DNS server", ip]), info.doh ? ["DNS over HTTPS", info.doh] : null, info.dot ? ["DNS over TLS", info.dot] : null, info.doq ? ["DNS over QUIC", info.doq] : null].filter(Boolean);
      const filt = filtered(info, { h, copyrow }, info.profile);
      fill(body,
        h("section", { class: "card" }, h("h2", null, "Addresses"), h("div", { class: "addrs" }, addrs.map(([k, v]) => copyrow(k, v))),
          info.port && info.port !== 53 ? h("p", { class: "notice warn small", style: { margin: 0 } }, `Plain DNS is on port ${info.port}. Most phones, computers and routers can only use port 53; set the port where they allow it.`) : null),
        filt ? h("section", { class: "card" }, h("h2", null, "Addresses with filtering"), ...filt) : null,
        h("section", { class: "card" }, h("h2", null, "Point a device or your router at DNSNova"),
          h("p", { class: "small muted", style: { margin: 0 } }, "Setting it once on the router covers every device on the network. Set it on a device to use it there only, or when away from home with encrypted DNS."),
          ...tabs(guides(info, { h, copyrow }), { h, fill })));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  })();
}

// ---------- settings ----------

// Field types: text, list (one per line), bool, number, select, listen (a
// switch that fills a listen list from server.listen with a port).
// upstream settings matter without recursion, or as its fallback
const upShown = (v) => !v["recursion.enabled"] || v["recursion.fallback"];

const SETTINGS = {
  dns: {
    title: "DNS & upstreams",
    sections: [
      { title: "Resolution", fields: [
        { key: "recursion.enabled", label: "Resolve names itself", type: "bool", help: "Ask the root servers and each domain\u2019s own name servers directly, instead of upstreams. No third party sees the queries, and answers are checked with DNSSEC." },
        { key: "recursion.dnssec", label: "Check DNSSEC", type: "bool", help: "Answers that fail the check are refused rather than passed on. Leave it on.", show: (v) => v["recursion.enabled"] },
        { key: "recursion.qname_minimisation", label: "Minimal names", type: "bool", help: "Each server is told only the part of the name it needs: the root sees \u201ccom\u201d, not the whole name.", show: (v) => v["recursion.enabled"] },
        { key: "recursion.fallback", label: "Fall back to upstreams", type: "bool", help: "When no name server of a domain can be reached, ask the upstreams below. Never after a failed DNSSEC check.", show: (v) => v["recursion.enabled"] },
        { key: "recursion.ipv6", label: "Use IPv6", type: "bool", help: "Also reach name servers over IPv6, when this server has it.", show: (v) => v["recursion.enabled"] },
        { key: "recursion.cookies", adv: true, label: "DNS Cookies with name servers", type: "bool", help: "Send each name server a cookie and check the one it returns (RFC 7873). A UDP answer with the wrong cookie, or none from a server that always sends one, is dropped as forged.", show: (v) => v["recursion.enabled"] },
        { key: "recursion.negative_trust_anchors", adv: true, label: "Domains not validated", type: "list", help: "Negative trust anchors (RFC 7646): domains with broken DNSSEC, answered without validation. Remove each once fixed. The DNSSEC page lists failures.", show: (v) => v["recursion.enabled"] && v["recursion.dnssec"] },
        { key: "recursion.allow_networks", label: "Private networks to query", type: "list", help: "Networks with your own name servers, such as 10.0.0.0/8. A public server otherwise never sends queries into private networks.", show: (v) => v["recursion.enabled"] },
        { key: "ecs.address", label: "Answer as if from (client subnet)", type: "text", placeholder: "off", help: "A public IP address or network. Name servers answer as they would for it (EDNS Client Subnet); your clients\u2019 addresses are never sent. Empty: off." },
      ] },
      { title: "Upstreams", fields: [
        { key: "upstream.primary", label: "Primary upstreams", type: "list", help: "Asked in parallel; the fastest answer wins. https://…/dns-query, h3://…/dns-query (HTTP/3), tls://host, quic://host, udp://IP or an IP address. With recursion, a fallback only.", show: upShown },
        { key: "upstream.fallback", label: "Fallback upstreams", type: "list", help: "Used only when every primary fails or is slow.", show: upShown },
        { key: "upstream.bootstrap", adv: true, label: "Bootstrap servers", type: "list", help: "Plain DNS servers (IP addresses) used only to find the upstreams' own addresses.", show: upShown },
        { key: "upstream.parallel", adv: true, label: "Ask at once", type: "number", help: "How many primaries to ask in parallel.", show: upShown },
        { key: "upstream.timeout", adv: true, label: "Timeout", type: "text", help: "How long to wait for an upstream, such as 3s.", show: upShown },
        { key: "upstream.fallback_delay", adv: true, label: "Fallback delay", type: "text", help: "Ask the fallbacks if the primaries have not answered after this long.", show: upShown },
      ] },
      { title: "Cache", action: ["Clear cache", async () => { await api("POST", "/cache/clear"); toast("Cache cleared"); }], fields: [
        { key: "cache.size", label: "Size", type: "number", help: "Most answers kept." },
        { key: "cache.prefetch", adv: true, label: "Prefetch", type: "bool", help: "Refresh popular answers shortly before they expire." },
        { key: "cache.persist", adv: true, label: "Keep across restarts", type: "select", options: [["auto", "Automatic: yes for a public server, no for a home or office network"], ["on", "Yes"], ["off", "No"]], help: "Save the cache every 10 minutes and on shutdown, and load it at start, so answers stay fast after a restart. The file lists names looked up, never by whom; with few users, as at home, that is close to their browsing history. Deleted when off." },
        { key: "cache.serve_stale", adv: true, label: "Serve stale", type: "text", help: "Keep answering from expired entries this long when upstreams fail (0s = off)." },
        { key: "cache.min_ttl", adv: true, label: "Minimum TTL", type: "text", help: "Answers are kept at least this long." },
        { key: "cache.max_ttl", adv: true, label: "Maximum TTL", type: "text", help: "Answers are kept at most this long." },
        { key: "cache.max_negative_ttl", adv: true, label: "Maximum negative TTL", type: "text", help: "Longest time to remember that a name does not exist." },
      ] },
      { title: "Local names", fields: [
        { key: "local.records", label: "Names answered here", type: "list", help: "One per line: a name and an address, such as \u201cnas.home 192.168.1.5\u201d. \u201c*.dev.home\u201d covers every name under dev.home. For IPv4 and IPv6, use two lines. 0.0.0.0 blocks a name." },
      ] },
      { title: "Clients", fields: [
        { key: "ddr.enabled", label: "Discovery (DDR)", type: "bool", help: "Devices asking over plain DNS learn the encrypted addresses and switch automatically." },
      ] },
    ],
  },
  filter: {
    title: "Filtering",
    filterStatus: true,
    sections: [
      { title: "Filtered service", fields: [
        { key: "filter.enabled", label: "Filtering", type: "bool", help: "Offer a second way in that blocks ads, trackers and malicious sites. The usual addresses answer as before; people choose which one to use." },
        { key: "filter.doh_path", label: "DoH path", type: "text", help: "DNS over HTTPS with filtering: the usual address with this path instead of the usual one.", show: (v) => v["filter.enabled"] && !v["filter.all"] },
        { key: "filter.names", label: "Names", type: "list", help: "For DNS over TLS and QUIC (and HTTPS), such as filtered.dns.example.com. Point each at this server; Let\u2019s Encrypt certificates include them.", show: (v) => v["filter.enabled"] && !v["filter.all"] },
        { key: "filter.listen", label: "Plain DNS addresses", type: "list", help: "Addresses that filter plain DNS (UDP and TCP), such as a second IP address with port 53. Not the same as the usual DNS addresses.", show: (v) => v["filter.enabled"] && !v["filter.all"] },
        { key: "filter.all", label: "Filter every address", type: "bool", help: "For a home or office server where everyone should be filtered.", show: (v) => v["filter.enabled"] },
      ] },
      { title: "Lists", action: ["Update now", async () => { const st = await api("POST", "/filter/update"); toast(`${st.rules.toLocaleString()} rules in force`); }], fields: [
        { key: "filter.lists", label: "Block lists", type: "list", help: "List URLs, one per line: adblock domain rules, hosts files or plain domains. Preset: ShieldNova, with few false positives, free to use in DNSNova, commercially too (other uses need its license).", show: (v) => v["filter.enabled"] },
        { key: "filter.update_interval", adv: true, label: "Update every", type: "text", help: "Such as 24h. A failed or much shorter download keeps the copy in use.", show: (v) => v["filter.enabled"] },
      ] },
      { title: "Your rules", fields: [
        { key: "filter.allow", label: "Never block", type: "list", help: "One domain per line; covers every name under it and wins over every list. Use it when something stops working.", show: (v) => v["filter.enabled"] },
        { key: "filter.block", label: "Also block", type: "list", help: "One domain per line; covers every name under it.", show: (v) => v["filter.enabled"] },
      ] },
    ],
  },
  encryption: {
    title: "Encrypted DNS",
    certificate: true,
    sections: [
      { title: "Domain & certificate", fields: [
        { key: "tls.domains", label: "Domain", type: "list", placeholder: "dns.example.com", help: "Names whose A or AAAA record points here, such as dns.example.com, for DNS over HTTPS, TLS and QUIC. One per line; the first is shown to clients. Empty: no encrypted DNS.",
          then: (v) => {
            if (v["tls.domains"].length && v["tls.certificate"] === "off") v["tls.certificate"] = "acme";
            // a domain with no encrypted protocol on would do nothing: turn them on
            if (v["tls.domains"].length && !v["dot.listen"].length && !v["doq.listen"].length && !v["doh.https_listen"].length) Object.assign(v, encryptedListen(v["server.listen"]));
            // no domain, no encrypted DNS
            if (!v["tls.domains"].length && v["tls.certificate"] === "acme") Object.assign(v, { "tls.certificate": "off", "dot.listen": [], "doq.listen": [], "doh.https_listen": [] });
          } },
        { key: "tls.certificate", label: "Certificate", type: "select", options: [["acme", "Let's Encrypt (automatic, free)"], ["files", "My own certificate files"], ["off", "None (no encrypted DNS)"]], help: "Where the certificate for the domain comes from. One certificate serves DNS over HTTPS, TLS and QUIC." },
        { key: "tls.email", label: "Email", type: "text", help: "Let's Encrypt writes here before a certificate expires (optional).", show: (v) => v["tls.certificate"] === "acme" },
        { key: "tls.challenge", label: "Domain check", type: "select", options: [["", "Automatic (recommended)"], ["tls-alpn-01", "Through port 443"], ["http-01", "Through port 80"]], help: "How Let's Encrypt confirms the domain at each issue and renewal. Automatic: port 443 when DNS over HTTPS uses it, otherwise port 80. The port must be open to the internet.", show: (v) => v["tls.certificate"] === "acme" },
        { key: "tls.ip_addresses", adv: true, label: "Include IP addresses", type: "bool", help: "Lets clients switch to encrypted DNS automatically. Such certificates are renewed every few days.", show: (v) => v["tls.certificate"] === "acme" },
        { key: "tls.cert_file", label: "Certificate file", type: "text", help: "PEM file with the full chain; reloaded when it changes.", show: (v) => v["tls.certificate"] === "files" },
        { key: "tls.key_file", label: "Key file", type: "text", help: "Its private key. DNSNova must be able to read it.", show: (v) => v["tls.certificate"] === "files" },
      ] },
      { title: "Protocols", fields: [
        { key: "server.listen", label: "Plain DNS", type: "list", help: "UDP and TCP, port 53 (devices and routers cannot use another). List each address rather than 0.0.0.0, and keep 127.0.0.1:53 for this machine. For encrypted DNS only, use 127.0.0.1:53 alone." },
        { key: "dot.listen", label: "DNS over TLS", type: "listen", port: 853, help: "Android Private DNS, iOS and most routers. TCP 853." },
        { key: "doq.listen", label: "DNS over QUIC", type: "listen", port: 853, help: "Faster on mobile networks; fewer clients support it. UDP 853." },
        { key: "doh.https_listen", label: "DNS over HTTPS", type: "listen", port: 443, help: "Browsers, Windows and iOS profiles. TCP 443." },
        { key: "doh.http3", label: "HTTP/3 for DNS over HTTPS", type: "bool", help: "Faster on mobile networks and patchy Wi-Fi. Uses UDP 443 on the same addresses; where that is blocked, clients use HTTP/2 instead.", show: (v) => v["doh.https_listen"].length > 0 },
        { key: "doh.path", adv: true, label: "DoH path", type: "text", help: "Usually /dns-query." },
        { key: "status.enabled", label: "Public status page", type: "bool", help: "A page at https://domain/: addresses, setup steps per device, what this server keeps, and a check that a device uses it. No statistics." },
        { key: "doh.listen", adv: true, label: "Behind a reverse proxy", type: "text", help: "Plain HTTP for nginx or Caddy, such as 127.0.0.1:8053. Leave empty if unused." },
      ] },
    ],
    extra: ["Addresses for clients"],
  },
  access: {
    title: "Access & limits",
    sections: [
      { title: "Who can use it", fields: [
        { key: "server.mode", label: "Mode", type: "select", options: [["public", "Public: anyone, with limits"], ["private", "Private: listed networks only"]], help: "Private mode answers no one else, not even with an error." },
        { key: "access.allow", label: "Allowed networks", type: "list", help: "Addresses or networks, one per line.", show: (v) => v["server.mode"] === "private" },
        { key: "access.deny", label: "Blocked clients", type: "list", help: "Addresses or networks that never get an answer, in either mode, such as 203.0.113.7 or 198.51.100.0/24. One per line." },
      ] },
      { title: "Limits", fields: [
        { key: "limits.client_qps", label: "Per client", type: "number", help: "Queries a second from one address (0 = no limit). Phones on mobile networks often share one address." },
        { key: "limits.client_burst", adv: true, label: "Client burst", type: "number", help: "Short bursts allowed above that." },
        { key: "limits.prefix_qps", adv: true, label: "Per network", type: "number", help: "Queries a second from one IPv4 /24 or IPv6 /48 (0 = no limit)." },
        { key: "limits.global_qps", adv: true, label: "Whole server", type: "number", help: "Queries a second in total (0 = no limit)." },
        { key: "limits.rrl_rate", adv: true, label: "Response rate limiting", type: "number", help: "Identical answers a second to one network; stops reflection attacks (0 = off)." },
        { key: "server.proxy_protocol", adv: true, label: "Load balancers (PROXY protocol)", type: "list", help: "Load balancers that send the PROXY protocol header, one per line (e.g. 10.0.0.5/32), so clients' real addresses are seen. Required from them. Not for DoQ or HTTP/3." },
        { key: "server.cookies", adv: true, label: "DNS Cookies", type: "bool", help: "Clients that return a valid cookie are exempt from response rate limiting (RFC 7873). Nodes sharing one address need the same secrets/cookie-secret file." },
        { key: "limits.block_any", adv: true, label: "Refuse ANY queries", type: "bool", help: "They are mostly used for amplification." },
        { key: "limits.tcp_connections", adv: true, label: "TCP connections", type: "number", help: "Open TCP, DoT and DoH connections at most; each phone using DoT keeps one open. About 25 KB of memory each." },
        { key: "limits.client_connections", adv: true, label: "Connections per address", type: "number", help: "Open connections from one address (IPv4, or IPv6 /56) at most, over every protocol, so one address cannot take them all. 0: no limit." },
        { key: "limits.quic_connections", adv: true, label: "QUIC connections", type: "number", help: "Open DoQ and HTTP/3 connections at most. About 70 KB of memory each." },
        { key: "limits.upstream_concurrency", adv: true, label: "Upstream queries at once", type: "number", help: "Queries waiting for upstreams at most." },
      ] },
    ],
  },
  alerts: {
    title: "Alerts",
    alerts: true,
    sections: [
      { title: "Notifications", fields: [
        { key: "alerts.enabled", label: "Send alerts", type: "bool", help: "Notify the destinations above when something is wrong, and again when it is fixed. Off: nothing is checked or sent." },
        { key: "alerts.repeat", label: "Remind every", type: "text", help: "While a problem lasts, notify again this often, such as 4h (0s: once).", show: (v) => v["alerts.enabled"] },
        { key: "alerts.nodes", label: "Alerts from every node", type: "bool", help: "This primary also notifies about its followers: their own alerts, and a node that stops checking in. Off: each node's problems show only on its own pages.", show: (v) => v["alerts.enabled"] && state.cluster && state.cluster.role === "primary" },
      ] },
      { title: "When to alert", fields: [
        { key: "alerts.upstream_down_for", label: "Nothing answering for", type: "text", help: "Every upstream failing, or with recursion no name server answering (or the network intercepting DNS). Critical. Such as 30s.", show: (v) => v["alerts.enabled"] },
        { key: "alerts.upstream_failing_for", label: "One upstream failing for", type: "text", help: "At least half of its queries fail while others answer. Such as 5m.", show: (v) => v["alerts.enabled"] && !v["recursion.enabled"] },
        { key: "alerts.servfail_ratio", label: "SERVFAIL share", type: "number", help: "Alert when this share of answers over five minutes is SERVFAIL, such as 0.05 for 5% (0: off). DNSSEC failures are counted apart.", show: (v) => v["alerts.enabled"] },
        { key: "alerts.servfail_min_queries", adv: true, label: "SERVFAIL: at least", type: "number", help: "Answers in five minutes before the share counts, so a quiet server does not alert on a handful.", show: (v) => v["alerts.enabled"] },
        { key: "alerts.servfail_for", adv: true, label: "SERVFAIL: for", type: "text", help: "How long the share must stay above the threshold.", show: (v) => v["alerts.enabled"] },
        { key: "alerts.latency_p95", label: "Slow answers", type: "text", help: "Alert when 95% of queries not in the cache take longer than this, over five minutes, such as 500ms (0s: off).", show: (v) => v["alerts.enabled"] },
        { key: "alerts.latency_min_queries", adv: true, label: "Slow answers: at least", type: "number", help: "Such queries in five minutes before it counts.", show: (v) => v["alerts.enabled"] },
        { key: "alerts.latency_for", adv: true, label: "Slow answers: for", type: "text", help: "How long it must last.", show: (v) => v["alerts.enabled"] },
        { key: "alerts.dnssec_failures", label: "DNSSEC failures", type: "number", help: "Answers refused for failing DNSSEC in five minutes before an alert, which names the domains (0: off).", show: (v) => v["alerts.enabled"] && v["recursion.enabled"] && v["recursion.dnssec"] },
        { key: "alerts.cert_warn_days", label: "Certificate: warn", type: "number", help: "Days before the certificate expires (0: off). Renewal failures are always reported.", show: (v) => v["alerts.enabled"] && v["tls.certificate"] !== "off" },
        { key: "alerts.cert_critical_days", adv: true, label: "Certificate: critical", type: "number", help: "Days before it expires when the alert becomes critical.", show: (v) => v["alerts.enabled"] && v["tls.certificate"] !== "off" },
      ] },
    ],
  },
  admin: {
    title: "Admin",
    sections: [
      { title: "Statistics", action: ["Clear statistics", async () => { await api("POST", "/stats/clear"); toast("Statistics cleared"); }], fields: [
        { key: "stats.retention", label: "Keep statistics for", type: "select", options: [["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]], help: "Kept in memory only, so a restart starts them again. Counts and response times, and the domain lists; never client addresses." },
      ] },
      { title: "Access", fields: [
        { key: "admin.listen", label: "Admin address", type: "text", help: "127.0.0.1:7000: through an SSH tunnel only (safest). :7000: also from other machines, with a password: from your own network in private mode, over HTTPS only on a public server." },
        { key: "metrics.listen", label: "Metrics address", type: "text", help: "Prometheus metrics and the health check. Keep it on a private address." },
      ] },
    ],
    extra: ["Password", "Two-step verification", "Configuration history", "Edit the configuration file", "Clear statistics"],
  },
};

const PAGES_BY_ROUTE = {
  overview, upstreams: upstreamsPage, querylog: queryLogPage, nodes: nodesPage, dnssec: dnssecPage, "tools/trace": tracePage, "tools/lookup": lookupPage, "tools/guide": guidePage,
  "settings/dns": (m) => settingsPage(m, "dns"),
  "settings/encryption": (m) => settingsPage(m, "encryption"),
  "settings/filter": (m) => settingsPage(m, "filter"),
  "settings/access": (m) => settingsPage(m, "access"),
  "settings/alerts": (m) => settingsPage(m, "alerts"),
  "settings/admin": (m) => settingsPage(m, "admin"),
};

async function settingsPage(main, id) {
  const page = SETTINGS[id];
  main.classList.add("narrow");
  main.append(pageHead(page.title, "Settings"));
  if (state.cluster && state.cluster.role === "follower") {
    main.append(h("p", { class: "notice warn" }, "This node follows ", h("strong", null, state.cluster.primary_name || state.cluster.primary),
      ": settings are changed there and reach this node within seconds. Settings for this node only (its addresses, for example) go in its own configuration file. See ", h("a", { href: "#/nodes" }, "Nodes"), "."));
  }
  const holder = h("div", { style: { display: "flex", flexDirection: "column", gap: "18px" } }, h("p", { class: "muted" }, "Loading…"));
  main.append(holder);
  let cfg;
  try {
    cfg = await api("GET", "/config");
  } catch (e) {
    if (e.status !== 401) fill(holder, errorBox(e));
    return;
  }
  const cur = Object.fromEntries(cfg.settings.map((x) => [x.key, x.value]));
  const form = { hash: cfg.hash, cur, val: { ...cur }, rows: {}, problems: {} };
  const parts = [];
  if (page.certificate) parts.push(await certificateCard());
  if (page.filterStatus) parts.push(await filterCard(), whyCard());
  const alertParts = page.alerts ? await alertCards() : null;
  if (alertParts) parts.push(alertParts.status, alertParts.history, alertParts.destinations);
  const sectionCards = [];
  for (const sec of page.sections) {
    const card = h("section", { class: "card pad0", "aria-label": sec.title },
      h("div", { class: "pagehead", style: { margin: "12px 0 4px" } }, h("h2", null, sec.title),
        sec.action ? h("button", { type: "button", class: "btn small", onclick: async () => { try { await sec.action[1](); } catch (e) { toast(e.message, "err"); } } }, sec.action[0]) : null));
    // rarely changed settings fold away under "Advanced"
    const adv = h("details", { class: "adv" }, h("summary", null, "Advanced"));
    for (const f of sec.fields) {
      const row = fieldRow(f, form, () => { refresh(); });
      form.rows[f.key] = { f, row };
      (f.adv ? adv : card).append(row.el);
    }
    if (sec.fields.some((f) => f.adv)) card.append(adv);
    sectionCards.push([card, sec]);
    parts.push(card);
  }
  if (id === "encryption") parts.push(clientAddresses(cur));
  const review = h("section", { class: "review", "aria-live": "polite", "aria-label": "Changes" });
  parts.push(review);
  if (id === "admin") parts.push(...accountCards(), historyCard(), fileCard(cfg.hash));
  fill(holder, ...parts);

  let previewSeq = 0;
  const refresh = () => {
    for (const { f, row } of Object.values(form.rows)) {
      row.el.hidden = f.show ? !f.show(form.val) : false;
      row.sync();
    }
    // a section whose fields are all hidden is hidden too
    for (const [card, sec] of sectionCards) card.hidden = sec.fields.every((f) => f.show && !f.show(form.val));
    drawReview();
  };
  const changed = () => changedValues(form.cur, form.val);
  const drawReview = async () => {
    const set = changed();
    const n = Object.keys(set).length;
    const discard = h("button", { type: "button", class: "btn", disabled: !n, onclick: () => { form.val = { ...form.cur }; form.problems = {}; Object.values(form.rows).forEach((r) => r.row.reset()); refresh(); } }, "Discard");
    // while the preview is checked the button says so instead of looking
    // faded, which read as "cannot be pressed"
    const apply = h("button", { type: "button", class: "btn primary busy", disabled: true }, "Checking…");
    const list = h("div");
    review.className = "review" + (n ? " dirty" : "");
    review.hidden = !n;
    fill(review, h("div", { class: "head" }, h("h2", null, n ? `${n} change${n === 1 ? "" : "s"} to apply` : "No unsaved changes"), discard, apply), list,
      h("div", { class: "small muted" }, "Applies without a restart. The previous settings are kept in Admin › Configuration history."));
    if (!n) { setProblems({}); return; }
    const seq = ++previewSeq;
    await new Promise((r) => setTimeout(r, 250)); // typing: check once it pauses
    if (seq !== previewSeq) return;
    try {
      const p = await api("POST", "/config/preview", { hash: form.hash, set });
      if (seq !== previewSeq) return;
      setProblems({});
      const m = p.changes.length;
      review.querySelector("h2").textContent = `${m} change${m === 1 ? "" : "s"} to apply`;
      fill(list, changeList(p.changes, labelOf), p.warnings.length ? h("ul", { class: "small warn", style: { margin: 0 } }, p.warnings.map((x) => h("li", null, x))) : null,
        p.restart_required.length ? h("p", { class: "small warn" }, "Takes effect after a restart: " + p.restart_required.join(", ")) : null);
      apply.disabled = false;
      apply.classList.remove("busy");
      apply.textContent = "Apply";
      apply.onclick = async () => {
        apply.disabled = true;
        try {
          const r = await api("PATCH", "/config", { hash: form.hash, set });
          toast(`Saved ${r.changes.length} change${r.changes.length === 1 ? "" : "s"}`);
          window.onhashchange();
        } catch (e) {
          showApplyError(e, list);
          apply.disabled = false;
        }
      };
    } catch (e) {
      if (seq !== previewSeq) return;
      apply.classList.remove("busy");
      apply.textContent = "Apply";
      apply.title = "Fix the problems shown first";
      showApplyError(e, list);
    }
  };
  const showApplyError = (e, list) => {
    const probs = {};
    for (const p of e.data.problems || []) if (p.key) (probs[p.key] ||= []).push(p.message);
    setProblems(probs);
    if (e.status === 409) {
      fill(list, h("p", { class: "notice warn" }, "The configuration was changed elsewhere since this page was opened. ",
        h("button", { type: "button", class: "btn small", onclick: () => window.onhashchange() }, "Reload")));
    } else {
      fill(list, problemsBox(e, labelOf));
    }
  };
  const setProblems = (probs) => {
    for (const [k, { row }] of Object.entries(form.rows)) {
      row.problem(probs[k]);
      if (probs[k]) row.el.closest("details")?.setAttribute("open", ""); // show a problem in Advanced
    }
  };
  const labelOf = (k) => form.rows[k]?.f.label || k;
  refresh();
  if (state.focusKey && form.rows[state.focusKey]) {
    const el = form.rows[state.focusKey].row.el;
    el.hidden = false;
    el.closest("details")?.setAttribute("open", "");
    el.scrollIntoView({ block: "center" });
    el.classList.add("flash");
    el.querySelector("input,select,textarea,button")?.focus({ preventScroll: true });
  }
  state.focusKey = null;
}

function fieldRow(f, form, onchange) {
  const id = "f-" + f.key.replace(/\./g, "-");
  const prob = h("div", { class: "problem", id: id + "-err" });
  // f.then may adjust other fields after this one changes
  const set = (v) => { form.val[f.key] = v; if (f.then) f.then(form.val); onchange(); };
  let ctl, sync = () => {}, reset;
  const v = form.val[f.key];
  switch (f.type) {
    case "bool": {
      ctl = h("button", { type: "button", class: "switch", role: "switch", id, "aria-checked": String(!!v), "aria-label": f.label, onclick: () => set(!form.val[f.key]) });
      sync = () => ctl.setAttribute("aria-checked", String(!!form.val[f.key]));
      reset = sync;
      break;
    }
    case "listen": {
      const sw = h("button", { type: "button", class: "switch", role: "switch", id, "aria-label": f.label });
      const addrs = h("div", { class: "small muted mono" });
      const ta = h("textarea", { "aria-label": f.label + " addresses" });
      ta.value = v.join("\n");
      ta.addEventListener("input", () => set(lines(ta.value)));
      sw.addEventListener("click", () => {
        if (form.val[f.key].length) set([]);
        else {
          // the plain DNS addresses, except this machine's own (127.0.0.1 keeps
          // plain DNS local; encrypted DNS still has to be reachable)
          const hosts = (form.val["server.listen"] || []).map(hostOf).filter((x) => x && !/^(127\.|::1$|localhost$)/.test(x));
          set((hosts.length ? hosts : ["0.0.0.0"]).map((x) => withPort(x, f.port)));
          ta.value = form.val[f.key].join("\n");
        }
      });
      sync = () => {
        const on = form.val[f.key].length > 0;
        sw.setAttribute("aria-checked", String(on));
        addrs.textContent = on ? form.val[f.key].join(", ") : "off";
        if (document.activeElement !== ta) ta.value = form.val[f.key].join("\n");
      };
      reset = sync;
      ctl = h("div", { style: { display: "flex", flexDirection: "column", gap: "6px", alignItems: "flex-end", width: "100%" } }, sw, addrs,
        h("details", { style: { width: "100%", textAlign: "right" } }, h("summary", null, "Addresses"), ta));
      break;
    }
    case "select": {
      ctl = h("select", { id, onchange: () => set(ctl.value) }, f.options.map(([val, label]) => h("option", { value: val }, label)));
      if (!f.options.some(([val]) => val === v)) ctl.append(h("option", { value: v }, v));
      ctl.value = v;
      reset = () => { ctl.value = form.val[f.key]; };
      sync = () => { if (ctl.value !== form.val[f.key]) ctl.value = form.val[f.key]; };
      break;
    }
    case "list": {
      ctl = h("textarea", { id, spellcheck: "false", placeholder: f.placeholder || null });
      ctl.value = v.join("\n");
      ctl.addEventListener("input", () => set(lines(ctl.value)));
      reset = () => { ctl.value = form.val[f.key].join("\n"); };
      break;
    }
    case "number": {
      ctl = h("input", { type: "number", id, value: v, step: "any", inputmode: "decimal" });
      ctl.addEventListener("input", () => { if (ctl.value !== "" && !isNaN(Number(ctl.value))) set(Number(ctl.value)); });
      reset = () => { ctl.value = form.val[f.key]; };
      break;
    }
    default: {
      ctl = h("input", { type: "text", id, value: v, class: /listen|file|path|domains|address/.test(f.key) ? "mono" : null, spellcheck: "false", placeholder: f.placeholder || null });
      ctl.addEventListener("input", () => set(ctl.value));
      reset = () => { ctl.value = form.val[f.key]; };
    }
  }
  const inline = f.type === "bool" || f.type === "listen";
  const labelEl = f.type === "bool" || f.type === "listen" ? h("span", { class: "label", id: id + "-l" }, f.label) : h("label", { for: id }, f.label);
  const el = h("div", { class: "field" + (inline ? " inline" : ""), "data-key": f.key },
    h("div", { class: "text" }, labelEl, h("div", { class: "help", id: id + "-h" }, f.help)),
    h("div", { class: "ctl" }, ctl, prob));
  const target = ctl.matches?.("input,select,textarea,button") ? ctl : ctl.querySelector("button");
  target.setAttribute("aria-describedby", id + "-h " + id + "-err");
  return {
    el, sync, reset,
    problem(msgs) {
      prob.textContent = (msgs || []).join(" ");
      target.setAttribute("aria-invalid", String(!!(msgs && msgs.length)));
    },
  };
}

// The label a setting has in the interface, for change lists.
function labelFor(key) {
  for (const page of Object.values(SETTINGS)) for (const sec of page.sections) for (const f of sec.fields) if (f.key === key) return f.label;
  return key;
}

function changeList(changes, labelOf = labelFor) {
  return h("ul", { class: "changes" }, changes.map((c) => h("li", null,
    h("span", { class: "k" }, labelOf(c.key)), h("span", { class: "from" }, fmt.value(c.from)), h("span", { class: "muted", "aria-label": "changes to" }, "→"), h("span", { class: "to" }, fmt.value(c.to)))));
}

function problemsBox(e, labelOf = labelFor) {
  const probs = e.data?.problems || [];
  return h("div", { class: "notice err", role: "alert" }, h("strong", null, e.message),
    probs.length ? h("ul", { style: { margin: "6px 0 0" } }, probs.map((p) => h("li", null, (p.key ? labelOf(p.key) + ": " : "") + p.message + (p.line ? ` (line ${p.line})` : "")))) : null);
}

async function certificateCard() {
  const st = state.status || await api("GET", "/status");
  const c = st.certificate;
  const days = c.not_after ? Math.floor((new Date(c.not_after) - Date.now()) / 86400e3) : null;
  let line;
  if (c.ready) line = h("span", { class: days > 14 ? "ok" : "warn", style: { fontWeight: 600 } }, `Valid for ${days} more days`);
  else if (c.mode && c.mode !== "off") line = h("span", { class: "warn", style: { fontWeight: 600 } }, c.next_attempt ? "Not issued yet; next attempt " + fmt.time(c.next_attempt, "full") : "Not issued yet");
  else line = h("span", { class: "muted" }, "No certificate");
  return h("section", { class: "card", "aria-label": "Certificate status" },
    h("div", { class: "pagehead" }, h("h2", null, "Certificate status"), line),
    c.ready ? h("div", { class: "small muted" }, (c.names || []).join(", "), c.issuer ? " · " + c.issuer : "") : null,
    c.last_error ? h("p", { class: "small err", style: { margin: 0 } }, c.last_error) : null);
}

async function filterCard() {
  const st = (await api("GET", "/status")).filter;
  const head = st.enabled
    ? h("span", { class: "ok", style: { fontWeight: 600 } }, `${st.rules.toLocaleString()} rules in force`)
    : h("span", { class: "muted" }, "Off");
  const short = (src) => src.replace(/^https?:\/\//, "").replace(/^raw\.githubusercontent\.com\//, "");
  return h("section", { class: "card", "aria-label": "Filter status" },
    h("div", { class: "pagehead" }, h("h2", null, "Filter status"), head),
    st.enabled && (st.lists || []).length ? h("div", { class: "lists" }, st.lists.map((l) => h("div", { class: "listrow" },
      h("div", { class: "mono small ellipsis", title: l.source }, short(l.source)),
      h("div", { class: "small " + (l.error ? "warn" : "muted") },
        l.rules ? `${l.rules.toLocaleString()} rules` : "Not downloaded yet",
        l.updated ? " · updated " + fmt.time(l.updated, "full") : "",
        l.error ? " · " + l.error : "")))) : null,
    st.enabled ? null : h("p", { class: "small muted", style: { margin: 0 } }, "Turn it on below. Nothing changes for the usual addresses."));
}

// whyCard answers "which list blocks this?" for one domain.
function whyCard() {
  const name = h("input", { type: "text", class: "mono", placeholder: "ads.example.com", "aria-label": "Domain to check", spellcheck: "false", autocapitalize: "off" });
  name.style.maxWidth = "none";
  const out = h("div", { "aria-live": "polite" });
  const btn = h("button", { type: "submit", class: "btn" }, "Check");
  const short = (src) => src === "filter.block" ? "Your rules › Also block" : src === "filter.allow" ? "Your rules › Never block" : src.replace(/^https?:\/\//, "").replace(/^raw\.githubusercontent\.com\//, "");
  const items = (srcs) => h("ul", { class: "small", style: { margin: "4px 0 0", paddingLeft: "18px" } }, srcs.map((s) => h("li", { class: "mono ellipsis", title: s }, short(s))));
  return h("section", { class: "card", "aria-label": "Check a domain" },
    h("h2", null, "Check a domain"),
    h("p", { class: "small muted", style: { marginTop: 0 } }, "Which lists block it, and which rules let it through."),
    h("form", {
      class: "row", style: { alignItems: "center" }, onsubmit: async (ev) => {
        ev.preventDefault();
        if (!name.value.trim()) return;
        btn.disabled = true;
        fill(out, h("p", { class: "small muted" }, "Checking…"));
        try {
          const r = await api("POST", "/filter/why", { name: name.value });
          const d = name.value.trim().toLowerCase().replace(/\.$/, "");
          if (!r.enabled) fill(out, h("p", { class: "small muted" }, "Filtering is off."));
          else fill(out,
            h("p", { style: { margin: "8px 0 0" } }, h("strong", { class: r.blocked ? "warn" : "ok" }, r.blocked ? "Blocked" : "Not blocked"), " on the filtered service"),
            r.blocked_by.length ? h("div", { class: "small", style: { marginTop: "8px" } }, r.blocked ? "Blocked by" : "In the block rules of", items(r.blocked_by)) : null,
            r.allowed_by.length ? h("div", { class: "small", style: { marginTop: "8px" } }, "Let through by", items(r.allowed_by)) : null,
            r.blocked ? h("p", { style: { margin: "10px 0 0" } }, h("button", { type: "button", class: "btn small", onclick: async () => { try { await allowDomain(d); } catch (e) { toast(e.message, "err"); } } }, "Never block " + d)) : null);
        } catch (e) { fill(out, errorBox(e)); }
        btn.disabled = false;
      },
    }, h("div", { style: { flex: "1 1 220px" } }, name), btn), out);
}

// allowDomain adds a name to filter.allow (from the query log).
async function allowDomain(name) {
  const cfg = await api("GET", "/config");
  const cur = (cfg.settings.find((x) => x.key === "filter.allow") || {}).value || [];
  if (cur.includes(name)) { toast(`${name} is already allowed`); return; }
  await api("PATCH", "/config", { hash: cfg.hash, set: { "filter.allow": [...cur, name] } });
  toast(`${name} will no longer be blocked`);
}

function clientAddresses(cur) {
  const d = (cur["tls.domains"] || [])[0];
  const rows = [];
  if (d && cur["dot.listen"].length) rows.push(["DNS over TLS", d]);
  if (d && cur["doq.listen"].length) rows.push(["DNS over QUIC", "quic://" + d]);
  if (d && cur["doh.https_listen"].length) rows.push(["DNS over HTTPS", `https://${d}${cur["doh.path"]}`]);
  if (d && cur["status.enabled"] && (cur["doh.https_listen"].length || cur["doh.listen"])) rows.push(["Status page", `https://${d}/`]);
  return h("section", { class: "card", "aria-label": "Addresses for clients" }, h("h2", null, "Addresses for clients"),
    rows.length ? rows.map(([k, v]) => h("div", { class: "copyrow" }, h("span", { class: "k" }, k), h("code", null, v), h("button", { type: "button", class: "btn small", onclick: () => copy(v) }, "Copy")))
      : h("p", { class: "empty small", style: { margin: 0 } }, "Set a domain and turn on a protocol to get addresses for your devices."));
}

// ---------- admin page: account, history, file ----------

// ---------- alerts ----------

const DESTINATIONS = [
  { id: "telegram", name: "Telegram", fields: [["token", "Bot token", "123456789:AA…", true], ["chat_id", "Chat ID", "-1001234567890 or @channel"]],
    help: "Make a bot with @BotFather and add it to the chat or channel. The chat ID of a group starts with -100." },
  { id: "discord", name: "Discord", fields: [["url", "Webhook URL", "https://discord.com/api/webhooks/…", true]],
    help: "Channel settings › Integrations › Webhooks › New Webhook › Copy Webhook URL." },
  { id: "slack", name: "Slack", fields: [["url", "Webhook URL", "https://hooks.slack.com/services/…", true]],
    help: "An Incoming Webhook of a Slack app, for the channel to post in." },
  { id: "webhook", name: "Webhook (JSON)", fields: [["url", "URL", "https://alerts.example.com/dnsnova", true], ["secret", "Signing secret (optional)", "a long random string", true]],
    help: "Each alert is POSTed as JSON (docs/alerts.md). With a secret, X-DNSNova-Signature carries its HMAC-SHA256 for the receiver to verify. For PagerDuty, Opsgenie, ntfy, n8n or your own." },
  { id: "heartbeat", name: "Heartbeat", fields: [["url", "Check URL", "https://hc-ping.com/…", true]],
    help: "Requested every minute while alerts are on. A monitor such as Healthchecks.io or Uptime Kuma alerts you when the requests stop, which covers the one problem this server cannot report: being down." },
];

const SEVERITY = { critical: ["err", "Critical"], warning: ["warn", "Warning"] };

async function alertCards() {
  const statusBody = h("div", null, h("p", { class: "muted" }, "Loading…"));
  const destBody = h("div");
  const histBody = h("div");
  const pill = ([cls, label]) => h("span", { class: "state " + cls }, h("span", { class: "dot " + cls }), label);
  let a;
  const draw = () => {
    const follower = a.role === "follower";
    // what is wrong now
    fill(statusBody,
      !a.enabled ? h("p", { class: "muted", style: { margin: 0 } }, "Alerts are off. Set up a destination, then turn on ", h("strong", null, "Send alerts"), " below.")
        : !a.active.length ? h("p", { style: { margin: 0 } }, pill(["ok", "Nothing wrong"]), h("span", { class: "muted small" }, " · checked every 30 seconds"))
          : h("div", { class: "tablewrap" }, h("table", { class: "stack" },
            h("thead", null, h("tr", null, ["State", "Problem", "Node", "Since"].map((t) => h("th", { scope: "col" }, t)))),
            h("tbody", null, a.active.map((x) => h("tr", null,
              h("td", { "data-label": "State" }, x.firing ? pill(SEVERITY[x.severity] || SEVERITY.warning) : pill(["idle", "Pending"])),
              h("td", { class: "head", style: { whiteSpace: "normal" } }, h("div", { style: { textAlign: "left" } }, x.summary, (x.details || []).map((d) => h("div", { class: "small muted", style: { fontWeight: 400 } }, d)))),
              h("td", { class: "muted", "data-label": "Node" }, x.node),
              h("td", { class: "muted", "data-label": "Since" }, fmt.ago(x.since))))))),
      a.enabled && a.active.some((x) => !x.firing) ? h("p", { class: "small muted" }, "Pending: seen, but not for as long as its setting below asks yet.") : null);

    // where alerts go
    const configured = DESTINATIONS.filter((d) => d.id !== "heartbeat" && a.destinations[d.id] && a.destinations[d.id].set).length;
    const testOut = h("div", { class: "small", "aria-live": "polite" });
    const test = h("button", { type: "button", class: "btn small", disabled: follower || !a.enabled || !configured, onclick: async () => {
      test.disabled = true;
      fill(testOut, h("span", { class: "muted" }, "Sending…"));
      try {
        const r = await api("POST", "/alerts/test");
        fill(testOut, Object.entries(r.results).map(([ch, res]) => h("div", null, h("strong", null, ch + ": "), res === "ok" ? h("span", { class: "ok" }, "delivered") : h("span", { class: "err" }, res))));
        load();
      } catch (e) { fill(testOut, h("span", { class: "err" }, e.message)); }
      test.disabled = false;
    } }, "Send a test");
    test.title = follower ? "The primary sends this node's alerts" : !configured ? "Set up a destination first" : !a.enabled ? "Turn on Send alerts first" : "";
    const rows = DESTINATIONS.filter((d) => !follower || d.id === "heartbeat").map((d) => {
      const cur = a.destinations[d.id] || {};
      const row = h("div", { class: "dest" });
      const show = () => fill(row,
        h("div", { class: "row", style: { alignItems: "center", justifyContent: "space-between", gap: "8px" } },
          h("div", null, h("strong", null, d.name), " ", cur.set ? h("span", { class: "small mono muted" }, cur.hint || "set") : h("span", { class: "small muted" }, "not set up")),
          h("div", { class: "row", style: { gap: "6px" } },
            h("button", { type: "button", class: "btn small", onclick: edit }, cur.set ? "Replace…" : "Set up…"),
            cur.set ? h("button", { type: "button", class: "btn small", onclick: async () => {
              try { a = await api("PUT", "/alerts/destinations/" + d.id, {}); toast(d.name + " removed"); draw(); } catch (e) { toast(e.message, "err"); }
            } }, "Remove") : null)));
      const edit = () => {
        const inputs = d.fields.map(([k, label, ph, secret]) => [k, label, h("input", { type: secret ? "password" : "text", class: "mono", placeholder: ph, autocomplete: "off", spellcheck: "false", "aria-label": label })]);
        const err = h("p", { class: "err small", role: "alert" });
        fill(row, h("form", { class: "signin", style: { maxWidth: "none" }, onsubmit: async (ev) => {
          ev.preventDefault();
          err.textContent = "";
          try {
            a = await api("PUT", "/alerts/destinations/" + d.id, Object.fromEntries(inputs.map(([k, , el]) => [k, el.value.trim()])));
            toast(d.name + " saved");
            draw();
          } catch (e) { err.textContent = e.message; }
        } }, h("strong", null, d.name), h("p", { class: "small muted", style: { margin: 0 } }, d.help),
          inputs.map(([, label, el]) => h("label", null, label, el)), err,
          h("div", { class: "row", style: { gap: "6px" } }, h("button", { type: "submit", class: "btn small primary" }, "Save"), h("button", { type: "button", class: "btn small", onclick: show }, "Cancel"))));
        inputs[0][2].focus();
      };
      show();
      return row;
    });
    fill(destBody,
      follower ? h("p", { class: "notice small" }, "This node is a cluster follower: its alerts go to ", h("strong", null, (state.cluster && state.cluster.primary_name) || "the primary"), ", which sends them for every node. Only its heartbeat is set here.") : null,
      h("div", { class: "dests" }, rows),
      follower ? null : h("div", { class: "row", style: { alignItems: "center", gap: "10px" } }, test, testOut),
      h("p", { class: "small muted" }, "Addresses and tokens are kept in secrets/alerts.json on this server, readable by DNSNova only, and never shown again once saved. Alerts carry no client addresses."));

    fill(histBody, a.history.length ? h("div", { class: "tablewrap" }, h("table", { class: "stack" },
      h("thead", null, h("tr", null, ["Sent", "Alert", "Delivery"].map((t) => h("th", { scope: "col" }, t)))),
      h("tbody", null, a.history.map((n) => h("tr", null,
        h("td", { class: "muted", "data-label": "Sent" }, fmt.ago(n.time)),
        h("td", { class: "head", style: { whiteSpace: "normal" } }, h("div", { style: { textAlign: "left" } },
          h("span", { class: n.status === "resolved" ? "ok" : n.status === "test" ? "" : n.severity === "critical" ? "err" : "warn" }, { reminder: "Still: ", resolved: "Resolved: ", firing: n.severity === "critical" ? "Critical: " : "Warning: " }[n.status] || ""),
          n.summary, n.node && n.node !== n.server ? h("span", { class: "muted small" }, " · " + n.node) : null)),
        h("td", { "data-label": "Delivery", class: "small" }, Object.entries(n.results).map(([ch, res]) => h("div", null, ch + ": ", res === "ok" ? h("span", { class: "ok" }, "ok") : h("span", { class: "err" }, res)))))))))
      : h("p", { class: "muted", style: { margin: 0 } }, "Nothing sent since the server started."));
  };
  const load = async () => {
    try { a = await api("GET", "/alerts"); draw(); } catch (e) { if (e.status !== 401) fill(statusBody, errorBox(e)); }
  };
  await load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible" && !destBody.querySelector("input")) load(); }, 15000);
  return {
    status: h("section", { class: "card", "aria-label": "Now" }, h("h2", null, "Now"), statusBody),
    destinations: h("section", { class: "card", "aria-label": "Destinations" }, h("h2", null, "Destinations"), destBody),
    history: h("section", { class: "card", "aria-label": "Sent" }, h("h2", null, "Sent"), histBody),
  };
}

function accountCards() {
  const cur = h("input", { type: "password", autocomplete: "current-password" });
  const nw = h("input", { type: "password", autocomplete: "new-password" });
  const nw2 = h("input", { type: "password", autocomplete: "new-password" });
  const perr = h("p", { class: "err small", role: "alert" });
  const pw = h("section", { class: "card", "aria-label": "Password" }, h("h2", null, "Password"),
    h("form", {
      class: "signin", style: { maxWidth: "440px" }, onsubmit: async (ev) => {
        ev.preventDefault();
        perr.textContent = "";
        if (nw.value !== nw2.value) { perr.textContent = "The new passwords do not match."; return; }
        try {
          await api("POST", "/account/password", { current: cur.value, new: nw.value });
          toast("Password changed; other sessions were logged out");
          cur.value = nw.value = nw2.value = "";
        } catch (e) { perr.textContent = e.message; }
      },
    }, h("label", null, "Current password", cur), h("label", null, "New password (at least 10 characters)", nw), h("label", null, "New password again", nw2), perr,
      h("div", null, h("button", { type: "submit", class: "btn" }, "Change password"))));

  const totpBody = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const drawTOTP = () => {
    const on = state.session.totp;
    const err = h("p", { class: "err small", role: "alert" });
    if (on) {
      const p = h("input", { type: "password", autocomplete: "current-password", "aria-label": "Password" });
      fill(totpBody, h("p", { style: { margin: 0 } }, h("strong", { class: "ok" }, "On."), " Signing in asks for a code from your authenticator app."),
        h("form", {
          class: "row", style: { alignItems: "center" }, onsubmit: async (ev) => {
            ev.preventDefault();
            try { await api("DELETE", "/account/totp", { password: p.value }); state.session.totp = false; toast("Two-step verification is off"); drawTOTP(); } catch (e) { err.textContent = e.message; }
          },
        }, h("div", { style: { flex: "1 1 220px" } }, p), h("button", { type: "submit", class: "btn danger" }, "Turn off")), err);
    } else {
      fill(totpBody, h("p", { style: { margin: 0 } }, "Off. With it on, signing in also asks for a 6-digit code from an app such as 1Password, Google Authenticator or Authy."),
        h("div", null, h("button", {
          type: "button", class: "btn", onclick: async () => {
            try {
              const r = await api("POST", "/account/totp");
              const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", "aria-label": "Code from the app" });
              fill(totpBody, 
                h("p", { style: { margin: 0 } }, "Add this key to your authenticator app (choose “enter a setup key”), then type the code it shows."),
                h("div", { class: "copyrow" }, h("span", { class: "k" }, "Setup key"), h("code", null, r.secret.replace(/(.{4})/g, "$1 ").trim()), h("button", { type: "button", class: "btn small", onclick: () => copy(r.secret) }, "Copy")),
                h("div", { class: "copyrow" }, h("span", { class: "k" }, "Or this link"), h("code", { class: "small" }, r.uri), h("button", { type: "button", class: "btn small", onclick: () => copy(r.uri) }, "Copy")),
                h("form", {
                  class: "row", style: { alignItems: "center" }, onsubmit: async (ev) => {
                    ev.preventDefault();
                    try { await api("POST", "/account/totp/confirm", { code: code.value }); state.session.totp = true; toast("Two-step verification is on"); drawTOTP(); } catch (e) { err.textContent = e.message; }
                  },
                }, h("div", { style: { flex: "1 1 160px" } }, code), h("button", { type: "submit", class: "btn primary" }, "Turn on")), err);
              code.focus();
            } catch (e) { err.textContent = e.message; totpBody.append(err); }
          },
        }, "Set up two-step verification")));
    }
  };
  drawTOTP();
  return [pw, h("section", { class: "card", "aria-label": "Two-step verification" }, h("h2", null, "Two-step verification"), totpBody)];
}

function diffView(diff) {
  const pre = h("pre", { class: "diff" });
  let last = 0;
  for (const d of diff) {
    const n = d.new || d.old;
    if (last && n > last + 1) pre.append(h("span", { class: "gap" }, "  ⋯\n"));
    last = d.new || last;
    pre.append(h("span", { class: d.op === "+" ? "add" : d.op === "-" ? "del" : "" }, `${d.op} ${d.text}\n`));
  }
  return diff.length ? pre : h("p", { class: "empty small" }, "Identical to the current file.");
}

function historyCard() {
  const body = h("div", null, h("p", { class: "muted small" }, "Loading…"));
  const card = h("section", { class: "card", "aria-label": "Configuration history" }, h("h2", null, "Configuration history"),
    h("p", { class: "muted small", style: { margin: 0 } }, "The last 10 versions of the file, saved before each change."), body);
  (async () => {
    try {
      const { versions } = await api("GET", "/config/history");
      if (!versions.length) { fill(body, h("p", { class: "empty small" }, "No earlier versions yet.")); return; }
      fill(body, h("ul", { class: "list" }, versions.map((v) => {
        const out = h("div", { style: { width: "100%" } });
        const li = h("li", { style: { flexWrap: "wrap" } }, h("span", { class: "grow" }, fmt.time(v.saved, "full"), " ", h("span", { class: "small muted" }, fmt.ago(v.saved))),
          h("button", {
            type: "button", class: "btn small", onclick: async () => {
              if (out.childNodes.length) { fill(out, ); return; }
              try {
                const r = await api("GET", "/config/history/" + encodeURIComponent(v.name));
                const restore = h("button", {
                  type: "button", class: "btn small primary", onclick: async () => {
                    try {
                      const cfg = await api("GET", "/config");
                      await api("POST", "/config/history/" + encodeURIComponent(v.name) + "/restore", { hash: cfg.hash });
                      toast("Restored the version from " + fmt.time(v.saved, "full"));
                      window.onhashchange();
                    } catch (e) { out.append(problemsBox(e)); }
                  },
                }, "Restore this version");
                fill(out, h("p", { class: "small muted" }, "Restoring changes the current file like this:"), diffView(r.diff), h("div", null, restore));
              } catch (e) { fill(out, errorBox(e)); }
            },
          }, "Changes"), out);
        return li;
      })));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  })();
  return card;
}

function fileCard(hash) {
  const ta = h("textarea", { class: "file", spellcheck: "false", "aria-label": "Configuration file" });
  const out = h("div");
  let base = hash;
  const load = async () => {
    const r = await api("GET", "/config/file");
    ta.value = r.content;
    base = r.hash;
  };
  const send = async (preview) => {
    try {
      const r = await api("PUT", "/config/file", { hash: base, content: ta.value, preview });
      if (preview) {
        fill(out, r.changes.length ? changeList(r.changes) : h("p", { class: "small muted" }, "No setting changes."), diffView(r.diff));
      } else {
        toast("Saved");
        window.onhashchange();
      }
    } catch (e) {
      fill(out, e.status === 409 ? h("p", { class: "notice warn" }, "The file was changed elsewhere. ", h("button", { type: "button", class: "btn small", onclick: () => load().then(() => fill(out, )) }, "Load the current file")) : problemsBox(e));
    }
  };
  const det = h("details", { ontoggle: () => { if (det.open && !ta.value) load().catch((e) => fill(out, errorBox(e))); } },
    h("summary", null, "Show the file"),
    h("div", { style: { display: "flex", flexDirection: "column", gap: "10px", marginTop: "10px" } }, ta,
      h("div", { class: "row" }, h("button", { type: "button", class: "btn", onclick: () => send(true) }, "Check"), h("button", { type: "button", class: "btn primary", onclick: () => send(false) }, "Save")), out));
  return h("section", { class: "card", "aria-label": "Edit the configuration file" }, h("h2", null, "Edit the configuration file"),
    h("p", { class: "muted small", style: { margin: 0 } }, "The whole file, comments included. Every setting is explained in dnsnova.example.toml."), det);
}

boot();
