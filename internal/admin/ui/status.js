// DNSNova public status page: how to use this server, what it keeps, and a
// check that this device is using it. It loads nothing from other sites and
// sends nothing but the check below to this server.
//
// The check: the page loads an image from a random name under
// check.<domain>. To fetch it, the device first asks its DNS for that name.
// If its DNS is this server, the server notes the random name and the
// protocol it came over (nothing else), and /check/<name> says so. Any
// other DNS never reaches this server, so the name is never seen.

import { guides, tabs, filtered } from "./guides.js";

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
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}
function fill(el, ...kids) { el.replaceChildren(); add(el, kids); return el; }

// Line icons in the style of Lucide (ISC license; see app.js).
const LINE = {
  check: [["path", { d: "M20 6 9 17l-5-5" }]],
  x: [["path", { d: "M18 6 6 18M6 6l12 12" }]],
  alert: [["path", { d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3M12 9v4M12 17h.01" }]],
  shield: [["path", { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }]],
  lock: [["rect", { x: 3, y: 11, width: 18, height: 11, rx: 2 }], ["path", { d: "M7 11V7a5 5 0 0 1 10 0v4" }]],
  phone: [["rect", { x: 5, y: 2, width: 14, height: 20, rx: 2 }], ["path", { d: "M12 18h.01" }]],
  list: [["path", { d: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" }]],
  filter: [["path", { d: "M10 20a1 1 0 0 0 .553.895l2 1A1 1 0 0 0 14 21v-7a2 2 0 0 1 .517-1.341L21.74 4.67A1 1 0 0 0 21 3H3a1 1 0 0 0-.742 1.67l7.225 7.989A2 2 0 0 1 10 14z" }]],
  code: [["path", { d: "m16 18 6-6-6-6M8 6l-6 6 6 6" }]],
  search: [["circle", { cx: 11, cy: 11, r: 7 }], ["path", { d: "M20 20l-3.5-3.5" }]],
  sun: [["circle", { cx: 12, cy: 12, r: 4 }], ["path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }]],
  moon: [["path", { d: "M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11z" }]],
};
function line(name, size = 16) {
  return s("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ic" },
    LINE[name].map(([tag, a]) => s(tag, a)));
}
// the DNSNova mark and wordmark, the same as in the admin interface (app.js)
const MARK_PATH = "M50 -1L66 24L56.5 19.5V51H43.5V19.5L34 24Z" +
  "M14 1L29 26L20.5 22V29C20.5 41.5 32 49.5 43.5 50.5H56.5C68 49.5 79.5 41.5 79.5 29V22L71 26L86 1L101 26L92.5 22V29C92.5 51.5 75.5 62.5 56.5 63.5V64H43.5V63.5C24.5 62.5 7.5 51.5 7.5 29V22L-1 26Z" +
  "M43.5 64H56.5V86H43.5ZM33 66H67L61.5 74H38.5ZM50 81L58.5 90.5L50 101L41.5 90.5Z";
let markSeq = 0;
function stops(prefix, offsets) {
  return offsets.map((o, i) => s("stop", { offset: o, class: prefix + i }));
}
function logoMark(size = 28, glow = false) {
  const id = "dnm" + ++markSeq;
  const bevel = s("linearGradient", { id: id + "b", x1: 0, y1: 0, x2: 100, y2: 0, gradientUnits: "userSpaceOnUse" },
    s("stop", { offset: 0, "stop-color": "#fff", "stop-opacity": 0.3 }), s("stop", { offset: 0.5, "stop-color": "#fff", "stop-opacity": 0 }),
    s("stop", { offset: 0.5, "stop-color": "#001", "stop-opacity": 0.1 }), s("stop", { offset: 1, "stop-color": "#001", "stop-opacity": 0.2 }));
  return s("svg", { width: size, height: size, viewBox: "-5 -3 110 106", "aria-hidden": "true", class: "mark" + (glow ? " glow" : "") },
    s("defs", null, s("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 100, gradientUnits: "userSpaceOnUse" }, stops("k", [0, 0.22, 0.45, 0.5, 0.8, 1])), bevel),
    s("path", { d: MARK_PATH, fill: `url(#${id})` }), s("path", { d: MARK_PATH, fill: `url(#${id}b)` }));
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
function logo(size) { return logoMark(size, true); }

function toast(msg) {
  const t = h("div", { class: "toast" }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), 2500);
}
function copy(text) {
  navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => toast("Could not copy"));
}
function copyrow(label, value) {
  return h("div", { class: "copyrow" }, h("span", { class: "k" }, label), h("code", null, value),
    h("button", { type: "button", class: "btn small", onclick: () => copy(value) }, "Copy"));
}

function themeToggle() {
  const btn = h("button", { type: "button", class: "btn small", "aria-label": "Switch appearance" });
  const draw = () => {
    const dark = document.documentElement.dataset.theme === "dark";
    fill(btn, line(dark ? "sun" : "moon", 14), dark ? "Light" : "Dark");
  };
  btn.addEventListener("click", () => {
    window.dnsnovaTheme.set(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    draw();
  });
  draw();
  return btn;
}

const PROTO_NAMES = { doh: "DNS over HTTPS", doh3: "DNS over HTTPS (HTTP/3)", dot: "DNS over TLS", doq: "DNS over QUIC", udp: "plain DNS (UDP)", tcp: "plain DNS (TCP)" };

// ---------- the check ----------

function token() {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(36).padStart(2, "0")).join("").slice(0, 20);
}

async function runCheck(info, box) {
  fill(box, h("div", { class: "result wait" }, h("span", { class: "spin", "aria-hidden": "true" }), h("div", null, h("strong", null, "Checking…"), h("div", { class: "small muted" }, "Asking your device's DNS for a one-time name."))));
  const t = token();
  await new Promise((done) => {
    const img = new Image();
    const timer = setTimeout(done, 4000);
    img.onload = img.onerror = () => { clearTimeout(timer); done(); };
    img.src = `https://${t}.check.${info.domain}/dnsnova-check.png`;
  });
  let r = { seen: false };
  for (let i = 0; i < 3 && !r.seen; i++) {
    if (i) await new Promise((x) => setTimeout(x, 800));
    try { r = await (await fetch("/check/" + t, { cache: "no-store" })).json(); } catch (e) { /* retry */ }
  }
  const again = h("button", { type: "button", class: "btn small", onclick: () => runCheck(info, box) }, "Check again");
  if (r.seen && /^(doh|doh3|dot|doq)$/.test(r.proto)) {
    fill(box, h("div", { class: "result ok" }, h("span", { class: "badge" }, line("check", 22)),
      h("div", null, h("strong", null, "Yes, this device is using this server"), h("div", { class: "small" }, "Encrypted, over " + PROTO_NAMES[r.proto] + "."))), again);
  } else if (r.seen) {
    fill(box, h("div", { class: "result warn" }, h("span", { class: "badge" }, line("alert", 22)),
      h("div", null, h("strong", null, "Using this server, but unencrypted"), h("div", { class: "small" }, "Over " + PROTO_NAMES[r.proto] + ". Your network can read these queries. Switch to an encrypted address below."))), again);
  } else {
    fill(box, h("div", { class: "result no" }, h("span", { class: "badge" }, line("x", 22)),
      h("div", null, h("strong", null, "This device is not using this server"), h("div", { class: "small" }, "Its DNS queries go somewhere else right now."))),
    h("ul", { class: "small muted hints" },
      h("li", null, "Just changed the setting? Give it a minute, or reconnect to the network."),
      h("li", null, "Browsers with their own “secure DNS” setting use that instead of the system's."),
      h("li", null, "A VPN or iCloud Private Relay sends DNS through the VPN.")), again);
  }
}

// ---------- page ----------

function dcard(span, title, ic, ...body) {
  return h("section", { class: "card dcard " + span, "aria-label": title },
    h("header", { class: "dhead" }, line(ic, 15), h("h2", null, title)), ...body);
}

async function boot() {
  const app = document.getElementById("app");
  let info;
  try {
    info = await (await fetch("/status.json", { cache: "no-store" })).json();
  } catch (e) {
    fill(app, h("p", { class: "boot" }, "The status could not be loaded."));
    return;
  }
  document.title = (info.domain || "DNS") + " · Encrypted DNS";
  const state = !info.healthy ? ["err", "Upstreams not answering"] : info.domain && !info.encrypted ? ["warn", "Encrypted DNS not ready yet"] : ["ok", "Operating normally"];
  const checkBox = h("div", { class: "checkbox", "aria-live": "polite" });

  const facts = [
    info.query_log ? null : "No query log",
    "Your address is never sent upstream",
    "Open source",
  ].filter(Boolean);
  const hero = h("section", { class: "card hero2 s12", "aria-label": "Status" },
    h("div", { class: "heroinfo" },
      h("span", { class: "pill " + state[0] }, h("span", { class: "dot " + state[0] }), state[1]),
      h("h1", null, "Private, encrypted DNS"),
      h("div", { class: "mono domain" }, info.domain || location.hostname),
      h("div", { class: "facts" }, facts.map((f) => h("span", null, line("check", 14), f)))),
    info.check ? h("div", { class: "heropanel" }, h("div", { class: "label" }, "Is this device using it?"), checkBox) : null);

  const addrRows = [
    info.doh ? ["DNS over HTTPS", info.doh] : null,
    info.dot ? ["DNS over TLS", info.dot] : null,
    info.doq ? ["DNS over QUIC", info.doq] : null,
    ...(info.plain || []).map((ip) => ["Plain DNS", ip]),
  ].filter(Boolean);
  const filt = filtered(info, { h, copyrow }, "");
  const addresses = dcard("s5", "Addresses", "list",
    addrRows.length ? h("div", { class: "addrs" }, addrRows.map(([k, v]) => copyrow(k, v))) : h("p", { class: "empty small" }, "No addresses are published."),
    filt ? h("div", { class: "filtered" }, h("h3", null, line("filter", 14), "With filtering"), ...filt) : null,
    h("footer", { class: "dfoot" }, h("span", null, info.http3 ? "HTTPS also over HTTP/3" : "HTTPS over HTTP/1.1 and HTTP/2"), h("span", null, info.mode === "public" ? "Open to everyone" : "Private")));

  const guide = dcard("s7", "Use this server", "phone", ...tabs(guides(info, { h, copyrow }), { h, fill }),
    h("footer", { class: "dfoot" }, h("span", null, info.check ? "After changing the setting, check above that it works." : "Settings take effect within a minute."), h("span")));

  const privRows = [
    ["Query log", info.query_log ? (info.query_log_full_ip ? "On now, with addresses" : "On now, addresses shortened") : "Off", info.query_log ? "warn" : "ok"],
    ["Queries kept on disk", "Never", "ok"],
    ["Your address kept on disk", "Never", "ok"],
    ["Your address sent upstream", "Never", "ok"],
    ["Ads, tracking, telemetry", "None", "ok"],
  ];
  const privacy = dcard("s6", "What this server keeps", "shield",
    h("dl", { class: "kvs" }, privRows.map(([k, v, c]) => h("div", null, h("dt", null, k), h("dd", { class: c }, v)))),
    h("footer", { class: "dfoot" }, h("span", null, "Counts and popular domains (asked by 5+ networks) are kept in memory only."), h("span")));
  const about = dcard("s6", "About this server", "code",
    h("p", { class: "small", style: { margin: 0 } }, "Runs DNSNova, an open-source DNS server. It answers from its cache or asks its upstream resolvers on your behalf; they see this server's address, not yours."),
    h("p", { class: "small", style: { margin: 0 } }, "The query log is for troubleshooting only. When the operator turns it on, it runs for a limited time, stays in memory, and this page shows it."),
    h("p", { class: "small muted", style: { margin: 0 } }, "This page loads nothing from other sites. The check above sends one DNS query for a random name; nothing is stored but that name and the protocol, for five minutes."),
    h("footer", { class: "dfoot" }, h("span", null, "DNSNova · AGPL-3.0"), h("a", { href: "https://github.com/harryheros/dnsnova", rel: "noopener noreferrer" }, "Source code")));

  fill(app, h("div", { class: "pubwrap" },
    h("header", { class: "pubtop" }, h("div", { class: "brand" }, logo(32), wordmark()), themeToggle()),
    h("main", { class: "dash" }, hero, guide, addresses, privacy, about)));
  if (info.check) runCheck(info, checkBox);
}

boot();
