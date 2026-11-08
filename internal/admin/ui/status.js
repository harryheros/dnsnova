// DNSNova public status page: how to use this server, what it keeps, and a
// check that this device is using it. It loads nothing from other sites and
// sends nothing but the check below to this server.
//
// The check: the page loads an image from a random name under
// check.<domain>. To fetch it, the device first asks its DNS for that name.
// If its DNS is this server, the server notes the random name and the
// protocol it came over (nothing else), and /check/<name> says so. Any
// other DNS never reaches this server, so the name is never seen.

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
  code: [["path", { d: "m16 18 6-6-6-6M8 6l-6 6 6 6" }]],
  search: [["circle", { cx: 11, cy: 11, r: 7 }], ["path", { d: "M20 20l-3.5-3.5" }]],
  sun: [["circle", { cx: 12, cy: 12, r: 4 }], ["path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }]],
  moon: [["path", { d: "M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11z" }]],
};
function line(name, size = 16) {
  return s("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ic" },
    LINE[name].map(([tag, a]) => s(tag, a)));
}
function logo(size) {
  return s("svg", { width: size, height: size, viewBox: "0 0 24 24", "aria-hidden": "true" },
    s("circle", { cx: 12, cy: 12, r: 3.4, fill: "var(--accent)" }),
    s("circle", { cx: 12, cy: 12, r: 7.4, fill: "none", stroke: "var(--accent)", "stroke-width": 1.6, opacity: 0.6 }),
    s("circle", { cx: 12, cy: 12, r: 11, fill: "none", stroke: "var(--accent)", "stroke-width": 1.2, opacity: 0.28 }));
}

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

// ---------- setup guides ----------

function guides(info) {
  const doh = info.doh, dot = info.dot && !info.dot.includes(":") ? info.dot : "", ip = (info.plain || [])[0] || "";
  const step = (...kids) => h("li", null, ...kids);
  const bare = (el) => (el ? h("li", { class: "bare" }, el) : null);
  const path = (...p) => h("span", { class: "path" }, p.join(" › "));
  const list = [];
  if (dot) list.push(["Android", [
    h("ol", { class: "steps-list" },
      step("Open ", path("Settings", "Network & internet", "Private DNS"), "."),
      step("Choose ", h("strong", null, "Private DNS provider hostname"), " and enter:"),
      bare(copyrow("Hostname", dot)),
      step("Save. Android 9 or later; menu names vary by maker.")),
  ]]);
  if (doh || dot) list.push(["iPhone & Mac", [
    h("ol", { class: "steps-list" },
      step("Download the profile on the device:"),
      bare(h("div", { class: "row" },
        doh ? h("a", { class: "btn primary", href: "/dnsnova.mobileconfig?p=doh" }, "Profile, DNS over HTTPS") : null,
        dot ? h("a", { class: "btn", href: "/dnsnova.mobileconfig?p=dot" }, "Profile, DNS over TLS") : null)),
      step("iPhone and iPad: ", path("Settings", "Profile Downloaded"), ", then Install."),
      step("Mac: ", path("System Settings", "Privacy & Security", "Profiles"), ", then Install."),
      step("The profile is not signed, so the system says “Unverified”. It only sets DNS; remove it there at any time.")),
  ]]);
  if (doh) list.push(["Windows", [
    h("ol", { class: "steps-list" },
      step("Open ", path("Settings", "Network & internet", "Wi-Fi or Ethernet", "Hardware properties"), "."),
      step("Next to DNS server assignment choose ", h("strong", null, "Edit"), ", then Manual, and turn on IPv4."),
      ip ? bare(copyrow("Preferred DNS", ip)) : step("Preferred DNS: this server's IP address."),
      step("DNS over HTTPS: ", h("strong", null, "On (manual template)"), ", with:"),
      bare(copyrow("Template", doh)),
      step("Windows 11.")),
  ]]);
  if (doh) list.push(["Browsers", [
    h("ol", { class: "steps-list" },
      step("Chrome and Edge: ", path("Settings", "Privacy and security", "Security", "Use secure DNS"), ", choose Custom."),
      step("Firefox: ", path("Settings", "Privacy & Security", "DNS over HTTPS"), ", Max Protection, Custom."),
      bare(copyrow("Address", doh)),
      step("Only the browser uses it; other apps keep the system's DNS.")),
  ]]);
  list.push(["Routers & Linux", [
    h("ol", { class: "steps-list" },
      step("Use the encrypted addresses where the router or client supports them:"),
      info.dot ? bare(copyrow("DoT", info.dot)) : null,
      info.doq ? bare(copyrow("DoQ", info.doq)) : null,
      doh ? bare(copyrow("DoH", doh)) : null,
      ip && dot ? step("systemd-resolved: ", h("code", null, `DNS=${ip}#${dot}`), " and ", h("code", null, "DNSOverTLS=yes"), ".") : null,
      info.plain?.length ? step("Plain DNS (port 53, not encrypted): ", h("code", null, info.plain.join(", ")), ".") : null),
  ]]);
  return list;
}

function tabs(list) {
  const body = h("div", { class: "tabbody" });
  const bar = h("div", { class: "seg tabs", role: "tablist", "aria-label": "Device" });
  const pick = (i) => {
    [...bar.children].forEach((b, j) => { b.setAttribute("aria-selected", String(i === j)); b.setAttribute("aria-pressed", String(i === j)); b.tabIndex = i === j ? 0 : -1; });
    fill(body, list[i][1]);
  };
  list.forEach(([name], i) => bar.append(h("button", { type: "button", role: "tab", onclick: () => pick(i) }, name)));
  bar.addEventListener("keydown", (ev) => {
    const cur = [...bar.children].findIndex((b) => b.getAttribute("aria-selected") === "true");
    if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") {
      const n = (cur + (ev.key === "ArrowRight" ? 1 : list.length - 1)) % list.length;
      pick(n);
      bar.children[n].focus();
    }
  });
  // Start on the visitor's platform when it is obvious.
  const ua = navigator.userAgent;
  const guess = /Android/.test(ua) ? "Android" : /iPhone|iPad|Macintosh/.test(ua) ? "iPhone & Mac" : /Windows/.test(ua) ? "Windows" : null;
  pick(Math.max(0, list.findIndex(([n]) => n === guess)));
  return [bar, body];
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
  const addresses = dcard("s5", "Addresses", "list",
    addrRows.length ? h("div", { class: "addrs" }, addrRows.map(([k, v]) => copyrow(k, v))) : h("p", { class: "empty small" }, "No addresses are published."),
    h("footer", { class: "dfoot" }, h("span", null, info.http3 ? "HTTPS also over HTTP/3" : "HTTPS over HTTP/1.1 and HTTP/2"), h("span", null, info.mode === "public" ? "Open to everyone" : "Private")));

  const guide = dcard("s7", "Use this server", "phone", ...tabs(guides(info)),
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
    h("header", { class: "pubtop" }, h("div", { class: "brand" }, logo(24), h("span", null, "DNSNova")), themeToggle()),
    h("main", { class: "dash" }, hero, guide, addresses, privacy, about)));
  if (info.check) runCheck(info, checkBox);
}

boot();
