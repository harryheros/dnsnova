// DNSNova admin interface. Plain JavaScript, no framework and no build step:
// every screen is drawn from the admin API (docs/api.md), and the interface
// holds no privileges of its own. Text from the server is always inserted as
// text, never as HTML.

import { guides, tabs } from "./guides.js";

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
  user: [["path", { d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" }], ["circle", { cx: 12, cy: 7, r: 4 }]],
  compare: [["path", { d: "M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4" }]],
  sliders: [["path", { d: "M20 7h-9M14 17H5" }], ["circle", { cx: 17, cy: 17, r: 3 }], ["circle", { cx: 7, cy: 7, r: 3 }]],
  power: [["path", { d: "M12 2v10M18.4 6.6a9 9 0 1 1-12.77.04" }]],
  alert: [["path", { d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3M12 9v4M12 17h.01" }]],
  info: [["circle", { cx: 12, cy: 12, r: 10 }], ["path", { d: "M12 16v-4M12 8h.01" }]],
  phone: [["rect", { x: 5, y: 2, width: 14, height: 20, rx: 2 }], ["path", { d: "M12 18h.01" }]],
};

function line(name, size = 16) {
  return s("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ic" },
    (LINE[name] || LINE.info).map(([tag, a]) => s(tag, a)));
}

const icon = {
  logo: (size = 24) => s("svg", { width: size, height: size, viewBox: "0 0 24 24", "aria-hidden": "true" },
    s("circle", { cx: 12, cy: 12, r: 3.4, fill: "var(--accent)" }),
    s("circle", { cx: 12, cy: 12, r: 7.4, fill: "none", stroke: "var(--accent)", "stroke-width": 1.6, opacity: 0.6 }),
    s("circle", { cx: 12, cy: 12, r: 11, fill: "none", stroke: "var(--accent)", "stroke-width": 1.2, opacity: 0.28 })),
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
    mount(h("div", { class: "center" }, h("div", { class: "signin" }, brandBig(), h("p", { class: "notice err" }, e.message))));
  }
}

function setupCodeFromURL() {
  const m = /setup=([A-Za-z0-9-]{8,40})/.exec(location.hash + location.search);
  if (m) history.replaceState(null, "", location.pathname); // keep the code out of history
  return m ? m[1] : "";
}

function brandBig() {
  return h("div", { class: "brand" }, icon.logo(28), h("span", null, "DNSNova"));
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

const WIZ_STEPS = ["Administrator", "Addresses", "Upstreams", "Encrypted DNS", "Review"];

async function showWizard(code, codeRequired) {
  const w = { step: 0, code, codeRequired, cfg: null, hash: "", values: {}, addrs: [], clientIP: "" };
  const render = () => {
    const body = h("section", { class: "card wizbody", "aria-labelledby": "step-h" });
    const steps = h("ol", { class: "steps", "aria-label": "Steps" }, WIZ_STEPS.map((t, i) =>
      h("li", { class: i < w.step ? "done" : "", "aria-current": i === w.step ? "step" : null },
        h("span", { class: "n" }, i < w.step ? "✓" : String(i + 1)), h("span", { class: "t" }, t))));
    mount(h("main", { class: "wizard" }, h("div", { class: "inner" },
      h("div", { class: "wizhead" }, h("div", { class: "brand" }, icon.logo(28), h("span", null, "DNSNova setup")), themeIcons()),
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
      [false, "From the network", "Open it from any computer or phone that can reach this server, with your password."],
      [true, "Only through an SSH tunnel", "More secure on a server on the internet. You will need: ssh -L port:127.0.0.1:port user@server"],
    ].map(([local, t, d]) => h("button", {
      type: "button", class: "choice", role: "radio", "aria-checked": String(!!w.adminLocal === local),
      onclick: () => { w.adminLocal = local; drawAccess(); },
    }, h("strong", null, t), h("span", null, d))));
    w.adminLocal = /^(127\.|\[::1\]|localhost)/.test(location.hostname);
    drawAccess();
    put(body, wizHead(w, "Create the administrator", "Only this account can sign in to DNSNova."),
      w.code || !w.codeRequired ? null : h("label", { class: "block" }, ["Setup code: the installer printed it, or run ", h("code", null, "cat /var/lib/dnsnova/secrets/setup-code"), " on the server. It is asked only when this page is opened from outside your network."], codeIn),
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
    const allNow = cur.length > 0 && cur.every((x) => /^(:|0\.0\.0\.0:|\[::\]:)/.test(x));
    const current = new Set(allNow ? [] : cur.map(hostOf));
    const virtual = /^(docker|veth|br-|virbr|cni|flannel|lxc|lxd|vmnet|vboxnet|zt)/;
    const usable = w.addrs.filter((a) => !a.loopback && !/^fe80/i.test(a.address));
    const list = [...new Set([...usable.map((a) => a.address), ...current])];
    const curPort = cur.length ? cur[0].slice(cur[0].lastIndexOf(":") + 1) : "53";
    const port = h("input", { type: "number", min: 1, max: 65535, value: curPort, inputmode: "numeric", "aria-label": "Port" });
    port.style.maxWidth = "120px";
    const all = h("input", { type: "checkbox", checked: allNow || !list.length });
    const boxes = list.map((ip) => {
      const info = w.addrs.find((a) => a.address === ip);
      const pre = current.size ? current.has(ip) : info && !virtual.test(info.interface);
      const cb = h("input", { type: "checkbox", value: ip, checked: pre });
      return h("label", { class: "check" }, cb, h("span", { class: "mono" }, ip),
        h("span", { class: "small muted", style: { marginLeft: "auto" } }, info ? `${info.public ? "public" : "private"} · ${info.interface}` : "configured"));
    });
    const listBox = h("fieldset", { style: { border: 0, margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: "8px" } },
      h("legend", { class: "sr-only" }, "Addresses"), boxes);
    const sync = () => { listBox.hidden = all.checked; };
    all.addEventListener("change", sync);
    sync();
    put(body, wizHead(w, "Addresses", "Devices and your router will use these addresses as their DNS server."),
      h("label", { class: "check" }, all, h("span", null, h("strong", null, "All addresses of this server"), h("span", { class: "small muted", style: { display: "block" } }, "Also ones it gets later. Good when the address can change."))),
      boxes.length ? listBox : null,
      h("label", { class: "block" }, "Port (53 is the standard DNS port; devices and routers expect it)", port),
      h("p", { class: "small muted", style: { margin: 0 } }, "If another DNS server, such as AdGuard Home, already uses this port, stop it first or choose another port."),
      wizNav(w, render, () => {
        const p = Number(port.value);
        if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error("The port must be a number from 1 to 65535.");
        if (all.checked) { w.values["server.listen"] = [":" + p]; return; }
        const ips = boxes.map((b) => b.querySelector("input")).filter((c) => c.checked).map((c) => c.value);
        if (!ips.length) throw new Error("Pick at least one address, or All addresses.");
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
    put(body, wizHead(w, "Upstreams", "Where queries go when the answer is not cached; the fastest healthy one answers. Cloudflare and Quad9 are filled in, both over encrypted DNS. Keep them or choose others."),
      h("div", { class: "chips" }, h("span", { class: "small muted" }, "Add:"), presets.map(([n, list]) =>
        h("button", { type: "button", class: "btn small", onclick: () => { prim.value = [...new Set([...lines(prim.value), list[0]])].join("\n"); } }, n))),
      h("label", { class: "block" }, "Primary, one per line: https://…/dns-query, tls://host, quic://host or an IP address", prim),
      h("label", { class: "block" }, "Fallback, used only if all primaries fail (optional)", fb),
      wizNav(w, render, () => {
        w.values["upstream.primary"] = lines(prim.value);
        w.values["upstream.fallback"] = lines(fb.value);
        if (!w.values["upstream.primary"].length) throw new Error("Add at least one primary upstream.");
      }));
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
        const hosts = w.values["server.listen"].map(hostOf);
        Object.assign(w.values, {
          "tls.certificate": "acme", "tls.domains": [d], "tls.email": mail.value.trim(),
          "dot.listen": hosts.map((x) => withPort(x, 853)), "doq.listen": hosts.map((x) => withPort(x, 853)),
          "doh.https_listen": hosts.map((x) => withPort(x, 443)),
        });
      }));
  },
  // 4: review
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
  let ips = (w.values["server.listen"] || []).map(hostOf).filter((x) => x && x !== "0.0.0.0" && x !== "::");
  if (!ips.length) ips = w.addrs.filter((a) => !a.loopback && !/^fe80/i.test(a.address)).map((a) => a.address);
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
    h("div", { class: "wizhead" }, h("div", { class: "brand" }, icon.logo(28), h("span", null, "DNSNova"))),
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
  ["Status", [["Overview", "overview", "overview"], ["Upstreams", "upstreams", "upstreams"], ["Query log", "querylog", "querylog"]]],
  ["Settings", [["DNS & upstreams", "settings/dns", "dns"], ["Encrypted DNS", "settings/encryption", "lock"], ["Access & limits", "settings/access", "shield"], ["Admin", "settings/admin", "user"]]],
  ["Tools", [["Setup guide", "tools/guide", "phone"], ["Compare upstreams", "tools/lookup", "compare"]]],
];

function route() {
  return (location.hash.replace(/^#\/?/, "") || "overview").split("?")[0];
}

async function showApp() {
  const main = h("main", { class: "main", id: "main", tabindex: "-1" });
  const nav = h("nav", { class: "nav", "aria-label": "Main" });
  const server = h("div", { class: "server" });
  const menu = h("button", { type: "button", class: "btn small menu", "aria-expanded": "false", "aria-controls": "sidebody" }, "Menu");
  const side = h("aside", { class: "side" },
    h("div", { class: "brand" }, icon.logo(24), h("span", null, "DNSNova"), menu),
    h("div", { class: "sidebody", id: "sidebody" }, searchBox(), nav,
      h("div", { class: "sidefoot" }, appearance(), server)));
  const setMenu = (open) => { side.classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); menu.textContent = open ? "Close" : "Menu"; };
  menu.addEventListener("click", () => setMenu(!side.classList.contains("open")));
  mount(h("div", { class: "shell" }, side, main));
  const drawNav = () => fill(nav, ...NAV.map(([title, items]) => h("div", { class: "navgroup" },
    h("div", { class: "navtitle" }, title),
    items.map(([label, r, ic]) => h("a", { href: "#/" + r, "aria-current": route() === r ? "page" : null }, line(ic), h("span", null, label))))));
  const go = () => {
    setMenu(false);
    drawNav();
    stopTimer();
    fill(main, );
    const page = PAGES_BY_ROUTE[route()] || PAGES_BY_ROUTE.overview;
    page(main);
    main.focus({ preventScroll: true });
  };
  window.onhashchange = go;
  go();
  try {
    state.status = await api("GET", "/status");
    fill(server, h("div", null, h("div", { class: "ellipsis" }, state.status.domains[0] || location.hostname),
      h("div", { class: "mono" }, `${state.status.version} · up ${fmt.uptime(state.status.uptime_seconds)}`)),
      h("button", { type: "button", class: "btn link small", onclick: logout }, "Sign out"));
  } catch (e) { /* the page shows the error */ }
}

async function logout() {
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

function overview(main) {
  let range = sessionStorage.getItem("dnsnova-range") || "24h";
  const body = h("div", null, h("p", { class: "muted" }, "Loading…"));
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Time range" });
  const ranges = () => ({ "24h": ["1h", "24h"], "30d": ["1h", "24h", "7d", "30d"] })[state.status?.retention] || ["1h", "24h", "7d"];
  const drawSeg = () => fill(seg, ...ranges().map((r) => h("button", {
    type: "button", "aria-pressed": String(r === range),
    onclick: () => { range = r; sessionStorage.setItem("dnsnova-range", r); drawSeg(); load(); },
  }, r)));
  drawSeg();
  main.append(pageHead("Overview", null, seg), body);
  const load = async () => {
    try {
      const [st, stats, ups, ev] = await Promise.all([api("GET", "/status"), api("GET", "/stats?range=" + range), api("GET", "/upstreams"), api("GET", "/events?limit=40")]);
      const had = ranges().join();
      state.status = st;
      if (ranges().join() !== had) drawSeg();
      fill(body, ...drawOverview(st, stats, ups.upstreams, ev.events, range));
    } catch (e) {
      if (e.status !== 401) fill(body, errorBox(e));
    }
  };
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible") load(); }, 15000);
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

// The overview is a fixed grid: every card in a row has the same height and
// every list has a fixed number of rows, so the page looks the same with
// little data as with a lot. Missing rows are drawn as faint placeholders.
const SLOTS = 6;

function slots(items, n, row) {
  const out = items.slice(0, n).map(row);
  while (out.length < n) {
    const sk = h("span", { class: "skel" });
    sk.style.width = [46, 62, 38, 54, 70, 42][out.length % 6] + "%";
    out.push(h("li", { class: "slot ph", "aria-hidden": "true" }, sk));
  }
  return h("ul", { class: "slots" }, out);
}

function card(span, title, ic, right, ...body) {
  return h("section", { class: "card dcard " + span, "aria-label": title },
    h("header", { class: "dhead" }, line(ic, 15), h("h2", null, title), right ? h("div", { class: "dright" }, right) : null),
    ...body);
}

function meter(frac) {
  const bar = h("div");
  bar.style.width = Math.max(0, Math.min(1, frac)) * 100 + "%";
  return h("div", { class: "meter" }, bar);
}

function drawOverview(st, stats, ups, events, range) {
  const label = { "1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" }[range];
  const total = Object.values(stats.queries).reduce((a, b) => a + b, 0);
  const rejected = Object.values(stats.rejected).reduce((a, b) => a + b, 0);
  const answered = Object.values(stats.answers).reduce((a, b) => a + b, 0);
  const states = ups.map((u) => upState(u, ups).cls);
  const failing = states.filter((x) => x === "err").length, slow = states.filter((x) => x === "warn").length;
  const health = failing ? ["err", `${failing} of ${ups.length} upstreams failing`]
    : slow ? ["warn", `${slow} upstream${slow === 1 ? " is" : "s are"} slow`]
      : ["ok", `All ${ups.length} upstream${ups.length === 1 ? "" : "s"} healthy`];
  const open = PROTOS.map(([k]) => k).filter((k) => (st.listeners || {})[k]);

  // ---- summary ----
  const kpi = (lab, value, unit, note) => h("div", { class: "kpi" }, h("dt", null, lab),
    h("dd", null, value, unit ? h("span", { class: "unit" }, unit) : null), h("div", { class: "note" }, note));
  const summary = h("section", { class: "card summary s12", "aria-label": "Summary" },
    h("div", { class: "statusbar" },
      h("span", { class: "pill " + health[0] }, h("span", { class: "dot " + health[0] }), health[1]),
      h("span", { class: "mono" }, open.length ? open.map((p) => PROTOS.find(([k]) => k === p)[1] + (p === "doh3" ? "/3" : "")).join(" · ") : "no listeners"),
      h("span", { class: "mono grow r" }, `${st.version} · up ${fmt.uptime(st.uptime_seconds)}`)),
    h("div", { class: "summarybody" },
      h("div", { class: "hero" },
        h("div", { class: "label" }, "Median response · " + label),
        h("div", { class: "heroval" }, h("span", { class: "big" }, total ? fmt.ms(stats.latency.all.p50_ms) : "–"), h("span", { class: "unit big-unit" }, "ms")),
        h("div", { class: "line" }, total ? `${answered ? fmt.pct(stats.cache_ratio) : "0%"} answered from cache` : "Waiting for the first queries")),
      h("dl", { class: "kpis" },
        kpi("Queries", fmt.short(total), null, label),
        kpi("95th percentile", total && stats.latency.all.p95_ms ? fmt.ms(stats.latency.all.p95_ms) : "–", "ms", "of response times"),
        kpi("Rejected", fmt.short(rejected), null, rejected && total ? fmt.pct(rejected / total) + " of queries" : "by limits and access list"))));

  // ---- chart and upstreams ----
  const chart = card("s8", "Response time", "overview",
    h("div", { class: "legend" }, h("span", null, h("span", { class: "swatch" }), "median"), h("span", null, h("span", { class: "swatch dash" }), "95th percentile")),
    responseChart(stats.series || [], total, range, label));
  const primaries = ups.filter((u) => u.role === "primary"), lats = primaries.filter((u) => u.healthy && u.latency_ms).map((u) => u.latency_ms);
  const upCard = card("s4", "Upstreams", "upstreams", h("a", { href: "#/upstreams", class: "small" }, "Details"),
    h("ul", { class: "slots" }, ups.map((u) => {
      const us = upState(u, ups);
      return h("li", { class: "slot tall" }, h("span", { class: "dot " + us.cls, title: us.label }),
        h("div", { class: "grow" }, h("div", { class: "mono small ellipsis", title: u.address }, u.address),
          h("div", { class: "small muted" }, h("span", { class: "state " + us.cls }, us.label), ` · ${u.role}` + (u.queries ? ` · ${successRate(u)}` : ""))),
        h("span", { class: "num strong" }, u.latency_ms ? fmt.ms(u.latency_ms) + " ms" : "–"));
    })),
    h("footer", { class: "dfoot" },
      h("span", null, `${primaries.length} primary · ${ups.length - primaries.length} fallback`),
      h("span", { class: "num" }, lats.length ? "avg " + fmt.ms(lats.reduce((a, b) => a + b, 0) / lats.length) + " ms" : "")));

  // ---- four lists ----
  const protoMax = Math.max(1, ...PROTOS.map(([k]) => stats.queries[k] || 0));
  const protos = card("s3", "Protocols", "dns", null,
    slots(PROTOS, SLOTS, ([k, n, d]) => {
      const c = stats.queries[k] || 0;
      return h("li", { class: "slot" + (open.includes(k) ? "" : " off"), title: open.includes(k) ? `${n} ${d}` : `${n} ${d} (not listening)` }, h("span", { class: "nm ellipsis" }, h("strong", null, k === "doh3" ? "DoH3" : n), " ", h("span", { class: "muted small" }, k === "doh" ? "h2" : k === "doh3" ? "h3" : d.replace("TCP ", "").replace("UDP ", ""))),
        meter(c / protoMax), h("span", { class: "num" }, fmt.short(c)));
    }),
    h("footer", { class: "dfoot" }, h("span", null, "Total"), h("span", { class: "num strong" }, fmt.int(total))));
  const topCard = (title, ic, list, emptyNote) => {
    const most = Math.max(1, ...list.map((x) => x.count));
    return card("s3", title, ic, null,
      slots(list, SLOTS, (x, i) => h("li", { class: "slot" }, h("span", { class: "rank" }, i + 1), h("span", { class: "nm mono ellipsis", title: x.name }, x.name),
        meter(x.count / most), h("span", { class: "num" }, fmt.short(x.count)))),
      h("footer", { class: "dfoot" }, h("span", null, list.length ? `Top ${Math.min(list.length, SLOTS)} of ${list.length}` : emptyNote), h("span", { class: "muted" }, "5+ networks")));
  };
  const rej = Object.entries(stats.rejected).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  const rejMax = Math.max(1, ...rej.map(([, v]) => v));
  const limited = stats.top_limited_networks || [];
  const rejCard = card("s3", "Rejected", "shield", null,
    slots(rej, SLOTS, ([k, v]) => h("li", { class: "slot" }, h("span", { class: "nm ellipsis" }, REJECT_NAMES[k] || k), meter(v / rejMax), h("span", { class: "num" }, fmt.short(v)))),
    h("footer", { class: "dfoot" }, limited.length
      ? [h("span", null, "Busiest network"), h("span", { class: "mono" }, limited[0].name)]
      : [h("span", null, "No network over the limits"), h("span")]));

  // ---- events, certificate, privacy ----
  const merged = mergeEvents(events);
  const evCard = card("s6", "Events", "info", h("span", { class: "small muted" }, "never queries"),
    slots(merged, SLOTS, (e) => h("li", { class: "slot" },
      h("span", { class: "evicon " + (e.level === "error" ? "err" : e.level === "warn" ? "warn" : "") }, line(eventIcon(e), 14)),
      h("span", { class: "nm ellipsis" + (e.level === "error" ? " err" : ""), title: e.message }, e.message),
      e.count > 1 ? h("span", { class: "count", title: `${e.count} times in a row` }, "×" + e.count) : h("span"),
      h("span", { class: "small muted mono", title: new Date(e.time).toString() }, fmt.time(e.time, Date.now() - new Date(e.time) > 86400e3)))),
    h("footer", { class: "dfoot" }, h("span", null, "Starts, errors, logins and setting changes"), h("span", null, "last 200 kept in memory")));

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
    ["Client IP upstream", "Never", "ok"],
    ["Telemetry", "None", "ok"],
  ];
  const privCard = card("s3", "Privacy", "shield", null,
    h("dl", { class: "kvs" }, privRows.map(([k, v, cls]) => h("div", null, h("dt", null, k), h("dd", { class: cls }, v)))),
    h("footer", { class: "dfoot" }, h("span", null, "In memory only"), h("a", { href: "#/querylog" }, "Query log")));

  const notServing = st.serves_dns === false ? h("p", { class: "notice warn s12" }, "DNS is not served yet: no address is set. Choose addresses and upstreams in ", h("a", { href: "#/settings/access" }, "Access & limits"), " and ", h("a", { href: "#/settings/dns" }, "DNS & upstreams"), ".") : null;
  return [h("div", { class: "dash" }, notServing, summary, chart, upCard, protos,
    topCard("Top domains", "dns", stats.top_domains || [], "Nothing listed yet"),
    topCard("Not found", "alert", stats.top_nxdomains || [], "None"),
    rejCard, evCard, certCard, privCard)];
}

// responseChart draws the median as a line over a light area and the 95th
// percentile as a dashed line, with a readout under the pointer.
function responseChart(ser, total, range, label) {
  if (ser.length < 2 || !total) {
    return h("div", { class: "chartempty" },
      s("svg", { viewBox: "0 0 600 120", preserveAspectRatio: "none", "aria-hidden": "true" },
        s("path", { d: "M0 92 C 80 88, 120 60, 200 66 S 330 96, 400 70 S 520 40, 600 52", class: "ghost", "vector-effect": "non-scaling-stroke" })),
      h("div", null, h("strong", null, "Not enough data yet"),
        h("div", { class: "small muted" }, range === "1h" ? "The first points appear after a minute or two of traffic." : "Points here are " + (range === "24h" ? "five minutes" : "an hour") + " apart. Choose 1h to see the first minutes.")));
  }
  const W = 600, H = 170, top = 10, base = 160;
  const maxV = Math.max(1, ...ser.map((p) => p.latency.p95_ms)) * 1.15;
  const x = (i) => (i * W) / (ser.length - 1);
  const y = (v) => base - (v / maxV) * (base - top);
  const pts = (key) => ser.map((p, i) => `${x(i).toFixed(1)},${y(p.latency[key]).toFixed(1)}`).join(" ");
  const area = `0,${base} ${pts("p50_ms")} ${W},${base}`;
  const cursor = s("line", { class: "cursor", x1: 0, x2: 0, y1: top, y2: base, "vector-effect": "non-scaling-stroke", visibility: "hidden" });
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": `Median and 95th percentile response time, ${label}; highest ${fmt.ms(maxV / 1.15)} ms` },
    [top, (top + base) / 2, base].map((yy) => s("line", { class: "grid", x1: 0, x2: W, y1: yy, y2: yy, "vector-effect": "non-scaling-stroke" })),
    s("polygon", { class: "area", points: area }),
    s("polyline", { class: "p95", points: pts("p95_ms"), "vector-effect": "non-scaling-stroke" }),
    s("polyline", { class: "p50", points: pts("p50_ms"), "vector-effect": "non-scaling-stroke" }),
    cursor);
  const tip = h("div", { class: "tip", hidden: true });
  const scale = h("div", { class: "scale" }, h("span", null, fmt.ms(maxV / 1.15) + " ms"), h("span", null, "0"));
  const wrap = h("div", { class: "chartwrap" }, svg, scale, tip);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => ser[Math.round(f * (ser.length - 1))].t);
  const show = (ev) => {
    const r = svg.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width));
    const i = Math.round(f * (ser.length - 1));
    const p = ser[i];
    cursor.setAttribute("x1", x(i));
    cursor.setAttribute("x2", x(i));
    cursor.setAttribute("visibility", "visible");
    fill(tip, h("div", { class: "mono small" }, fmt.time(p.t, range === "7d" || range === "30d" ? "full" : false)),
      h("div", null, h("span", { class: "swatch" }), " median ", h("strong", { class: "num" }, fmt.ms(p.latency.p50_ms) + " ms")),
      h("div", null, h("span", { class: "swatch dash" }), " 95th ", h("strong", { class: "num" }, fmt.ms(p.latency.p95_ms) + " ms")),
      h("div", { class: "muted" }, fmt.int(p.queries) + " queries"));
    tip.hidden = false;
    const left = (i / (ser.length - 1)) * r.width;
    tip.style.left = Math.min(Math.max(0, left - tip.offsetWidth / 2), r.width - tip.offsetWidth) + "px";
  };
  svg.addEventListener("pointermove", show);
  svg.addEventListener("pointerdown", show);
  svg.addEventListener("pointerleave", () => { tip.hidden = true; cursor.setAttribute("visibility", "hidden"); });
  const names = ticks.map((t, i) => (i === 4 ? "now" : fmt.time(t, range === "7d" || range === "30d")));
  return [wrap, h("div", { class: "axis" }, names.map((n, i) => h("span", null, i && n === names[i - 1] ? "" : n)))];
}

function listenersChips(l) {
  const out = [];
  if (l.dot) out.push("DoT");
  if (l.doq) out.push("DoQ");
  if (l.doh) out.push("DoH h2");
  if (l.doh3) out.push("DoH h3");
  return out.map((x) => h("span", { class: "chip" }, x));
}

// ---------- upstreams and lookup ----------

function upstreamsPage(main) {
  const body = h("div", null, h("p", { class: "muted" }, "Loading…"));
  main.append(pageHead("Upstreams", "Status"), body);
  const load = async () => {
    try {
      const { upstreams } = await api("GET", "/upstreams");
      fill(body, h("section", { class: "card" }, h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["State", "Upstream", "Role", "Latency", "Queries", "Errors", "Last error"].map((t, i) => h("th", { scope: "col", class: i >= 3 && i <= 5 ? "r" : "" }, t)))),
        h("tbody", null, upstreams.map((u) => h("tr", null,
          h("td", null, (() => { const st = upState(u, upstreams); return h("span", { class: "state " + st.cls }, h("span", { class: "dot " + st.cls }), st.label); })()),
          h("td", { class: "mono" }, u.address), h("td", { class: "muted" }, u.role),
          h("td", { class: "r num" }, u.latency_ms ? fmt.ms(u.latency_ms) + " ms" : "–"),
          h("td", { class: "r num" }, fmt.int(u.queries)),
          h("td", { class: "r num" }, fmt.int(u.errors) + (u.queries ? ` · ${successRate(u)} ok` : "")),
          h("td", { class: "muted" }, u.last_error ? fmt.ago(u.last_error) : "never"))))))),
        h("p", { class: "small muted" }, "Latency is smoothed over recent queries. Slow means over 500 ms, or three times slower than the other primaries and over 50 ms. Standby: a fallback, used only when the primaries fail. Change the list in ", h("a", { href: "#/settings/dns" }, "DNS & upstreams"), "; ask each one the same question in ", h("a", { href: "#/tools/lookup" }, "Compare upstreams"), "."));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  };
  load();
  state.timer = setInterval(() => { if (document.visibilityState === "visible") load(); }, 15000);
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
          h("td", { class: "mono small" }, q.client), h("td", { class: "small" }, q.proto),
          h("td", { class: "mono small ellipsis", title: q.name }, q.name), h("td", { class: "small" }, q.type),
          h("td", { class: "small " + (q.rcode === "NOERROR" ? "" : "warn") }, q.rcode), h("td", { class: "small muted" }, q.source),
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
      fill(body,
        h("section", { class: "card" }, h("h2", null, "Addresses"), h("div", { class: "addrs" }, addrs.map(([k, v]) => copyrow(k, v))),
          info.port && info.port !== 53 ? h("p", { class: "notice warn small", style: { margin: 0 } }, `Plain DNS is on port ${info.port}. Most phones, computers and routers can only use port 53; set the port where they allow it.`) : null),
        h("section", { class: "card" }, h("h2", null, "Point a device or your router at DNSNova"),
          h("p", { class: "small muted", style: { margin: 0 } }, "Setting it once on the router covers every device on the network. Set it on a device to use it there only, or when away from home with encrypted DNS."),
          ...tabs(guides(info, { h, copyrow }), { h, fill })));
    } catch (e) { if (e.status !== 401) fill(body, errorBox(e)); }
  })();
}

// ---------- settings ----------

// Field types: text, list (one per line), bool, number, select, listen (a
// switch that fills a listen list from server.listen with a port).
const SETTINGS = {
  dns: {
    title: "DNS & upstreams",
    sections: [
      { title: "Upstreams", fields: [
        { key: "upstream.primary", label: "Primary upstreams", type: "list", help: "Asked first, in parallel; the fastest answer wins. https://…/dns-query, tls://host, quic://host, udp://IP or an IP address." },
        { key: "upstream.fallback", label: "Fallback upstreams", type: "list", help: "Used only when every primary fails or is slow." },
        { key: "upstream.bootstrap", label: "Bootstrap servers", type: "list", help: "Plain DNS servers (IP addresses) used only to find the upstreams' own addresses." },
        { key: "upstream.parallel", label: "Ask at once", type: "number", help: "How many primaries to ask in parallel." },
        { key: "upstream.timeout", label: "Timeout", type: "text", help: "How long to wait for an upstream, such as 3s." },
        { key: "upstream.fallback_delay", label: "Fallback delay", type: "text", help: "Ask the fallbacks if the primaries have not answered after this long." },
      ] },
      { title: "Cache", action: ["Clear cache", async () => { await api("POST", "/cache/clear"); toast("Cache cleared"); }], fields: [
        { key: "cache.size", label: "Size", type: "number", help: "Most answers kept." },
        { key: "cache.prefetch", label: "Prefetch", type: "bool", help: "Refresh popular answers shortly before they expire." },
        { key: "cache.serve_stale", label: "Serve stale", type: "text", help: "Keep answering from expired entries this long when upstreams fail (0s = off)." },
        { key: "cache.min_ttl", label: "Minimum TTL", type: "text", help: "Answers are kept at least this long." },
        { key: "cache.max_ttl", label: "Maximum TTL", type: "text", help: "Answers are kept at most this long." },
        { key: "cache.max_negative_ttl", label: "Maximum negative TTL", type: "text", help: "Longest time to remember that a name does not exist." },
      ] },
      { title: "Local names", fields: [
        { key: "local.records", label: "Names answered here", type: "list", help: "One per line: a name and an address, such as \u201cnas.home 192.168.1.5\u201d. \u201c*.dev.home 192.168.1.9\u201d covers every name under dev.home. Give a name both an IPv4 and an IPv6 address on two lines. 0.0.0.0 makes a name unreachable." },
      ] },
      { title: "Clients", fields: [
        { key: "ddr.enabled", label: "Discovery (DDR)", type: "bool", help: "Devices asking over plain DNS learn the encrypted addresses and switch automatically." },
      ] },
    ],
  },
  encryption: {
    title: "Encrypted DNS",
    certificate: true,
    sections: [
      { title: "Certificate", fields: [
        { key: "tls.certificate", label: "Certificate", type: "select", options: [["acme", "Let's Encrypt (automatic)"], ["files", "Certificate files"], ["off", "None"]], help: "One certificate serves DNS over TLS, QUIC and HTTPS." },
        { key: "tls.domains", label: "Domains", type: "list", help: "Names pointing to this server. The first is also used for discovery.", show: (v) => v["tls.certificate"] !== "off" },
        { key: "tls.email", label: "Email", type: "text", help: "Let's Encrypt writes here before a certificate expires (optional).", show: (v) => v["tls.certificate"] === "acme" },
        { key: "tls.challenge", label: "Validation", type: "select", options: [["http-01", "HTTP on port 80"], ["tls-alpn-01", "TLS on port 443"]], help: "How Let's Encrypt checks that this server owns the domain.", show: (v) => v["tls.certificate"] === "acme" },
        { key: "tls.ip_addresses", label: "Include IP addresses", type: "bool", help: "Lets clients switch to encrypted DNS automatically. Such certificates are renewed every few days.", show: (v) => v["tls.certificate"] === "acme" },
        { key: "tls.cert_file", label: "Certificate file", type: "text", help: "PEM file with the full chain; reloaded when it changes.", show: (v) => v["tls.certificate"] === "files" },
        { key: "tls.key_file", label: "Key file", type: "text", help: "Its private key. DNSNova must be able to read it.", show: (v) => v["tls.certificate"] === "files" },
      ] },
      { title: "Protocols", fields: [
        { key: "dot.listen", label: "DNS over TLS", type: "listen", port: 853, help: "Android Private DNS, iOS and most routers. TCP 853." },
        { key: "doq.listen", label: "DNS over QUIC", type: "listen", port: 853, help: "Faster on mobile networks; fewer clients support it. UDP 853." },
        { key: "doh.https_listen", label: "DNS over HTTPS", type: "listen", port: 443, help: "Browsers, Windows and iOS profiles. TCP 443." },
        { key: "doh.http3", label: "Also over HTTP/3", type: "bool", sub: true, help: "The same address and port over UDP." },
        { key: "doh.path", label: "DoH path", type: "text", help: "Usually /dns-query." },
        { key: "status.enabled", label: "Public status page", type: "bool", help: "A page at the domain's address (https://domain/) with the addresses, setup steps for each kind of device, what this server keeps, and a check that a device is using it. It shows no statistics." },
        { key: "doh.listen", label: "Behind a reverse proxy", type: "text", help: "Plain HTTP for nginx or Caddy, such as 127.0.0.1:8053. Leave empty if unused." },
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
        { key: "server.listen", label: "DNS addresses", type: "list", help: "UDP and TCP, usually port 53. List each address rather than 0.0.0.0." },
      ] },
      { title: "Limits", fields: [
        { key: "limits.client_qps", label: "Per client", type: "number", help: "Queries a second from one address (0 = no limit)." },
        { key: "limits.client_burst", label: "Client burst", type: "number", help: "Short bursts allowed above that." },
        { key: "limits.prefix_qps", label: "Per network", type: "number", help: "Queries a second from one IPv4 /24 or IPv6 /48 (0 = no limit)." },
        { key: "limits.global_qps", label: "Whole server", type: "number", help: "Queries a second in total (0 = no limit)." },
        { key: "limits.rrl_rate", label: "Response rate limiting", type: "number", help: "Identical answers a second to one network; stops reflection attacks (0 = off)." },
        { key: "limits.block_any", label: "Refuse ANY queries", type: "bool", help: "They are mostly used for amplification." },
        { key: "limits.tcp_connections", label: "TCP connections", type: "number", help: "Open TCP and DoT connections at most." },
        { key: "limits.quic_connections", label: "QUIC connections", type: "number", help: "Open DoQ and HTTP/3 connections at most." },
        { key: "limits.upstream_concurrency", label: "Upstream queries at once", type: "number", help: "Queries waiting for upstreams at most." },
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
        { key: "admin.listen", label: "Admin address", type: "text", help: "127.0.0.1:7000 = only through an SSH tunnel (more secure); :7000 = from anywhere, with a password." },
        { key: "metrics.listen", label: "Metrics address", type: "text", help: "Prometheus metrics and the health check. Keep it on a private address." },
      ] },
    ],
    extra: ["Password", "Two-step verification", "Configuration history", "Edit the configuration file", "Clear statistics"],
  },
};

const PAGES_BY_ROUTE = {
  overview, upstreams: upstreamsPage, querylog: queryLogPage, "tools/lookup": lookupPage, "tools/guide": guidePage,
  "settings/dns": (m) => settingsPage(m, "dns"),
  "settings/encryption": (m) => settingsPage(m, "encryption"),
  "settings/access": (m) => settingsPage(m, "access"),
  "settings/admin": (m) => settingsPage(m, "admin"),
};

async function settingsPage(main, id) {
  const page = SETTINGS[id];
  main.classList.add("narrow");
  main.append(pageHead(page.title, "Settings"));
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
  for (const sec of page.sections) {
    const card = h("section", { class: "card pad0", "aria-label": sec.title },
      h("div", { class: "pagehead", style: { margin: "12px 0 4px" } }, h("h2", null, sec.title),
        sec.action ? h("button", { type: "button", class: "btn small", onclick: async () => { try { await sec.action[1](); } catch (e) { toast(e.message, "err"); } } }, sec.action[0]) : null));
    for (const f of sec.fields) {
      const row = fieldRow(f, form, () => { refresh(); });
      form.rows[f.key] = { f, row };
      card.append(row.el);
    }
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
    drawReview();
  };
  const changed = () => changedValues(form.cur, form.val);
  const drawReview = async () => {
    const set = changed();
    const n = Object.keys(set).length;
    const discard = h("button", { type: "button", class: "btn", disabled: !n, onclick: () => { form.val = { ...form.cur }; form.problems = {}; Object.values(form.rows).forEach((r) => r.row.reset()); refresh(); } }, "Discard");
    const apply = h("button", { type: "button", class: "btn primary", disabled: true }, "Apply");
    const list = h("div");
    review.className = "review" + (n ? " dirty" : "");
    review.hidden = !n;
    fill(review, h("div", { class: "head" }, h("h2", null, n ? `${n} change${n === 1 ? "" : "s"} to apply` : "No unsaved changes"), discard, apply), list,
      h("div", { class: "small muted" }, "Applies without a restart. The previous settings are kept in Admin › Configuration history."));
    if (!n) { setProblems({}); return; }
    const seq = ++previewSeq;
    try {
      const p = await api("POST", "/config/preview", { hash: form.hash, set });
      if (seq !== previewSeq) return;
      setProblems({});
      const m = p.changes.length;
      review.querySelector("h2").textContent = `${m} change${m === 1 ? "" : "s"} to apply`;
      fill(list, changeList(p.changes, labelOf), p.warnings.length ? h("ul", { class: "small warn", style: { margin: 0 } }, p.warnings.map((x) => h("li", null, x))) : null,
        p.restart_required.length ? h("p", { class: "small warn" }, "Takes effect after a restart: " + p.restart_required.join(", ")) : null);
      apply.disabled = false;
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
    for (const [k, { row }] of Object.entries(form.rows)) row.problem(probs[k]);
  };
  const labelOf = (k) => form.rows[k]?.f.label || k;
  refresh();
  if (state.focusKey && form.rows[state.focusKey]) {
    const el = form.rows[state.focusKey].row.el;
    el.hidden = false;
    el.scrollIntoView({ block: "center" });
    el.classList.add("flash");
    el.querySelector("input,select,textarea,button")?.focus({ preventScroll: true });
  }
  state.focusKey = null;
}

function fieldRow(f, form, onchange) {
  const id = "f-" + f.key.replace(/\./g, "-");
  const prob = h("div", { class: "problem", id: id + "-err" });
  const set = (v) => { form.val[f.key] = v; onchange(); };
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
          const hosts = (form.val["server.listen"] || []).map(hostOf).filter(Boolean);
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
      break;
    }
    case "list": {
      ctl = h("textarea", { id, spellcheck: "false" });
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
      ctl = h("input", { type: "text", id, value: v, class: /listen|file|path|domains/.test(f.key) ? "mono" : null, spellcheck: "false" });
      ctl.addEventListener("input", () => set(ctl.value));
      reset = () => { ctl.value = form.val[f.key]; };
    }
  }
  const inline = f.type === "bool" || f.type === "listen";
  const labelEl = f.type === "bool" || f.type === "listen" ? h("span", { class: "label", id: id + "-l" }, f.label) : h("label", { for: id }, f.label);
  const el = h("div", { class: "field" + (inline ? " inline" : "") + (f.sub ? " sub" : ""), "data-key": f.key },
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
