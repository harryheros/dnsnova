// Setup steps for each kind of device, shared by the public status page and
// the admin interface's setup guide. The caller passes its element builder
// and copy row so both pages draw them the same way.
//
// info: { domain, doh, dot, doq, plain: [IPs], profile: base URL of the
// Apple profile ("" when there is none) }.

export function guides(info, { h, copyrow }) {
  const doh = info.doh || "", dot = info.dot && !info.dot.includes(":") ? info.dot : "";
  const ip = (info.plain || [])[0] || "";
  const prof = info.profile === undefined ? "" : info.profile;
  const step = (...kids) => h("li", null, ...kids);
  const bare = (el) => (el ? h("li", { class: "bare" }, el) : null);
  const path = (...p) => h("span", { class: "path" }, p.join(" › "));
  const ol = (...kids) => h("ol", { class: "steps-list" }, ...kids);
  const ipRow = ip ? bare(copyrow("DNS server", ip)) : null;
  const list = [];

  // Android: Private DNS when there is DNS over TLS on 853, otherwise the
  // Wi-Fi network's own DNS setting.
  list.push(["Android", dot
    ? [ol(step("Open ", path("Settings", "Network & internet", "Private DNS"), "."),
      step("Choose ", h("strong", null, "Private DNS provider hostname"), " and enter:"),
      bare(copyrow("Hostname", dot)),
      step("Save. Android 9 or later; menu names vary by maker."))]
    : [ol(step("Open ", path("Settings", "Wi-Fi"), ", then the settings of your network."),
      step("Set ", h("strong", null, "IP settings"), " to Static and enter as DNS 1:"), ipRow,
      step("Save. Android uses it on this Wi-Fi network only."))]]);

  list.push(["iPhone & Mac", (doh || dot) && prof !== null
    ? [ol(step("Download the profile on the device:"),
      bare(h("div", { class: "row" },
        doh ? h("a", { class: "btn primary", href: prof + "/dnsnova.mobileconfig?p=doh" }, "Profile, DNS over HTTPS") : null,
        dot ? h("a", { class: "btn", href: prof + "/dnsnova.mobileconfig?p=dot" }, "Profile, DNS over TLS") : null)),
      step("iPhone and iPad: ", path("Settings", "Profile Downloaded"), ", then Install."),
      step("Mac: ", path("System Settings", "Privacy & Security", "Profiles"), ", then Install."),
      step("The profile is not signed, so the system says “Unverified”. It only sets DNS; remove it there at any time."))]
    : [ol(step("iPhone and iPad: ", path("Settings", "Wi-Fi"), ", tap ⓘ next to your network, then ", path("Configure DNS", "Manual"), " and add:"), ipRow,
      step("Mac: ", path("System Settings", "Network", "Wi-Fi or Ethernet", "Details", "DNS"), ", then + and the same address."),
      (doh || dot) ? step("For encrypted DNS on Apple devices, turn on the public status page: it offers a profile to download.") : null)]]);

  list.push(["Windows", [ol(
    step("Open ", path("Settings", "Network & internet", "Wi-Fi or Ethernet", "Hardware properties"), "."),
    step("Next to DNS server assignment choose ", h("strong", null, "Edit"), ", then Manual, and turn on IPv4."),
    ip ? bare(copyrow("Preferred DNS", ip)) : step("Preferred DNS: this server's IP address."),
    doh ? step("DNS over HTTPS: ", h("strong", null, "On (manual template)"), ", with:") : step("Save."),
    doh ? bare(copyrow("Template", doh)) : null,
    step("Windows 11; on Windows 10, use Control Panel › Network adapter › IPv4 properties."))]]);

  if (doh) list.push(["Browsers", [ol(
    step("Chrome and Edge: ", path("Settings", "Privacy and security", "Security", "Use secure DNS"), ", choose Custom."),
    step("Firefox: ", path("Settings", "Privacy & Security", "DNS over HTTPS"), ", Max Protection, Custom."),
    bare(copyrow("Address", doh)),
    step("Only the browser uses it; other apps keep the system's DNS."))]]);

  list.push(["Router", [ol(
    step("Open your router's admin page (often 192.168.1.1 or 192.168.0.1)."),
    step("In the ", h("strong", null, "DHCP"), " or ", h("strong", null, "LAN"), " settings, set the DNS server it hands out to:"), ipRow,
    step("Leave the second DNS server empty, or devices may use it instead."),
    step("Devices pick it up when they reconnect, or after a restart."))]]);

  list.push(["Linux", [ol(
    ip && dot ? step("systemd-resolved, encrypted: in /etc/systemd/resolved.conf set ", h("code", null, `DNS=${ip}#${dot}`), " and ", h("code", null, "DNSOverTLS=yes"), ".")
      : ip ? step("systemd-resolved: in /etc/systemd/resolved.conf set ", h("code", null, `DNS=${ip}`), ".") : null,
    step("Then: ", h("code", null, "sudo systemctl restart systemd-resolved"), "."),
    info.dot ? bare(copyrow("DoT", info.dot)) : null,
    info.doq ? bare(copyrow("DoQ", info.doq)) : null,
    doh ? bare(copyrow("DoH", doh)) : null)]]);
  return list;
}

// tabs shows one guide at a time, starting on the visitor's platform.
export function tabs(list, { h, fill }) {
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
  const guess = /Android/.test(ua) ? "Android" : /iPhone|iPad|Macintosh/.test(ua) ? "iPhone & Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : null;
  pick(Math.max(0, list.findIndex(([n]) => n === guess)));
  return [bar, body];
}


// filtered describes the filtered service (info.filtered): its addresses,
// with Apple profiles when they can be offered, or null when it is off.
// prof is the profile base URL ("" for the page's own origin, null: none).
export function filtered(info, { h, copyrow }, prof) {
  const f = info.filtered;
  if (!f) return null;
  const note = h("p", { class: "small muted", style: { margin: 0 } },
    `Blocks ads, trackers and malicious sites (${f.rules.toLocaleString()} rules). Same server, same privacy; only these addresses filter.`);
  if (!f.doh && !f.dot && !f.doq && !(f.plain || []).length) {
    return [note, h("p", { class: "small", style: { margin: 0 } }, "Every address of this server filters.")];
  }
  const rows = [
    f.doh ? ["DNS over HTTPS", f.doh] : null,
    f.dot ? ["DNS over TLS", f.dot] : null,
    f.doq ? ["DNS over QUIC", f.doq] : null,
    ...(f.plain || []).map((ip) => ["Plain DNS", ip]),
  ].filter(Boolean);
  const apple = prof !== null && prof !== undefined && (f.doh || (f.dot && !f.dot.includes(":")));
  return [note, h("div", { class: "addrs" }, rows.map(([k, v]) => copyrow(k, v))),
    apple ? h("div", { class: "row" },
      f.doh ? h("a", { class: "btn", href: prof + "/dnsnova.mobileconfig?p=doh-filtered" }, "Apple profile, DNS over HTTPS") : null,
      f.dot && !f.dot.includes(":") ? h("a", { class: "btn", href: prof + "/dnsnova.mobileconfig?p=dot-filtered" }, "Apple profile, DNS over TLS") : null) : null];
}
