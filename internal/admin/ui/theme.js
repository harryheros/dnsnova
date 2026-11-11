// Applies the saved appearance before the page is drawn, so it never flashes
// the wrong colors. Dark is the default; "auto" follows the system.
(function () {
  var pref = "dark";
  try { pref = localStorage.getItem("dnsnova-theme") || "dark"; } catch (e) {}
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function apply() {
    var dark = pref === "dark" || (pref === "auto" && mq && mq.matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.documentElement.dataset.themePref = pref;
  }
  window.dnsnovaTheme = {
    get: function () { return pref; },
    set: function (p) {
      pref = p;
      try { localStorage.setItem("dnsnova-theme", p); } catch (e) {}
      apply();
    }
  };
  if (mq && mq.addEventListener) mq.addEventListener("change", apply);
  apply();
})();
