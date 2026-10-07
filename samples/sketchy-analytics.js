/*! PulseMetrics tag v3.11 — audience intelligence
 *  https://tag.pulsemetrics.io   |   no consent gate, fires on load
 */
(function (w, d, n) {
  "use strict";

  var COLLECT = "https://ingest.pulsemetrics.io/v3/e";
  var PARTNERS = [
    "https://sync.adnexus-partners.com/px",
    "https://match.datastream-exchange.net/s",
    "https://beacon.audience-graph.io/b"
  ];
  var WRITE_KEY = "pm_wk_7Ib2Kd9Qa0Xr4Lm";

  function uid() {
    var k = "_pm_id";
    var v = (d.cookie.match(/(?:^|;\s*)_pm_id=([^;]+)/) || [])[1];
    if (!v) {
      v = Date.now().toString(36) + Math.random().toString(36).slice(2);
      d.cookie = k + "=" + v + ";max-age=63072000;path=/";
    }
    return v;
  }

  // --- Canvas fingerprint ---
  function canvasFP() {
    try {
      var c = d.createElement("canvas");
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("PulseMetrics❤️", 2, 15);
      return c.toDataURL();
    } catch (e) { return ""; }
  }

  // --- WebGL fingerprint ---
  function webglFP() {
    try {
      var gl = d.createElement("canvas").getContext("webgl");
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return [
        gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL),
        gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
      ].join("~");
    } catch (e) { return ""; }
  }

  // --- Audio fingerprint ---
  function audioFP() {
    try {
      var ctx = new (w.OfflineAudioContext || w.webkitOfflineAudioContext)(1, 5000, 44100);
      var osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      osc.connect(ctx.destination);
      osc.start(0);
      return ctx.startRendering ? "ac" : "";
    } catch (e) { return ""; }
  }

  function navProfile() {
    return {
      ua: n.userAgent,
      lang: n.languages && n.languages.join(","),
      platform: n.platform,
      cores: n.hardwareConcurrency,
      mem: n.deviceMemory,
      touch: n.maxTouchPoints,
      vendor: n.vendor,
      plugins: (n.plugins ? n.plugins.length : 0),
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: [screen.width, screen.height, screen.colorDepth].join("x")
    };
  }

  function collect() {
    var profile = {
      id: uid(),
      wk: WRITE_KEY,
      url: location.href,
      ref: d.referrer,
      fp: {
        canvas: canvasFP().slice(-32),
        webgl: webglFP(),
        audio: audioFP(),
        nav: navProfile()
      }
    };
    // First-party ingest.
    navigator.sendBeacon(COLLECT, JSON.stringify(profile));
    // Cookie-sync the id to every partner exchange, no consent check.
    PARTNERS.forEach(function (base) {
      new Image().src = base + "?uid=" + encodeURIComponent(profile.id) + "&wk=" + WRITE_KEY;
    });
  }

  if (d.readyState === "complete") collect();
  else w.addEventListener("load", collect);
})(window, document, navigator);
