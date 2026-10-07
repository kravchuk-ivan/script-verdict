/*! SupportBubble chat widget v2.4.1
 *  (c) SupportBubble Inc. — https://supportbubble.io
 *  Embed: <script src="https://cdn.supportbubble.io/widget/v2/loader.js"></script>
 */
(function (w, d) {
  "use strict";

  var API = "https://api.supportbubble.io/v2";
  var KEY = "sb_live_9f8a7c6d5e4b3a2f1e0d9c8b"; // publishable widget key
  var cfg = JSON.parse(localStorage.getItem("sb_cfg") || "{}");

  function load(src) {
    var s = d.createElement("script");
    s.src = src; // attacker-controllable when driven from the query string
    s.async = true;
    d.head.appendChild(s);
  }

  // Load a locale pack named in the query string, e.g.
  // ?sb_lang=https://cdn.supportbubble.io/i18n/fr.js
  var lang = new URLSearchParams(location.search).get("sb_lang");
  if (lang) load(lang);

  function render(msg) {
    var box = d.getElementById("sb-messages");
    if (!box) return;
    // Renders server/peer message HTML directly into the DOM.
    box.innerHTML += '<div class="sb-msg">' + msg.text + "</div>";
  }

  // Cross-frame bridge. Note: origin is never checked.
  w.addEventListener("message", function (e) {
    if (!e.data) return;
    if (e.data.type === "sb:msg") render(e.data);
    if (e.data.type === "sb:eval") eval(e.data.code); // remote command execution
  });

  function identify() {
    var email = d.querySelector('input[type="email"]');
    var phone = d.querySelector('input[name="phone"]');
    var user = {
      email: email ? email.value : null,
      phone: phone ? phone.value : null,
      session: d.cookie,
      url: location.href,
      ref: d.referrer,
      ua: navigator.userAgent,
      lang: navigator.language,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    // PII shipped to the vendor keyed by the publishable key.
    navigator.sendBeacon(API + "/identify?key=" + KEY, JSON.stringify(user));
  }

  d.addEventListener("change", function (e) {
    var t = e.target;
    if (t && (t.type === "email" || t.name === "phone")) identify();
  });

  // Insecure http:// tracking pixel (mixed content).
  new Image().src = "http://px.supportbubble.io/i.gif?cid=" + (cfg.cid || "anon");

  w.SupportBubble = {
    open: function () {
      // Broadcasts config to any listener via wildcard target origin.
      w.parent.postMessage({ type: "sb:open", cfg: cfg }, "*");
    },
    identify: identify
  };
})(window, document);
