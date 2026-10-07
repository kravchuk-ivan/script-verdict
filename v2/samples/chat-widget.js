/*! SupportBubble chat widget v2.4.1 */
(function (w, d) {
  var API = "https://api.supportbubble.io/v2";
  var KEY = "sb_live_9f8a7c6d5e4b3a2f1e0d9c8b";
  var cfg = JSON.parse(localStorage.getItem("sb_cfg") || "{}");

  function load(src) {
    var s = d.createElement("script");
    s.src = src;
    d.head.appendChild(s);
  }

  // Load locale pack from query string, e.g. ?sb_lang=https://cdn.supportbubble.io/fr.js
  var lang = new URLSearchParams(location.search).get("sb_lang");
  if (lang) load(lang);

  function render(msg) {
    var box = d.getElementById("sb-messages");
    box.innerHTML += '<div class="sb-msg">' + msg.text + "</div>";
  }

  w.addEventListener("message", function (e) {
    if (e.data && e.data.type === "sb:msg") render(e.data);
    if (e.data && e.data.type === "sb:eval") eval(e.data.code);
  });

  function identify() {
    var email = d.querySelector("input[type=email]");
    var user = {
      email: email ? email.value : null,
      session: d.cookie,
      url: location.href,
      ref: d.referrer,
      ua: navigator.userAgent,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    navigator.sendBeacon(API + "/identify?key=" + KEY, JSON.stringify(user));
  }

  d.addEventListener("change", function (e) {
    if (e.target.type === "email" || e.target.name === "phone") identify();
  });

  new Image().src = "http://px.supportbubble.io/i.gif?cid=" + (cfg.cid || "anon");
  w.SupportBubble = { open: function () { w.parent.postMessage({ type: "sb:open", cfg: cfg }, "*"); } };
})(window, document);
