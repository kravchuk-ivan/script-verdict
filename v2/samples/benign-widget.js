/*! ShopKit currency formatter widget v1.4.0
 *  (c) ShopKit — MIT licensed
 *  Renders localized prices from the store's own pricing API.
 *  No cookies, no tracking, no third-party calls.
 */
(function () {
  "use strict";

  var API = "https://api.shopkit.dev/v1/rates"; // first-party, https only
  var cache = null;
  var cacheAt = 0;
  var TTL = 5 * 60 * 1000;

  function fetchRates() {
    var now = Date.now();
    if (cache && now - cacheAt < TTL) return Promise.resolve(cache);
    return fetch(API, { headers: { Accept: "application/json" }, credentials: "omit" })
      .then(function (r) {
        if (!r.ok) throw new Error("rates " + r.status);
        return r.json();
      })
      .then(function (data) {
        cache = data.rates || {};
        cacheAt = now;
        return cache;
      });
  }

  function formatMoney(amount, currency, locale) {
    return new Intl.NumberFormat(locale || undefined, {
      style: "currency",
      currency: currency || "USD"
    }).format(amount);
  }

  function convert(baseAmount, from, to, rates) {
    if (from === to) return baseAmount;
    var f = rates[from];
    var t = rates[to];
    if (!f || !t) return baseAmount;
    return (baseAmount / f) * t;
  }

  function render(rates) {
    var nodes = document.querySelectorAll("[data-price]");
    var target = document.documentElement.getAttribute("data-currency") || "USD";
    var locale = document.documentElement.lang || "en-US";

    Array.prototype.forEach.call(nodes, function (el) {
      var amount = parseFloat(el.getAttribute("data-price"));
      var from = el.getAttribute("data-currency") || "USD";
      if (isNaN(amount)) return;
      var value = convert(amount, from, target, rates);
      // textContent, never innerHTML — nothing here is interpreted as HTML.
      el.textContent = formatMoney(value, target, locale);
    });
  }

  function init() {
    fetchRates()
      .then(render)
      .catch(function (err) {
        if (window.console && console.warn) console.warn("[shopkit]", err.message);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.ShopKitCurrency = { format: formatMoney, refresh: init };
})();
