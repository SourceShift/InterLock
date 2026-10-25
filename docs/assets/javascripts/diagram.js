/* Zoom and fullscreen for the Mermaid diagrams.
 *
 * How a diagram reaches the page: Zensical turns a ```mermaid fence into
 * <pre class="mermaid">, loads Mermaid from the network, renders the SVG into
 * a *closed* shadow root on a fresh <div class="mermaid">, and swaps that in
 * for the <pre>. Closed means nothing out here can reach the SVG, so this
 * script never tries. It works on the host element alone: the host is
 * wrapped in a group with a toolbar and a clipping viewport, and zoom and
 * pan are one CSS transform on the host. The browser scales the shadow tree
 * with it, and the drawing stays vector-crisp at any zoom.
 *
 * Hosts appear asynchronously (after Mermaid has loaded) and again after
 * every instant-navigation page swap, so a MutationObserver watches for
 * them rather than a one-off query at load.
 *
 * Fullscreen uses the Fullscreen API where the browser grants it and falls
 * back to a fixed overlay where it does not (iOS Safari has no element
 * fullscreen). Both states share the il-diagram--fullscreen class, so the
 * stylesheet has one thing to style.
 *
 * No dependencies and no network: this file and diagram.css are the feature.
 */
(function () {
  "use strict";

  // Instant navigation can evaluate this file more than once per visit. The
  // observer below is global, so a second copy would double-wrap nothing but
  // would double-handle every event.
  if (window.__ilDiagram) return;
  window.__ilDiagram = true;

  var MIN = 0.25;        // smallest zoom
  var MAX = 10;          // largest zoom; SVG stays crisp, so generous
  var STEP = 1.25;       // one button press or keypress
  var FIT_PAD = 0.94;    // fit leaves a little margin round the drawing
  var PAN_KEY = 40;      // px per arrow key

  var ICON = {
    plus: "M12 5v14M5 12h14",
    minus: "M5 12h14",
    enter: "M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7",
    exit: "M4 14h6v6M20 10h-6V4M14 10l7-7M3 21l7-7"
  };

  function icon(d) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
      'aria-hidden="true"><path d="' + d + '"/></svg>';
  }

  function button(cls, label, html) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "il-diagram__btn " + cls;
    b.setAttribute("aria-label", label);
    b.title = label;
    b.innerHTML = html;
    return b;
  }

  function el(tag, cls) {
    var e = document.createElement(tag);
    e.className = cls;
    return e;
  }

  function distance(a, b) {
    var dx = a.clientX - b.clientX, dy = a.clientY - b.clientY;
    return Math.sqrt(dx * dx + dy * dy);
  }

  // The controller of the diagram currently in fullscreen, if any. One
  // document-level fullscreenchange listener and one resize listener serve
  // every diagram through it, so a page swap leaks nothing per diagram.
  var current = null;

  function enhance(host) {
    if (host.closest(".il-diagram")) return;

    var group = el("div", "il-diagram");
    group.tabIndex = 0;
    group.setAttribute("role", "group");
    group.setAttribute("aria-label",
      "Diagram. Zoom with the buttons, Ctrl or Cmd and the wheel, or a pinch. " +
      "Drag to pan. F toggles fullscreen.");

    var bar = el("div", "il-diagram__bar");
    var out = button("il-diagram__out", "Zoom out", icon(ICON.minus));
    var level = button("il-diagram__level", "Reset zoom", "100%");
    var zin = button("il-diagram__in", "Zoom in", icon(ICON.plus));
    var full = button("il-diagram__full", "Fullscreen", icon(ICON.enter));
    bar.append(out, level, zin, full);

    var viewport = el("div", "il-diagram__viewport");
    var hint = el("div", "il-diagram__hint");
    hint.textContent = "Scroll or pinch to zoom · drag to pan · Esc to exit";

    host.parentNode.insertBefore(group, host);
    viewport.appendChild(host);
    group.append(bar, viewport, hint);

    var s = 1, tx = 0, ty = 0;   // the transform: translate(tx, ty) scale(s)
    var isFull = false;          // in fullscreen, native or overlay
    var nativeFull = false;      // ... granted by the Fullscreen API

    function apply() {
      host.style.transform = "translate(" + tx + "px," + ty + "px) scale(" + s + ")";
      level.textContent = Math.round(s * 100) + "%";
      // "Active" is when the diagram owns pointer gestures: zoomed, panned or
      // fullscreen. At rest it must stay passive, so a finger on it scrolls
      // the page and the wheel scrolls the page.
      if (isFull || Math.abs(s - 1) > 0.001 || tx || ty) {
        group.setAttribute("data-active", "");
      } else {
        group.removeAttribute("data-active");
      }
    }

    function clamp(v) { return Math.min(MAX, Math.max(MIN, v)); }

    // Zoom so that the viewport point (cx, cy) stays under the cursor.
    function zoomAt(factor, cx, cy) {
      var n = clamp(s * factor);
      if (n === s) return;
      tx = cx - (cx - tx) * (n / s);
      ty = cy - (cy - ty) * (n / s);
      s = n;
      apply();
    }

    function zoomCentre(factor) {
      zoomAt(factor, viewport.clientWidth / 2, viewport.clientHeight / 2);
    }

    function reset() { s = 1; tx = 0; ty = 0; apply(); }

    // The drawing's natural size, which the closed shadow root hides. Mermaid
    // emits the SVG at width 100% capped by a max-width equal to its natural
    // width, so two forced layouts recover both numbers: at a huge host width
    // the SVG is its natural size (giving the height), and at a tiny one its
    // height reveals the aspect ratio. An SVG with a fixed width instead
    // overflows the tiny host, and scrollWidth reports it directly.
    var natural = null;
    function measure() {
      if (natural) return natural;
      var width = host.style.width, transform = host.style.transform;
      host.style.transform = "none";
      host.style.width = "100000px";
      var hN = host.offsetHeight;
      host.style.width = "100px";
      var h2 = host.offsetHeight, sw = host.scrollWidth;
      host.style.width = width;
      host.style.transform = transform;
      var wN = sw > 100 ? sw : (h2 > 0 ? 100 * hN / h2 : 0);
      if (hN > 0 && wN > 0) natural = [wN, hN];   // cache only a real answer
      return [wN, hN];
    }

    // The drawing as currently laid out inside the host: centred, and no
    // wider than the host.
    function drawn() {
      var n = measure();
      var hostW = host.offsetWidth;
      var w = Math.min(n[0], hostW);
      var h = n[0] > 0 ? w * n[1] / n[0] : host.offsetHeight;
      return { w: w, h: h, x: (hostW - w) / 2, y: 0 };
    }

    // Scale and centre the drawing to the viewport. The fullscreen baseline.
    function fit() {
      var d = drawn();
      if (!(d.w > 0 && d.h > 0)) { reset(); return; }
      var vw = viewport.clientWidth, vh = viewport.clientHeight;
      s = clamp(Math.min(vw / d.w, vh / d.h) * FIT_PAD);
      tx = (vw - d.w * s) / 2 - d.x * s;
      ty = (vh - d.h * s) / 2 - d.y * s;
      apply();
    }

    function home() { if (isFull) fit(); else reset(); }

    // -- fullscreen ---------------------------------------------------------

    function setFull(on, native) {
      isFull = on;
      nativeFull = on && native;
      current = on ? ctl : (current === ctl ? null : current);
      group.classList.toggle("il-diagram--fullscreen", on);
      // The overlay fallback sits over a page that must not scroll under it.
      // Native fullscreen already takes the page out of the picture.
      document.documentElement.classList.toggle("il-diagram-lock", on && !native);
      full.innerHTML = icon(on ? ICON.exit : ICON.enter);
      full.setAttribute("aria-label", on ? "Exit fullscreen" : "Fullscreen");
      full.title = on ? "Exit fullscreen" : "Fullscreen";
      // The viewport's size changes with the class; lay out, then fit.
      requestAnimationFrame(home);
      if (on) group.focus({ preventScroll: true });
    }

    function enter() {
      var request = group.requestFullscreen;
      if (typeof request === "function") {
        var p;
        try { p = request.call(group); } catch (e) { p = Promise.reject(e); }
        // Granted: fullscreenchange sets the state. Refused: the overlay.
        if (p && typeof p.catch === "function") {
          p.catch(function () { setFull(true, false); });
        }
        return;
      }
      setFull(true, false);
    }

    function exit() {
      if (nativeFull && document.fullscreenElement === group) {
        var p = document.exitFullscreen();
        if (p && typeof p.catch === "function") p.catch(function () {});
      } else {
        setFull(false, false);
      }
    }

    var ctl = { group: group, setFull: setFull, fit: fit, isFull: function () { return isFull; } };
    group.__ilDiagram = ctl;

    // -- toolbar ------------------------------------------------------------

    out.addEventListener("click", function () { zoomCentre(1 / STEP); });
    zin.addEventListener("click", function () { zoomCentre(STEP); });
    level.addEventListener("click", home);
    full.addEventListener("click", function () { isFull ? exit() : enter(); });

    // -- wheel --------------------------------------------------------------

    // Only fullscreen takes the bare wheel. On the page the wheel keeps
    // scrolling the page, and zooming needs Ctrl or Cmd, which is also what a
    // trackpad pinch arrives as.
    viewport.addEventListener("wheel", function (e) {
      if (!isFull && !(e.ctrlKey || e.metaKey)) return;
      e.preventDefault();
      var r = viewport.getBoundingClientRect();
      var delta = e.deltaMode === 1 ? e.deltaY * 20 : e.deltaY;
      var factor = Math.min(2, Math.max(0.5, Math.exp(-delta * 0.0015)));
      zoomAt(factor, e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });

    // -- pointer: drag to pan, pinch to zoom --------------------------------

    var pointers = new Map();
    var drag = null;    // { x, y, tx, ty }
    var pinch = null;   // { d, s, tx, ty, mx, my }

    function midpoint() {
      var p = Array.from(pointers.values());
      var r = viewport.getBoundingClientRect();
      return {
        x: (p[0].clientX + p[1].clientX) / 2 - r.left,
        y: (p[0].clientY + p[1].clientY) / 2 - r.top,
        d: distance(p[0], p[1])
      };
    }

    viewport.addEventListener("pointerdown", function (e) {
      // At rest the diagram is passive so the page keeps scrolling by touch.
      if (!group.hasAttribute("data-active")) return;
      if (e.pointerType === "mouse" && e.button !== 0) return;
      pointers.set(e.pointerId, e);
      viewport.setPointerCapture(e.pointerId);
      if (pointers.size === 1) {
        drag = { x: e.clientX, y: e.clientY, tx: tx, ty: ty };
        group.setAttribute("data-dragging", "");
      } else if (pointers.size === 2) {
        drag = null;
        var m = midpoint();
        pinch = { d: m.d, s: s, tx: tx, ty: ty, mx: m.x, my: m.y };
      }
      e.preventDefault();
    });

    viewport.addEventListener("pointermove", function (e) {
      if (!pointers.has(e.pointerId)) return;
      pointers.set(e.pointerId, e);
      if (pinch && pointers.size === 2) {
        var m = midpoint();
        var n = clamp(pinch.s * (m.d / pinch.d));
        // Keep the drawing point that was under the first midpoint under the
        // current one, which both zooms and pans in one motion.
        tx = m.x - (pinch.mx - pinch.tx) * (n / pinch.s);
        ty = m.y - (pinch.my - pinch.ty) * (n / pinch.s);
        s = n;
        apply();
      } else if (drag) {
        tx = drag.tx + (e.clientX - drag.x);
        ty = drag.ty + (e.clientY - drag.y);
        apply();
      }
    });

    function release(e) {
      if (!pointers.has(e.pointerId)) return;
      pointers.delete(e.pointerId);
      if (viewport.hasPointerCapture(e.pointerId)) viewport.releasePointerCapture(e.pointerId);
      if (pointers.size === 0) {
        drag = null;
        pinch = null;
        group.removeAttribute("data-dragging");
      } else if (pointers.size === 1) {
        // Two fingers became one: carry on as a drag from here.
        pinch = null;
        var p = pointers.values().next().value;
        drag = { x: p.clientX, y: p.clientY, tx: tx, ty: ty };
      }
    }
    viewport.addEventListener("pointerup", release);
    viewport.addEventListener("pointercancel", release);

    viewport.addEventListener("dblclick", function (e) {
      e.preventDefault();
      home();
    });

    // -- keyboard -----------------------------------------------------------

    group.addEventListener("keydown", function (e) {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      var k = e.key;
      if (k === "+" || k === "=") zoomCentre(STEP);
      else if (k === "-" || k === "_") zoomCentre(1 / STEP);
      else if (k === "0") home();
      else if (k === "f" || k === "F") isFull ? exit() : enter();
      else if (k === "Escape" && isFull) exit();
      else if (k === "ArrowLeft" && group.hasAttribute("data-active")) { tx += PAN_KEY; apply(); }
      else if (k === "ArrowRight" && group.hasAttribute("data-active")) { tx -= PAN_KEY; apply(); }
      else if (k === "ArrowUp" && group.hasAttribute("data-active")) { ty += PAN_KEY; apply(); }
      else if (k === "ArrowDown" && group.hasAttribute("data-active")) { ty -= PAN_KEY; apply(); }
      else return;
      e.preventDefault();
    });

    apply();
  }

  // -- document-level plumbing ----------------------------------------------

  document.addEventListener("fullscreenchange", function () {
    var fs = document.fullscreenElement;
    var granted = fs && fs.__ilDiagram ? fs.__ilDiagram : null;
    if (granted) {
      granted.setFull(true, true);
    } else if (current) {
      current.setFull(false, false);
    }
  });

  window.addEventListener("resize", function () {
    if (current && current.isFull()) current.fit();
  });

  function scan(node) {
    if (node.nodeType !== 1) return;
    if (node.matches("div.mermaid")) enhance(node);
    else node.querySelectorAll("div.mermaid").forEach(enhance);
  }

  new MutationObserver(function (mutations) {
    mutations.forEach(function (m) { m.addedNodes.forEach(scan); });
  }).observe(document.documentElement, { childList: true, subtree: true });

  scan(document.body);
})();
