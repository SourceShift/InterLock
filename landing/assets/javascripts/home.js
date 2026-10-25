/* ============================================================================
   interlock -- the landing page's behaviour.

   Loaded only on the site root (overrides/main.html injects this from
   {% block scripts %}). Everything here is additive: the page is complete and
   readable with this file blocked. Nothing in it moves focus, gates content,
   or is needed to reach a link. It adds motion, sticky-nav state, the copy
   button, and the hero's particle field.

   Guarded on .il-home so an instant-navigation hop onto a docs page cannot
   leave an observer or a rAF loop running against elements that are gone.
   ========================================================================= */
(function () {
  "use strict";

  var root = document.querySelector(".il-home");
  if (!root) return;

  var reduce =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* --- reveal on scroll --------------------------------------------------
     Elements marked [data-il-reveal] start shifted (the CSS only applies the
     shift once body.il-motion is set, so with JS off they are simply visible)
     and fade in when they enter the viewport.
     ---------------------------------------------------------------------- */
  if (!reduce && "IntersectionObserver" in window) {
    document.body.classList.add("il-motion");
    var revealObs = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting) return;
          en.target.classList.add("il-in");
          revealObs.unobserve(en.target);
        });
      },
      { threshold: 0.12 }
    );
    var vh = window.innerHeight;
    /* Document-scoped, not root-scoped, and that is load-bearing. The hero's
       stat strip is emitted by main.html's {% block hero %} -- which renders
       BEFORE the {% block container %} that wraps the .il-home prose. So it
       carries data-il-reveal while sitting outside .il-home, and a
       root.querySelectorAll would never see it: the CSS below would hide it
       and nothing would ever reveal it. Everything else uses root; only the
       reveal query reaches the whole document. Safe because this file loads on
       the landing page and nowhere else. */
    document.querySelectorAll("[data-il-reveal]").forEach(function (el) {
      /* Two jobs, and an element gets BOTH -- this is not an either/or.
         The CSS hides every [data-il-reveal] without .il-in, so anything on
         screen at load has to be marked now, before the next paint, or it
         renders invisible. But the load-time rect is not trustworthy on its
         own: the webfonts land after this script and reflow the hero, so an
         element measured just below the fold can end up on screen a frame
         later. Observing it as well costs nothing -- the callback is
         idempotent -- and catches exactly that shifted case. */
      if (el.getBoundingClientRect().top < vh) el.classList.add("il-in");
      revealObs.observe(el);
    });
  }

  /* --- sticky-nav highlight ---------------------------------------------
     The pills light up for the section occupying the middle of the viewport.
     ---------------------------------------------------------------------- */
  var pills = {};
  root.querySelectorAll(".il-nav__link[href^='#']").forEach(function (a) {
    pills[a.getAttribute("href").slice(1)] = a;
  });
  if ("IntersectionObserver" in window) {
    var secObs = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting) return;
          Object.keys(pills).forEach(function (id) {
            pills[id].classList.toggle("il-on", id === en.target.id);
          });
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    Object.keys(pills).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) secObs.observe(el);
    });
  }

  /* --- copy the install line -------------------------------------------- */
  var copyBtn = root.querySelector("[data-il-copy]");
  if (copyBtn) {
    var label = copyBtn.querySelector("[data-il-copy-label]");
    copyBtn.addEventListener("click", function () {
      var text = copyBtn.getAttribute("data-il-copy");
      var done = function () {
        if (!label) return;
        var was = label.textContent;
        label.textContent = "copied";
        copyBtn.classList.add("il-copied");
        setTimeout(function () {
          label.textContent = was;
          copyBtn.classList.remove("il-copied");
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        done();
      }
    });
  }

  /* --- spotlight ---------------------------------------------------------
     Cards get a soft light that follows the pointer, via --mx / --my.
     ---------------------------------------------------------------------- */
  root.addEventListener("mousemove", function (e) {
    var el = e.target.closest && e.target.closest("[data-il-spot]");
    if (!el) return;
    var r = el.getBoundingClientRect();
    el.style.setProperty("--mx", e.clientX - r.left + "px");
    el.style.setProperty("--my", e.clientY - r.top + "px");
  });

  /* --- the console's Run button ------------------------------------------
     Steps the three receipts in, and the counters with them. Purely a demo
     affordance; the receipt rows are already in the DOM and legible.
     ---------------------------------------------------------------------- */
  var runBtn = root.querySelector("[data-il-run]");
  var receipts = root.querySelectorAll("[data-il-receipt]");
  if (runBtn && receipts.length) {
    var timers = [];
    var replay = function () {
      timers.forEach(clearTimeout);
      timers = [];
      receipts.forEach(function (r) {
        r.style.opacity = "0.12";
        r.style.transform = "translateY(4px)";
      });
      receipts.forEach(function (r, i) {
        timers.push(
          setTimeout(function () {
            r.style.transition = "opacity .35s ease, transform .35s ease";
            r.style.opacity = "1";
            r.style.transform = "none";
          }, 450 + (i + 1) * 900)
        );
      });
      var lab = runBtn.querySelector("[data-il-run-label]");
      if (lab) {
        lab.textContent = "running";
        timers.push(setTimeout(function () { lab.textContent = "run"; }, 3400));
      }
    };
    runBtn.addEventListener("click", replay);
  }

  /* --- the hero's particle field ----------------------------------------
     A port of the design's canvas: calls travel left to right, are judged at
     the gate (the amber line at the copy column's edge), and either carry on
     coloured, are rewritten (a square), or stop dead (a burst). Purely
     decorative, so it does not run at all when the reader has asked for less
     motion.
     ---------------------------------------------------------------------- */
  if (reduce) return;

  var canvas = document.querySelector("[data-il-hero-canvas]");
  if (!canvas || !canvas.getContext) return;
  var hero = canvas.parentElement;
  var ctx = canvas.getContext("2d");
  var W = 0, H = 0, gate = 0, dpr = 1, frame = 0;
  var TR = null;
  var particles = [], bursts = [], flashes = [];
  var mouse = { x: -999, y: -999 };

  var LANE = 26;
  var TASKS = {
    allow: [
      ['read_file("notes.md")'],
      ['search("q3 pricing")'],
      ["GET api.acme.com/notes"],
      ["SELECT name FROM users LIMIT 50"],
      ['list_dir("./src")'],
      ['send_email(team, "weekly summary")'],
      ['calendar.create("standup")'],
      ['git commit -m "fix typo"']
    ],
    rewrite: [
      ['post_note("card 4242 4242…")', 'post_note("[REDACTED CREDIT_CARD]")'],
      ["SELECT * FROM orders", "SELECT * FROM orders LIMIT 100"],
      ['deploy("prod")', 'deploy("prod", dry_run=True)'],
      ['reply("key: sk-live-…")', 'reply("key: [REDACTED]")']
    ],
    block: [
      ['read_file("/etc/shadow")'],
      ["send_email(creds → unknown@mail.ru)"],
      ["POST evil.example/upload"],
      ['shell("rm -rf /")'],
      ["DROP TABLE users"],
      ["GET 169.254.169.254/latest/meta-data"],
      ["git push --force origin main"],
      ['upload("~/.ssh/id_rsa")'],
      ['follow "ignore previous instructions"']
    ]
  };
  var GLYPH = { allow: "✓ ", rewrite: "~ ", block: "✗ " };
  var COL = { allow: "95,214,138", rewrite: "245,192,74", block: "255,122,107" };
  var acc = "245,165,36";
  var labelled = 0;

  var hexRgb = function (h) {
    var m = String(h).trim().match(/^#?([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i);
    return m ? m.slice(1).map(function (x) { return parseInt(x, 16); }).join(",") : "245,165,36";
  };

  var spawn = function (x) {
    var lanes = Math.floor(H / LANE);
    if (lanes < 2) return;
    var r = Math.random();
    var verdict = r < 0.22 ? "block" : r < 0.36 ? "rewrite" : "allow";
    var lab = labelled < 9 && Math.random() < 0.4;
    var list = TASKS[verdict];
    var task = lab ? list[Math.floor(Math.random() * list.length)] : null;
    if (lab) labelled++;
    particles.push({
      x: x == null ? -40 : x,
      y: (1 + Math.floor(Math.random() * (lanes - 1))) * LANE,
      v: lab ? 0.55 + Math.random() * 0.45 : 0.6 + Math.random() * 1.4,
      len: 30 + Math.random() * 70,
      verdict: verdict,
      past: false,
      task: task
    });
  };

  var drawLabel = function (text, x, y, rgb, a) {
    var inText =
      TR && x > TR.x - 20 && x < TR.x + TR.w + 260 &&
      y > TR.y - 10 && y < TR.y + TR.h + 10;
    ctx.globalAlpha = inText ? a * 0.35 : a;
    ctx.fillStyle = "rgb(" + rgb + ")";
    ctx.fillText(text, x, y);
    ctx.globalAlpha = 1;
  };

  var resize = function () {
    var r = hero.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width;
    H = r.height;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    var proof = hero.querySelector("[data-il-proof]");
    var pr = proof && proof.getBoundingClientRect();
    var copy = proof && proof.previousElementSibling;
    var cr = copy && copy.getBoundingClientRect();
    TR = cr
      ? { x: cr.left - r.left, y: cr.top - r.top, w: cr.width, h: cr.height }
      : null;

    if (pr && pr.left - r.left > W * 0.25) {
      gate = pr.left - r.left - 28;
    } else {
      var tr = 0;
      if (copy) {
        copy.querySelectorAll("h1,p,div").forEach(function (el) {
          tr = Math.max(tr, el.getBoundingClientRect().right - r.left);
        });
      }
      gate = Math.min(W - 16, Math.max(tr + 40, W * 0.85));
    }
  };

  resize();
  if (window.ResizeObserver) new ResizeObserver(resize).observe(hero);
  window.addEventListener("resize", resize);

  hero.addEventListener("mousemove", function (e) {
    var r = hero.getBoundingClientRect();
    mouse.x = e.clientX - r.left;
    mouse.y = e.clientY - r.top;
  });

  for (var i = 0; i < 46; i++) spawn(Math.random() * W);

  var tick = function () {
    /* Stop for good once the hero leaves the document -- an instant-navigation
       hop to a docs page detaches it, and a detached node reports an all-zero
       rect, so the off-screen early-out below never fires and this loop would
       spin forever, painting into a canvas nobody can see. Returning before
       the re-arm is what ends it; checking after would leave one more frame
       scheduled each time. */
    if (!hero.isConnected) return;
    requestAnimationFrame(tick);
    if (document.hidden) return;
    if (hero.getBoundingClientRect().bottom < 0) return;
    if (frame++ % 60 === 0) {
      var cur = getComputedStyle(document.documentElement).getPropertyValue("--acc");
      if (cur) acc = hexRgb(cur) || acc;
    }

    ctx.clearRect(0, 0, W, H);

    var g = ctx.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, "rgba(" + acc + ",0)");
    g.addColorStop(0.35, "rgba(" + acc + ",.55)");
    g.addColorStop(0.75, "rgba(" + acc + ",.35)");
    g.addColorStop(1, "rgba(" + acc + ",0)");
    ctx.fillStyle = g;
    ctx.fillRect(gate - 0.5, 0, 1, H);
    ctx.globalAlpha = 0.18;
    ctx.fillRect(gate - 6, 0, 12, H);
    ctx.globalAlpha = 1;

    if (Math.random() < 0.55 && particles.length < 90) spawn();

    for (var j = particles.length - 1; j >= 0; j--) {
      var p = particles[j];
      var near = Math.max(
        0,
        1 - Math.hypot(mouse.x - p.x, mouse.y - p.y) / 180
      );
      p.x += p.v * (1 + near * 1.5);

      if (!p.past && p.x >= gate) {
        p.past = true;
        flashes.push({ y: p.y, life: 1, c: COL[p.verdict] });
        if (p.verdict === "block") {
          bursts.push({ x: gate, y: p.y, r: 2, life: 1, task: p.task });
          if (p.task) labelled--;
          particles.splice(j, 1);
          continue;
        }
      }
      if (p.x - p.len > W) {
        if (p.task) labelled--;
        particles.splice(j, 1);
        continue;
      }

      var rgb = p.past ? COL[p.verdict] : "236,235,230";
      var a = (p.past ? 0.55 : 0.22) + near * 0.4;
      var tail = p.past ? Math.max(gate, p.x - p.len) : p.x - p.len;

      var lg = ctx.createLinearGradient(tail, 0, p.x, 0);
      lg.addColorStop(0, "rgba(" + rgb + ",0)");
      lg.addColorStop(1, "rgba(" + rgb + "," + a + ")");
      ctx.strokeStyle = lg;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(tail, p.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();

      if (p.past && p.x - p.len < gate) {
        var lg2 = ctx.createLinearGradient(p.x - p.len, 0, gate, 0);
        lg2.addColorStop(0, "rgba(236,235,230,0)");
        lg2.addColorStop(1, "rgba(236,235,230,.22)");
        ctx.strokeStyle = lg2;
        ctx.beginPath();
        ctx.moveTo(p.x - p.len, p.y);
        ctx.lineTo(gate, p.y);
        ctx.stroke();
      }

      ctx.fillStyle = "rgba(" + rgb + "," + Math.min(1, a + 0.3) + ")";
      if (p.past && p.verdict === "rewrite") {
        ctx.fillRect(p.x - 2, p.y - 2, 4, 4);
      } else {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.6, 0, 6.283);
        ctx.fill();
      }

      if (p.task) {
        ctx.font = "10px 'Martian Mono', monospace";
        ctx.textBaseline = "alphabetic";
        if (!p.past) {
          ctx.textAlign = "right";
          drawLabel(p.task[0], p.x - 6, p.y - 6, "216,215,209", 0.55 + near * 0.4);
        } else {
          ctx.textAlign = "left";
          var t = GLYPH[p.verdict] + (p.task[1] || p.task[0]);
          drawLabel(
            t,
            Math.max(gate + 10, p.x - ctx.measureText(t).width - 6),
            p.y - 6,
            rgb,
            Math.min(1, (W - p.x) / 120) * 0.9
          );
        }
      }
    }

    for (var k = flashes.length - 1; k >= 0; k--) {
      var f = flashes[k];
      f.life -= 0.04;
      if (f.life <= 0) {
        flashes.splice(k, 1);
        continue;
      }
      ctx.fillStyle = "rgba(" + f.c + "," + f.life * 0.9 + ")";
      ctx.fillRect(gate - 1.5, f.y - 9, 3, 18);
    }

    for (var m = bursts.length - 1; m >= 0; m--) {
      var b = bursts[m];
      if (b.r < 26) b.r += 0.9;
      b.life -= b.task ? 0.012 : 0.025;
      if (b.life <= 0) {
        bursts.splice(m, 1);
        continue;
      }
      ctx.strokeStyle = "rgba(255,122,107," + b.life * 0.7 + ")";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(b.x, b.y, b.r, 0, 6.283);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(b.x - 4, b.y - 4);
      ctx.lineTo(b.x + 4, b.y + 4);
      ctx.moveTo(b.x + 4, b.y - 4);
      ctx.lineTo(b.x - 4, b.y + 4);
      ctx.stroke();

      if (b.task) {
        ctx.font = "10px 'Martian Mono', monospace";
        ctx.textAlign = "right";
        ctx.textBaseline = "alphabetic";
        drawLabel("✗ " + b.task[0], b.x - 12, b.y - 6, "255,122,107", Math.min(1, b.life * 1.6));
        ctx.save();
        ctx.globalAlpha = Math.min(1, b.life * 1.6) * 0.8;
        ctx.strokeStyle = "rgb(255,122,107)";
        ctx.lineWidth = 1;
        var w = ctx.measureText("✗ " + b.task[0]).width;
        ctx.beginPath();
        ctx.moveTo(b.x - 12 - w, b.y - 9.5);
        ctx.lineTo(b.x - 12, b.y - 9.5);
        ctx.stroke();
        ctx.restore();
      }
    }
  };

  tick();
})();
