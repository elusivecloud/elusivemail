(function() {
  "use strict";
  var SUN = '<svg class="icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6"/></svg>';
  var MOON = '<svg class="icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 13a8.3 8.3 0 0 1-11-11 8.3 8.3 0 1 0 11 11Z"/></svg>';
  Array.prototype.forEach.call(document.querySelectorAll("[data-theme-toggle]"), function(btn) {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.innerHTML = '<span class="icon-sun">' + SUN + '</span><span class="icon-moon">' + MOON + "</span>";
    btn.setAttribute("aria-label", "Toggle color theme");
    btn.addEventListener("click", function() {
      var cur = document.documentElement.getAttribute("data-theme");
      var sysDark = matchMedia("(prefers-color-scheme: dark)").matches;
      var next = (cur ? cur === "dark" : sysDark) ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try {
        localStorage.setItem("elusive_theme", next);
      } catch (e) {
      }
    });
  });
  var nav = document.getElementById("siteNav");
  if (nav) {
    var onScroll = function() {
      nav.classList.toggle("is-stuck", window.scrollY > 8);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }
  var burger = document.getElementById("navBurger");
  var mobile = document.getElementById("navMobile");
  var navScrim = document.getElementById("navScrim");
  if (burger && mobile) {
    var setOpen = function(open) {
      mobile.classList.toggle("show", open);
      if (navScrim) navScrim.classList.toggle("show", open);
      document.documentElement.classList.toggle("nav-lock", open);
      burger.setAttribute("aria-expanded", String(open));
    };
    burger.addEventListener("click", function() {
      setOpen(!mobile.classList.contains("show"));
    });
    if (navScrim) navScrim.addEventListener("click", function() {
      setOpen(false);
    });
    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape") setOpen(false);
    });
    Array.prototype.forEach.call(mobile.querySelectorAll("a"), function(a) {
      a.addEventListener("click", function() {
        setOpen(false);
      });
    });
  }
  var heart = document.getElementById("goalHeart");
  if (heart) {
    heart.addEventListener("click", function() {
      heart.classList.toggle("is-liked");
      heart.classList.remove("pop");
      void heart.offsetWidth;
      heart.classList.add("pop");
    });
  }
  var links = Array.prototype.slice.call(document.querySelectorAll(".secdoc__nav a"));
  if (links.length && "IntersectionObserver" in window) {
    var byId = {};
    links.forEach(function(a) {
      byId[a.getAttribute("href").slice(1)] = a;
    });
    var obs = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          links.forEach(function(l) {
            l.classList.remove("active");
          });
          if (byId[e.target.id]) byId[e.target.id].classList.add("active");
        }
      });
    }, { rootMargin: "-20% 0px -70% 0px" });
    Array.prototype.forEach.call(document.querySelectorAll(".secdoc section[id]"), function(s) {
      obs.observe(s);
    });
  }
  var revs = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
  if (revs.length && "IntersectionObserver" in window && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    document.documentElement.classList.add("reveal-on");
    var ro = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          e.target.classList.add("in-view");
          ro.unobserve(e.target);
        }
      });
    }, { rootMargin: "0px 0px -12% 0px", threshold: 0.15 });
    revs.forEach(function(el) {
      ro.observe(el);
    });
  } else {
    revs.forEach(function(el) {
      el.classList.add("in-view");
    });
  }
  var goalWrap = document.querySelector("[data-goal]");
  if (goalWrap && /^https?:$/.test(location.protocol)) {
    fetch("/api/stats").then(function(r) {
      return r.ok ? r.json() : null;
    }).then(function(d) {
      if (!d) return;
      var n = d.users || 0;
      var items = Array.prototype.slice.call(document.querySelectorAll(".milestone"));
      var goals = items.map(function(el) {
        return parseInt(el.getAttribute("data-at"), 10);
      });
      items.forEach(function(el) {
        var at = parseInt(el.getAttribute("data-at"), 10);
        var reached = n >= at;
        el.classList.toggle("is-reached", reached);
        var flag = el.querySelector("[data-goal-flag]");
        if (flag) flag.textContent = reached ? "reached" : "";
      });
      var idx = goals.findIndex(function(g) {
        return n < g;
      });
      var prev = idx <= 0 ? 0 : goals[idx - 1];
      var target = idx === -1 ? goals[goals.length - 1] : goals[idx];
      var pct = idx === -1 ? 100 : Math.max(3, Math.min(100, Math.round((n - prev) / (target - prev) * 100)));
      var countEl = goalWrap.querySelector("[data-goal-count]");
      if (countEl) countEl.textContent = n.toLocaleString();
      var fill = goalWrap.querySelector("[data-goal-fill]");
      if (fill) fill.style.width = pct + "%";
      var nextEl = goalWrap.querySelector("[data-goal-next]");
      if (nextEl) {
        var label = idx === -1 ? "" : items[idx].querySelector(".milestone__num").textContent;
        var title = idx === -1 ? "" : items[idx].querySelector("h3").textContent.toLowerCase();
        nextEl.textContent = idx === -1 ? " \xB7 every goal reached" : " \xB7 next at " + label + ": " + title;
      }
      goalWrap.hidden = false;
    }).catch(function() {
    });
  }
  var footBottom = document.querySelector(".site-footer__bottom");
  if (footBottom && /^https?:$/.test(location.protocol)) {
    fetch("/.well-known/build-info").then(function(r) {
      return r.ok ? r.json() : null;
    }).then(function(d) {
      if (!d || !d.commit) return;
      var short = d.commit.slice(0, 7);
      var badge = document.createElement("a");
      badge.className = "mono build-badge";
      badge.href = "security.html#provenance";
      badge.title = "Verify this build";
      badge.textContent = "running " + short + (d.imageDigest ? ", signed" : "");
      footBottom.insertBefore(badge, footBottom.firstChild);
    }).catch(function() {
    });
  }
})();
