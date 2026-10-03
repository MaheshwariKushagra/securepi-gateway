/* SecurePi Gateway - console front end.
   Polls the JSON APIs and updates the DOM in place. No framework: the whole
   console is a handful of tables and charts, and a build step would cost more
   than it returns at this size. */

const SP = {
    range: localStorage.getItem("sp.range") || "6h",
    live: localStorage.getItem("sp.live") !== "0",
    intervalMs: 5000,
    timer: null,
    charts: {},
    notifSeen: null,
};

const STATUS_META = {
    new:            { label: "New",            cls: "" },
    investigating:  { label: "Investigating",  cls: "investigating" },
    resolved:       { label: "Resolved",       cls: "resolved" },
    false_positive: { label: "False positive", cls: "false_positive" },
};
const STATUS_ORDER = ["new", "investigating", "resolved", "false_positive"];
const LIST_STALE_AFTER_H = 48; // keep in sync with webapp.py's LIST_STALE_AFTER_HOURS

/* ------------------------------------------------------------- helpers */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, c => (
        { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
}

/* Count up to a new value rather than snapping. Small touch, but it makes a
   live dashboard feel continuous instead of twitchy. */
function animateNumber(el, to) {
    if (!el) return;
    const from = parseFloat(el.dataset.v || "0");
    if (from === to) { el.textContent = fmtNum(to); return; }
    el.dataset.v = to;
    const dur = 420, t0 = performance.now();
    const step = (t) => {
        const p = Math.min(1, (t - t0) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = fmtNum(from + (to - from) * eased);
        if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

function fmtNum(n) {
    if (Number.isInteger(n)) return n.toLocaleString();
    return (Math.round(n * 10) / 10).toLocaleString(undefined, { minimumFractionDigits: 1 });
}

/* Replays a one-shot CSS animation class (e.g. the badge pop). */
function bump(el) {
    el.classList.remove("bump");
    void el.offsetWidth;  // restart the animation if it's already applied
    el.classList.add("bump");
}

/* Marks rows that weren't in this container's previous render, so only
   genuinely new rows animate - a 5-second live refresh that re-renders the
   same rows moves nothing. `live` picks the treatment: a brief accent wash
   for rows that arrived on their own, a plain fade-in for rows revealed by
   the user's own filter or search. The first render never animates. */
function markNewRows(container, rowSelector, live) {
    if (!container) return;
    const prev = container.__rowKeys;
    const keys = new Set();
    $$(rowSelector, container).forEach(row => {
        const key = row.dataset.key;
        if (key == null) return;
        keys.add(key);
        if (prev && !prev.has(key)) row.classList.add(live ? "row-fresh" : "row-enter");
    });
    container.__rowKeys = keys;
}

/* Updates a stacked meter's segments in place so width changes glide
   (app.css transitions .meter > span) instead of being rebuilt each tick. */
function setMeter(el, segments) {
    if (!el) return;
    const wanted = segments.filter(sg => sg.pct > 0);
    const byClass = new Map($$(":scope > span", el).map(sp => [sp.className, sp]));
    wanted.forEach((sg, i) => {
        let span = byClass.get(sg.cls);
        if (!span) {
            span = document.createElement("span");
            span.className = sg.cls;
            span.style.width = "0%";
        }
        byClass.delete(sg.cls);
        if (el.children[i] !== span) el.insertBefore(span, el.children[i] || null);
    });
    byClass.forEach(sp => sp.remove());
    void el.offsetWidth;  // commit the 0% start of any new segment before growing it
    wanted.forEach(sg => { el.querySelector(`:scope > .${sg.cls}`).style.width = sg.pct + "%"; });
}

function setLive(on) {
    SP.live = on;
    localStorage.setItem("sp.live", on ? "1" : "0");
    const el = $("#liveIndicator");
    if (el) {
        el.classList.toggle("paused", !on);
        $("#liveLabel").textContent = on ? "Live" : "Paused";
    }
    const btn = $("#liveToggle");
    if (btn) { btn.textContent = on ? "Pause" : "Resume"; btn.classList.toggle("on", !on); }
    schedule();
}

function schedule() {
    clearInterval(SP.timer);
    if (SP.live) SP.timer = setInterval(tick, SP.intervalMs);
}

function tick() {
    refresh();
    refreshSystem();
    refreshNotifications();
    refreshDnsStatus();
}

/* --------------------------------------------------------------- toasts */

function toast(title, message, tone) {
    const stack = $("#toastStack");
    if (!stack) return;
    const el = document.createElement("div");
    el.className = "toast" + (tone ? ` ${tone}` : "");
    el.innerHTML = `<div class="title"></div><div class="msg"></div>`;
    el.querySelector(".title").textContent = title;
    el.querySelector(".msg").textContent = message || "";
    stack.appendChild(el);
    setTimeout(() => {
        el.classList.add("fade");
        setTimeout(() => el.remove(), 220);
    }, 4800);
}

/* ---------------------------------------------------------------- theme */

let themeTransitionId = 0;
let activeThemeTransition = null;

function applyTheme(theme) {
    const root = document.documentElement;
    if (theme === "light") root.dataset.theme = "light";
    else delete root.dataset.theme;
    try { localStorage.setItem("sp.theme", theme); } catch (e) { /* private mode: not remembered */ }
    updateThemeToggle();
    restyleCharts();
}

/* The point the new theme radiates out from: the centre of the topbar
   toggle, whichever way the switch was triggered (click, keyboard, or the
   command palette). Keyboard clicks carry no pointer coordinates, so the
   button's own box is used rather than the event. */
function themeOrigin() {
    const btn = $("#themeToggle");
    const r = btn && btn.getBoundingClientRect();
    if (r && r.width) return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    return { x: window.innerWidth / 2, y: 0 };
}

function setTheme(theme) {
    const root = document.documentElement;
    const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Fallback (no View Transitions support, or reduced motion requested):
    // a short crossfade of every surface.
    if (!document.startViewTransition || reduceMotion) {
        root.classList.add("theme-switching");
        applyTheme(theme);
        setTimeout(() => root.classList.remove("theme-switching"), 300);
        return;
    }

    /* View Transitions: the browser snapshots the page in the old theme,
       the theme is applied, and the new page is revealed through a circle
       growing from the toggle until it covers the farthest corner. Ordinary
       hover transitions are suspended for the moment of the switch
       (theme-instant), otherwise buttons would still be fading between
       colors inside the revealed area. */
    const { x, y } = themeOrigin();
    const radius = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
    const id = ++themeTransitionId;
    root.classList.add("theme-instant");

    const transition = document.startViewTransition(() => applyTheme(theme));
    activeThemeTransition = transition;
    transition.ready.then(() => {
        root.animate(
            { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radius}px at ${x}px ${y}px)`] },
            // Scaled to the distance covered so the sweep feels equally quick
            // on a phone (~0.4s) and a wide monitor (~0.7s).
            { duration: Math.min(720, Math.max(420, radius * 0.45)), easing: "cubic-bezier(.45, .05, .25, 1)",
              pseudoElement: "::view-transition-new(root)" },
        );
    }).catch(() => { /* skipped by a newer switch - that one animates instead */ });
    transition.finished.finally(() => {
        // A rapid second click starts a new transition; only the latest one
        // may lift the suspension.
        if (id === themeTransitionId) {
            root.classList.remove("theme-instant");
            activeThemeTransition = null;
        }
    });
}

/* While a view transition runs, the browser hit-tests every click to <html>
   (CSS pointer-events can't change that), so a click during the ~0.6s
   reveal would silently do nothing. Instead: finish the reveal at once,
   then hand the click to whatever is actually under the pointer - a quick
   second press of the toggle switches back, a nav link still navigates. */
document.addEventListener("click", (e) => {
    const transition = activeThemeTransition;
    if (!transition || e.target !== document.documentElement) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    const { clientX: x, clientY: y } = e;
    transition.skipTransition();
    transition.finished.finally(() => {
        const el = document.elementFromPoint(x, y);
        if (el && el !== document.documentElement) {
            // A bubbling event rather than el.click(): the hit may be an SVG
            // icon inside a button, which has no click() of its own.
            el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window, clientX: x, clientY: y }));
        }
    });
}, true);

function toggleTheme() {
    setTheme(currentTheme() === "light" ? "dark" : "light");
}

function updateThemeToggle() {
    const btn = $("#themeToggle");
    if (!btn) return;
    const label = currentTheme() === "light" ? "Switch to dark mode" : "Switch to light mode";
    btn.title = label;
    btn.setAttribute("aria-label", label);
}

/* Re-colors every chart already on the page without re-fetching its data:
   any color from the old palette is swapped for the same role in the new
   one, then each chart is rebuilt from its own (now recolored) config.
   Rebuilding rather than chart.update() matters - Chart.js caches the
   resolved colors of bar and doughnut segments, so an in-place update
   leaves those drawn in the old theme. */
function restyleCharts() {
    if (!window.Chart) return;
    const next = PAL();
    const prev = CHART_PALETTES[currentTheme() === "light" ? "dark" : "light"];
    const swap = {};
    Object.keys(prev).forEach(k => { swap[prev[k]] = next[k]; });
    const recolor = v => Array.isArray(v) ? v.map(recolor) : (typeof v === "string" && swap[v]) ? swap[v] : v;

    CHART_GRID = next.grid;
    CHART_TEXT = next.text;
    Chart.defaults.color = next.text;

    Object.entries(SP.charts).forEach(([key, chart]) => {
        const o = chart.options;
        Object.values(o.scales || {}).forEach(sc => {
            if (sc.grid) sc.grid.color = recolor(sc.grid.color);
            if (sc.border) sc.border.color = recolor(sc.border.color);
            if (sc.ticks) sc.ticks.color = recolor(sc.ticks.color);
        });
        const p = o.plugins || {};
        if (p.legend && p.legend.labels) p.legend.labels.color = next.text;
        if (p.tooltip) {
            p.tooltip.backgroundColor = next.tooltipBg;
            p.tooltip.borderColor = next.tooltipBorder;
            p.tooltip.titleColor = next.tooltipTitle;
            p.tooltip.bodyColor = next.tooltipBody;
        }
        chart.data.datasets.forEach(ds => {
            ds.borderColor = recolor(ds.borderColor);
            ds.hoverBackgroundColor = recolor(ds.hoverBackgroundColor);
            // Area fills are canvas gradients built from the line color.
            if (ds.backgroundColor && typeof ds.backgroundColor === "object" && !Array.isArray(ds.backgroundColor)) {
                ds.backgroundColor = gradient(chart.ctx, ds.borderColor);
            } else {
                ds.backgroundColor = recolor(ds.backgroundColor);
            }
        });
        const canvas = chart.canvas;
        const config = chart.config._config;
        chart.destroy();
        // Rebuild without the grow-in animation: the chart should already be
        // fully drawn when the new theme is revealed, not replay from zero.
        const opts = config.options || (config.options = {});
        const animation = opts.animation;
        opts.animation = false;
        const rebuilt = new Chart(canvas, config);
        rebuilt.options.animation = animation;
        SP.charts[key] = rebuilt;
    });
}

/* ------------------------------------------------------------- sidebar */

function initSidebar() {
    const shell = $("#shell");
    if (!shell) return;
    const collapsed = localStorage.getItem("sp.sidebarCollapsed") === "1";
    shell.classList.toggle("collapsed", collapsed);

    const setCollapsed = (v) => {
        // Lets the labels fade back in as the sidebar widens (app.css).
        shell.classList.add("sidebar-animating");
        clearTimeout(shell.__animTimer);
        shell.__animTimer = setTimeout(() => shell.classList.remove("sidebar-animating"), 450);
        shell.classList.toggle("collapsed", v);
        localStorage.setItem("sp.sidebarCollapsed", v ? "1" : "0");
    };
    const collapseBtn = $("#sidebarCollapse");
    const expandBtn = $("#sidebarExpand");
    if (collapseBtn) collapseBtn.addEventListener("click", () => setCollapsed(true));
    if (expandBtn) expandBtn.addEventListener("click", () => setCollapsed(false));
}

/* -------------------------------------------------------- notifications */

async function refreshNotifications() {
    try {
        const res = await fetch("/api/incidents?status=new");
        const d = await res.json();
        const items = d.incidents.slice(0, 8);
        const openCount = d.incidents.length;

        const badge = $("#notifBadge");
        const grew = SP.lastOpenCount != null && openCount > SP.lastOpenCount;
        SP.lastOpenCount = openCount;
        if (badge) { badge.textContent = openCount; badge.hidden = openCount === 0; if (grew) bump(badge); }
        const navBadge = $("#navIncidentBadge");
        if (navBadge) { navBadge.textContent = openCount; navBadge.hidden = openCount === 0; if (grew) bump(navBadge); }
        const panelCount = $("#notifPanelCount");
        if (panelCount) panelCount.textContent = openCount;

        renderNotifPanel(items);

        let seen = SP.notifSeen;
        if (!seen) {
            try { seen = new Set(JSON.parse(sessionStorage.getItem("sp.notifSeen") || "[]")); }
            catch (e) { seen = new Set(); }
            SP.notifSeen = seen;
        }
        const primed = sessionStorage.getItem("sp.notifPrimed") === "1";
        if (primed) {
            d.incidents.forEach(i => {
                if (!seen.has(i.id)) {
                    toast(i.severity === "high" ? "New high-severity incident" : "New incident",
                          i.title, i.severity === "high" ? "high" : "");
                }
            });
        }
        d.incidents.forEach(i => seen.add(i.id));
        sessionStorage.setItem("sp.notifSeen", JSON.stringify(Array.from(seen)));
        sessionStorage.setItem("sp.notifPrimed", "1");
    } catch (err) { console.error("notifications refresh failed", err); }
}

function renderNotifPanel(items) {
    const el = $("#notifPanelBody");
    if (!el) return;
    if (!items.length) {
        el.innerHTML = `<div class="empty"><span class="empty-icon">✓</span>No new incidents. The network is quiet.</div>`;
        return;
    }
    el.innerHTML = items.map(i => `
        <a class="notif-row" href="/incidents/${i.id}">
            <span class="sev-dot ${esc(i.severity)}"></span>
            <span>
                <div class="title">${esc(i.title)}</div>
                <div class="meta">${esc(i.device || "network-wide")} · ${esc(i.age)} ago</div>
            </span>
        </a>`).join("");
}

/* ----------------------------------------------------------- pipeline health */

async function refreshSystem() {
    try {
        const res = await fetch("/api/system");
        const d = await res.json();

        const dot = $("#pipelineDot");
        const label = $("#pipelineLabel");
        const sub = $("#pipelineSub");
        const statusBtn = $("#pipelineStatus");
        if (dot) dot.classList.toggle("bad", !d.healthy);
        if (label) label.textContent = d.healthy ? "Pipeline healthy" : "Pipeline issue";
        if (sub) sub.textContent = d.ingest.age ? `ingest ${d.ingest.age} ago` : "ingest idle";
        if (statusBtn) {
            statusBtn.title = "Ingest: " + (d.ingest.healthy ? "ok" : "stale") +
                (d.ingest.age ? ` (${d.ingest.age} ago)` : "") + "\n" +
                d.signals.map(s => `${s.signal.replace(/_/g, " ")}: ${s.healthy ? "ok" : "stale"}`).join("\n");
        }

        const hc = $("#healthGrid");
        if (hc) {
            const items = [
                { label: "Ingest pipeline", healthy: d.ingest.healthy,
                  value: d.ingest.age ? `last write ${d.ingest.age} ago` : "never run" },
            ].concat(d.signals.map(s => ({
                label: s.signal.replace(/_/g, " "), healthy: s.healthy,
                value: s.age ? `checked ${s.age} ago` : "never run",
            })));
            hc.innerHTML = items.map(i => `
                <div class="health-item ${i.healthy ? "" : "bad"}" title="${esc(i.value)}">
                    <span class="dot ${i.healthy ? "" : "bad"}"></span>
                    <span class="label">${esc(i.label)}</span>
                    <span class="value">${esc(i.value.replace(/^(last write|checked) /, ""))}</span>
                </div>`).join("");
            const summary = $("#healthSummary");
            if (summary) {
                const bad = items.filter(i => !i.healthy).length;
                summary.textContent = bad ? `${bad} of ${items.length} stale` : `${items.length} of ${items.length} healthy`;
                summary.className = "chip dot nocap " + (bad ? "high" : "ok");
            }
        }
    } catch (err) { console.error("system refresh failed", err); }
}

/* ------------------------------------------------------------ dns fail-open */

async function refreshDnsStatus() {
    try {
        const res = await fetch("/api/dns-status");
        const d = await res.json();
        const banner = $("#degradedBanner");
        const text = $("#degradedBannerText");
        if (!banner) return;
        banner.hidden = !d.active;
        if (d.active && text) {
            text.textContent = "DNS protection degraded - the DNS filter isn't answering" +
                (d.since ? ` (since ${d.since})` : "") +
                " - plaintext DNS is running unfiltered through a public resolver.";
        }
    } catch (err) { console.error("dns status refresh failed", err); }
}

/* --------------------------------------------------------------- charts */

/* Chart.js draws on a canvas, so it can't read CSS variables - each theme's
   chart colors live here instead. Keep these in step with the matching
   tokens in app.css (:root and :root[data-theme="light"]). */
const CHART_PALETTES = {
    dark: {
        accent: "#5aa2ff", violet: "#8b6cf6", high: "#f2545b", medium: "#f5a524",
        grid: "rgba(29,37,51,.85)", text: "#69758a", strong: "#e8edf5", surface: "#0e131c",
        muted: "#2a3549", mutedHover: "#35425a",
        tooltipBg: "rgba(19,26,37,.96)", tooltipBorder: "#2a3446", tooltipTitle: "#e8edf5", tooltipBody: "#97a2b5",
    },
    light: {
        accent: "#2563eb", violet: "#7c3aed", high: "#dc2626", medium: "#d97706",
        grid: "rgba(225,230,238,1)", text: "#64748b", strong: "#0f172a", surface: "#ffffff",
        muted: "#cbd5e1", mutedHover: "#b6c2d2",
        tooltipBg: "rgba(255,255,255,.98)", tooltipBorder: "#cdd5e1", tooltipTitle: "#0f172a", tooltipBody: "#475569",
    },
};

function currentTheme() {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}
function PAL() { return CHART_PALETTES[currentTheme()]; }

let CHART_GRID = PAL().grid;
let CHART_TEXT = PAL().text;

if (window.Chart) {
    Chart.defaults.font.family = getComputedStyle(document.documentElement).getPropertyValue("--sans").trim()
        || "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
    Chart.defaults.color = CHART_TEXT;
}

function baseChartOpts(extra) {
    return Object.assign({
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        interaction: { mode: "index", intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: PAL().tooltipBg,
                borderColor: PAL().tooltipBorder,
                borderWidth: 1,
                titleColor: PAL().tooltipTitle,
                bodyColor: PAL().tooltipBody,
                titleFont: { weight: "600", size: 12 },
                bodyFont: { size: 11.5 },
                padding: 10,
                cornerRadius: 8,
                caretSize: 5,
                displayColors: true,
                boxWidth: 8, boxHeight: 8, usePointStyle: true,
            },
        },
        scales: {
            x: {
                grid: { display: false },
                ticks: { color: CHART_TEXT, maxTicksLimit: 7, font: { size: 10 } },
                border: { color: CHART_GRID },
            },
            y: {
                beginAtZero: true,
                grid: { color: CHART_GRID, drawTicks: false },
                ticks: { color: CHART_TEXT, maxTicksLimit: 5, font: { size: 10 }, padding: 6 },
                border: { display: false },
            },
        },
    }, extra || {});
}

/* Draws the total in the middle of a doughnut chart - the one number a
   severity donut is actually read for. Reads live data at draw time, so it
   stays correct when upsertChart swaps the data in place. */
const donutCenterLabel = {
    id: "donutCenterLabel",
    afterDatasetsDraw(chart) {
        const meta = chart.getDatasetMeta(0);
        if (!meta || !meta.data.length) return;
        const total = chart.data.datasets[0].data.reduce((a, b) => a + (b || 0), 0);
        const { x, y } = meta.data[0];
        const ctx = chart.ctx;
        ctx.save();
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillStyle = PAL().strong;
        ctx.font = `700 26px ${Chart.defaults.font.family}`;
        ctx.fillText(total.toLocaleString(), x, y - 7);
        ctx.fillStyle = CHART_TEXT;
        ctx.font = `600 10px ${Chart.defaults.font.family}`;
        ctx.fillText("OPEN", x, y + 14);
        ctx.restore();
    },
};

function gradient(ctx, hex) {
    const g = ctx.createLinearGradient(0, 0, 0, 190);
    g.addColorStop(0, hex + "45");
    g.addColorStop(1, hex + "00");
    return g;
}

function upsertChart(key, canvasId, config) {
    const el = document.getElementById(canvasId);
    if (!el) return;
    if (SP.charts[key]) {
        const ch = SP.charts[key];
        ch.data.labels = config.data.labels;
        ch.data.datasets.forEach((ds, i) => {
            if (config.data.datasets[i]) ds.data = config.data.datasets[i].data;
        });
        ch.update("none");
    } else {
        SP.charts[key] = new Chart(el, config);
    }
}

function renderSparkline(key, canvasId, data, color) {
    const el = document.getElementById(canvasId);
    if (!el) return;
    upsertChart(key, canvasId, {
        type: "line",
        data: {
            labels: data.map((_, i) => i),
            datasets: [{ data, borderColor: color, borderWidth: 1.6, pointRadius: 0, tension: .35, fill: false }],
        },
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            scales: { x: { display: false }, y: { display: false } },
        },
    });
}

/* ------------------------------------------------------------ dashboard */

async function refreshDashboard() {
    const [ovRes, heatRes] = await Promise.all([
        fetch(`/api/overview?range=${SP.range}`),
        fetch(`/api/heatmap`),
    ]);
    const d = await ovRes.json();
    const heat = await heatRes.json();

    // KPI tiles
    animateNumber($("#kpiDevices"), d.kpis.devices_active);
    $("#kpiDevicesSub").textContent = `${d.kpis.devices_total} known`;
    animateNumber($("#kpiEvents"), d.kpis.events_per_min);
    $("#kpiEventsSub").textContent = `${d.kpis.events_total.toLocaleString()} stored`;
    animateNumber($("#kpiIncidents"), d.kpis.incidents_open);
    $("#kpiIncidentsSub").textContent = d.kpis.incidents_high
        ? `${d.kpis.incidents_high} high severity` : "none high severity";
    $("#kpiIncidentsTile").classList.toggle("alert", d.kpis.incidents_high > 0);
    animateNumber($("#kpiBlocked"), d.kpis.blocked);
    $("#kpiBlockedSub").textContent = `${d.kpis.block_rate}% of ${d.kpis.dns_total.toLocaleString()} queries`;
    $("#kpiTraffic").textContent = d.kpis.traffic;
    $("#kpiTrafficSub").textContent = `over ${d.range_label}`;

    // Meters for the two tiles that have no time series of their own.
    const devMeter = $("#kpiDevicesMeter");
    if (devMeter) {
        const pct = d.kpis.devices_total ? (d.kpis.devices_active / d.kpis.devices_total) * 100 : 0;
        setMeter(devMeter, [{ cls: "m-ok", pct }]);
        devMeter.title = `${d.kpis.devices_active} of ${d.kpis.devices_total} known devices online`;
    }
    const incMeter = $("#kpiIncidentsMeter");
    if (incMeter) {
        const sev = d.severity, total = sev.high + sev.medium + sev.low;
        setMeter(incMeter, ["high", "medium", "low"].map(k => ({ cls: `m-${k}`, pct: total ? (sev[k] / total) * 100 : 0 })));
        incMeter.title = `${sev.high} high · ${sev.medium} medium · ${sev.low} low`;
    }

    $("#lastUpdated").textContent = d.generated_at;

    renderSparkline("sparkEvents", "sparkEvents", d.series.events, PAL().accent);
    renderSparkline("sparkBlocked", "sparkBlocked", d.series.blocked, PAL().high);
    const traffic = d.series.down_kbps.map((v, i) => v + (d.series.up_kbps[i] || 0));
    renderSparkline("sparkTraffic", "sparkTraffic", traffic, PAL().violet);

    // Throughput
    const tctx = document.getElementById("throughputChart").getContext("2d");
    upsertChart("throughput", "throughputChart", {
        type: "line",
        data: {
            labels: d.series.labels,
            datasets: [
                { label: "Download", data: d.series.down_kbps, borderColor: PAL().accent,
                  backgroundColor: gradient(tctx, PAL().accent), fill: true, tension: .35,
                  pointRadius: 0, borderWidth: 2 },
                { label: "Upload", data: d.series.up_kbps, borderColor: PAL().violet,
                  backgroundColor: gradient(tctx, PAL().violet), fill: true, tension: .35,
                  pointRadius: 0, borderWidth: 2 },
            ],
        },
        options: baseChartOpts({
            plugins: {
                legend: { display: true, position: "top", align: "end",
                    labels: { color: CHART_TEXT, boxWidth: 8, boxHeight: 8,
                              usePointStyle: true, font: { size: 11 } } },
                tooltip: baseChartOpts().plugins.tooltip,
            },
            scales: Object.assign(baseChartOpts().scales, {
                y: Object.assign(baseChartOpts().scales.y, {
                    ticks: { color: CHART_TEXT, maxTicksLimit: 5, font: { size: 10 },
                             padding: 6, callback: v => v + " KB/s" },
                }),
            }),
        }),
    });

    // DNS: allowed vs blocked, stacked
    upsertChart("dns", "dnsChart", {
        type: "bar",
        data: {
            labels: d.series.labels,
            datasets: [
                { label: "Allowed", data: d.series.allowed, backgroundColor: PAL().muted,
                  hoverBackgroundColor: PAL().mutedHover, borderRadius: 3, stack: "dns", maxBarThickness: 22 },
                { label: "Blocked", data: d.series.blocked, backgroundColor: PAL().high,
                  borderRadius: 3, stack: "dns", maxBarThickness: 22 },
            ],
        },
        options: baseChartOpts({
            plugins: {
                legend: { display: true, position: "top", align: "end",
                    labels: { color: CHART_TEXT, boxWidth: 8, boxHeight: 8,
                              usePointStyle: true, font: { size: 11 } } },
                tooltip: baseChartOpts().plugins.tooltip,
            },
            scales: {
                x: Object.assign({}, baseChartOpts().scales.x, { stacked: true }),
                y: Object.assign({}, baseChartOpts().scales.y, { stacked: true }),
            },
        }),
    });

    // Severity donut
    upsertChart("severity", "severityChart", {
        type: "doughnut",
        data: {
            labels: ["High", "Medium", "Low"],
            datasets: [{
                data: [d.severity.high, d.severity.medium, d.severity.low],
                backgroundColor: [PAL().high, PAL().medium, PAL().accent],
                borderColor: PAL().surface, borderWidth: 3, hoverOffset: 6, borderRadius: 3,
            }],
        },
        plugins: [donutCenterLabel],
        options: {
            responsive: true, maintainAspectRatio: false, cutout: "72%",
            animation: { duration: 400 },
            plugins: {
                legend: { position: "bottom",
                    labels: { color: CHART_TEXT, boxWidth: 8, boxHeight: 8,
                              usePointStyle: true, padding: 14, font: { size: 11 } } },
                tooltip: baseChartOpts().plugins.tooltip,
            },
        },
    });

    renderBarList("#topTalkers", d.top_talkers.map(t => ({
        label: t.name, value: t.bytes_h, weight: t.bytes,
        href: `/devices/${t.id}`,
    })), "Traffic by device");

    renderBarList("#topBlocked", d.top_blocked.map(b => ({
        label: b.domain, value: b.count, weight: b.count, tone: "high",
    })), "No blocked domains in this window");

    renderBarList("#topDest", d.top_destinations.map(s => ({
        label: s.sni, value: s.count, weight: s.count,
    })), "No TLS destinations in this window");

    renderBarList("#signalMix", d.signal_mix.map(s => ({
        label: s.signal.replace(/_/g, " "), value: s.count, weight: s.count,
        tone: s.severity === "high" ? "high" : s.severity === "medium" ? "medium" : "",
    })), "No detections yet");

    renderBarList("#protocolMix", d.protocols.map(p => ({
        label: (p.name || "unknown").toUpperCase(), value: p.count, weight: p.count,
    })), "No protocol data in this window");

    renderBarList("#eventTypes", d.event_types.map(e => ({
        label: e.name.replace(/_/g, " "), value: e.count.toLocaleString(), weight: e.count, tone: "violet",
    })), "No events yet");

    renderFeed(d.recent_events);
    renderActiveIncidents(d.active_incidents);
    renderHeatmap(heat.grid, heat.days);
}

function renderHeatmap(grid, days) {
    const rowsEl = $("#heatmapRows");
    const daysEl = $("#heatmapDays");
    if (!rowsEl) return;
    const max = Math.max(1, ...grid.map(row => Math.max(...row)));
    rowsEl.innerHTML = grid.map(row => `<div class="heatmap-row">` + row.map(v => {
        const pct = v / max;
        const style = pct > 0
            ? `style="background:rgba(var(--accent-rgb),${(0.14 + pct * 0.78).toFixed(2)})"`
            : "";
        return `<div class="heatmap-cell" ${style} title="${v.toLocaleString()} event${v === 1 ? "" : "s"}"></div>`;
    }).join("") + `</div>`).join("");
    if (daysEl) daysEl.innerHTML = days.map(d => `<span>${esc(d)}</span>`).join("");
}

/* Rows are keyed by label and reused across refreshes, so on a live update
   existing bars glide to their new length and a newly ranked item grows in
   from zero - rather than the whole list being rebuilt every tick. */
function renderBarList(sel, items, emptyMsg) {
    const el = $(sel);
    if (!el) return;
    if (!items.length) { el.innerHTML = `<div class="empty">${esc(emptyMsg)}</div>`; return; }
    const max = Math.max(...items.map(i => i.weight)) || 1;
    let list = el.querySelector(":scope > .barlist");
    if (!list) {
        el.innerHTML = `<div class="barlist"></div>`;
        list = el.firstElementChild;
    }
    const existing = new Map($$(":scope > .barrow", list).map(r => [r.dataset.key, r]));
    const placed = items.map((i, idx) => {
        const key = `${i.label}|${i.href || ""}`;
        let row = existing.get(key);
        if (!row) {
            row = document.createElement("div");
            row.className = "barrow";
            row.dataset.key = key;
            const label = i.href
                ? `<a class="link barlabel" href="${esc(i.href)}">${esc(i.label)}</a>`
                : `<span class="barlabel" title="${esc(i.label)}">${esc(i.label)}</span>`;
            row.innerHTML = `${label}<span class="num dim"></span>
                <span class="bartrack"><span class="barfill" style="width:0%"></span></span>`;
        }
        existing.delete(key);
        row.querySelector(".num").textContent = i.value;
        const fill = row.querySelector(".barfill");
        fill.className = `barfill ${i.tone || ""}`;
        if (list.children[idx] !== row) list.insertBefore(row, list.children[idx] || null);
        return { fill, pct: Math.max(2, (i.weight / max) * 100) };
    });
    existing.forEach(r => r.remove());
    void list.offsetWidth;  // commit new bars at 0% so they visibly grow
    placed.forEach(({ fill, pct }) => { fill.style.width = `${pct}%`; });
}

function renderFeed(events) {
    const el = $("#eventFeed");
    if (!el) return;
    if (!events.length) { el.innerHTML = `<div class="empty">No events yet</div>`; return; }
    el.innerHTML = events.map(e => `
        <div class="feed-row" data-key="${esc(`${e.time}|${e.type}|${e.detail}|${e.device || e.src || ""}`)}">
            <span class="mono dim">${esc(e.time)}</span>
            <span class="type-tag ${esc(e.type)}">${esc(e.type.replace("dns_query", "dns"))}</span>
            <span class="truncate mono" title="${esc(e.detail)}">${esc(e.detail)}</span>
            <span class="dim">${e.blocked ? '<span class="chip high">blocked</span>' : esc(e.device || e.src || "")}</span>
        </div>`).join("");
    // Plain fade-in, not the accent wash: events arrive on almost every
    // refresh, and a wash that often would just be flicker.
    markNewRows(el, ".feed-row", false);
}

function renderActiveIncidents(items) {
    const el = $("#activeIncidents");
    if (!el) return;
    if (!items.length) {
        el.innerHTML = `<div class="empty"><span class="empty-icon">✓</span>No open incidents. The network is quiet.</div>`;
        return;
    }
    el.innerHTML = items.map(i => `
        <a class="inc-row ${esc(i.severity)}" href="/incidents/${i.id}" data-key="${i.id}">
            <span class="inc-body">
                <div class="inc-title" title="${esc(i.title)}">${esc(i.title)}</div>
                <div class="inc-meta"><span class="sev-label ${esc(i.severity)}">${esc(i.severity)}</span> · ${esc(i.device || "network-wide")} · ${esc(i.evidence_count)} events</div>
            </span>
            <span class="inc-age">${esc(i.age)} ago</span>
        </a>`).join("");
    markNewRows(el, ".inc-row", true);
}

/* -------------------------------------------------------------- devices */

let deviceSort = { key: "down", dir: -1 };

async function refreshDevices() {
    const res = await fetch("/api/devices");
    const d = await res.json();
    window.__devices = d.devices;
    renderDevices(true);
    $("#lastUpdated").textContent = new Date().toLocaleTimeString();
}

function renderDevices(live) {
    const tbody = $("#deviceRows");
    if (!tbody) return;
    const q = ($("#deviceSearch") && $("#deviceSearch").value || "").toLowerCase();
    const hideTest = $("#hideTest") && $("#hideTest").classList.contains("on");

    let rows = (window.__devices || []).filter(d => {
        if (hideTest && d.is_test) return false;
        if (!q) return true;
        return (d.name + " " + (d.ip || "") + " " + (d.hostname || "")).toLowerCase().includes(q);
    });

    rows.sort((a, b) => {
        const k = deviceSort.key;
        const av = a[k], bv = b[k];
        if (typeof av === "string") return av.localeCompare(bv) * deviceSort.dir;
        return ((av || 0) - (bv || 0)) * deviceSort.dir;
    });

    $("#deviceCount").textContent = `${rows.length} device${rows.length === 1 ? "" : "s"}`;

    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="9"><div class="empty">No devices match</div></td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(d => `
        <tr class="clickable" onclick="location.href='/devices/${d.id}'" data-key="${d.id}">
            <td style="white-space:nowrap"><span class="status-dot ${d.online ? "online" : "offline"}" title="${d.online ? "online" : "offline"}"></span><span class="row-title">${esc(d.name)}</span>
                ${d.is_test ? '<span class="chip neutral" style="margin-left:6px">test</span>' : ""}
                ${d.quarantined ? '<span class="chip high nocap dot" style="margin-left:6px">quarantined</span>' : ""}
                ${d.trust === "unknown" && !d.is_test ? '<span class="chip medium nocap" style="margin-left:6px" title="Not approved yet">unknown</span>' : ""}
                ${d.trust === "blocked" ? '<span class="chip high nocap" style="margin-left:6px">blocked</span>' : ""}
                ${d.profile && d.profile !== "standard" ? `<span class="chip neutral nocap" style="margin-left:6px">${esc(d.profile_label)}</span>` : ""}
                ${d.paused ? '<span class="chip medium nocap" style="margin-left:6px">filtering paused</span>' : ""}
                ${d.hostname && d.hostname !== d.name ? `<div class="row-sub mono" style="padding-left:16px">${esc(d.hostname)}</div>` : ""}</td>
            <td class="mono dim">${esc(d.ip || "—")}</td>
            <td>${d.randomized ? '<span class="chip neutral" title="Uses a randomized MAC">randomized</span>' : '<span class="dim">hardware</span>'}${d.mac_count > 1 ? `<span class="dim"> ·${d.mac_count} MACs</span>` : ""}</td>
            <td class="num">${esc(d.down_h)}</td>
            <td class="num">${esc(d.up_h)}</td>
            <td class="num">${d.dns.toLocaleString()}</td>
            <td class="num">${d.blocked ? `<span class="text-high">${d.blocked.toLocaleString()}</span>` : '<span class="dim">0</span>'}</td>
            <td class="num">${d.incidents ? `<span class="chip ${d.incidents_high ? "high" : "low"}">${d.incidents}</span>` : '<span class="dim">0</span>'}</td>
            <td class="num dim" style="white-space:nowrap">${esc(d.age)}</td>
        </tr>`).join("");
    markNewRows(tbody, "tr[data-key]", live === true);
}

/* ------------------------------------------------------------ incidents */

let incidentFilter = { severity: "", status: "" };

function statusMenuHtml(current, id) {
    return STATUS_ORDER.filter(s => s !== current).map(s =>
        `<button data-set-status="${s}" data-incident-id="${id}">Mark ${esc(STATUS_META[s].label.toLowerCase())}</button>`
    ).join("");
}

async function refreshIncidents(source) {
    const p = new URLSearchParams();
    if (incidentFilter.severity) p.set("severity", incidentFilter.severity);
    if (incidentFilter.status) p.set("status", incidentFilter.status);
    const res = await fetch("/api/incidents?" + p.toString());
    const d = await res.json();
    window.__incidents = d.incidents;

    $("#cntAll") && ($("#cntAll").textContent = d.counts.total);
    $("#cntHigh") && ($("#cntHigh").textContent = d.counts.high);
    $("#cntMedium") && ($("#cntMedium").textContent = d.counts.medium);
    $("#cntLow") && ($("#cntLow").textContent = d.counts.low);

    renderIncidents(source !== "user");
    $("#lastUpdated").textContent = new Date().toLocaleTimeString();
}

function renderIncidents(live) {
    const tbody = $("#incidentRows");
    if (!tbody) return;
    const q = ($("#incidentSearch") && $("#incidentSearch").value || "").toLowerCase();
    const rows = (window.__incidents || []).filter(i =>
        !q || (i.title + " " + (i.device || "") + " " + i.signal_type).toLowerCase().includes(q));

    $("#incidentCount").textContent = `${rows.length} incident${rows.length === 1 ? "" : "s"}`;

    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="8"><div class="empty"><span class="empty-icon">✓</span>No incidents match these filters</div></td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(i => {
        const meta = STATUS_META[i.status] || STATUS_META.new;
        return `
        <tr class="clickable" onclick="location.href='/incidents/${i.id}'" data-key="${i.id}">
            <td><span class="chip ${esc(i.severity)} dot">${esc(i.severity)}</span></td>
            <td><div class="row-title">${esc(i.title)}</div>
                <div class="row-sub truncate incident-desc" title="${esc(i.description || "")}">${esc(i.description || "")}</div></td>
            <td class="dim" style="white-space:nowrap"><span class="type-tag">${esc(i.signal_type.replace(/_/g, " "))}</span></td>
            <td style="white-space:nowrap">${i.device ? `<a class="link" href="/devices/${i.device_id}" onclick="event.stopPropagation()">${esc(i.device)}</a>` : '<span class="dim">—</span>'}</td>
            <td><span class="status-pill ${meta.cls}">${esc(meta.label)}</span></td>
            <td class="num">${i.evidence_count}</td>
            <td class="num dim" style="white-space:nowrap">${esc(i.age)} ago</td>
            <td style="width:1%" onclick="event.stopPropagation()">
                <div class="row-menu">
                    <button class="icon-btn row-menu-btn" data-toggle-menu aria-label="Actions">
                        <svg class="icon" width="16" height="16"><use href="#i-more"/></svg>
                    </button>
                    <div class="row-menu-list">${statusMenuHtml(i.status, i.id)}</div>
                </div>
            </td>
        </tr>`;
    }).join("");
    markNewRows(tbody, "tr[data-key]", live === true);
}

function initIncidentBlockDomain() {
    const btn = $("#incidentBlockDomain");
    if (!btn) return;
    const deviceId = btn.dataset.deviceId;
    const domain = btn.dataset.domain;

    btn.addEventListener("click", async () => {
        const reason = prompt(`Why block "${domain}" for this device?`, "blocked from an incident's playbook action");
        if (reason === null || !reason.trim()) return;  // cancelled, or empty
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering/block`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain, reason: reason.trim() }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Domain blocked for this device", domain, "ok");
            btn.disabled = true;
            btn.textContent = `Blocked ${domain}`;
        } catch (err) {
            toast("Could not block domain", "The DNS filter did not accept the change.", "high");
        }
    });
}

function initIncidentNotes() {
    const btn = $("#incidentNoteSave");
    const input = $("#incidentNoteInput");
    if (!btn || !input) return;
    const incidentId = btn.dataset.incidentId;

    const submit = async () => {
        const note = input.value.trim();
        if (!note) return;
        try {
            const res = await fetch(`/api/incidents/${incidentId}/notes`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ note }),
            });
            if (!res.ok) throw new Error("request failed");
            location.reload();
        } catch (err) {
            toast("Could not add note", "The note was not saved.", "high");
        }
    };
    btn.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
}

async function updateIncidentStatus(id, status) {
    try {
        const res = await fetch(`/api/incidents/${id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status }),
        });
        if (!res.ok) throw new Error("request failed");
        toast("Incident updated", (STATUS_META[status] || {}).label || status, "ok");
        if ($("#incidentActions")) {
            setTimeout(() => location.reload(), 500);
        } else if ($("#incidentRows")) {
            refreshIncidents();
        }
        refreshNotifications();
    } catch (err) {
        toast("Update failed", "Could not change the incident status.", "high");
    }
}

/* --------------------------------------------------------------- exports */

function csvCell(v) {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function exportCsv(filename, rows, columns) {
    const lines = [columns.map(c => c.label).join(",")];
    rows.forEach(r => lines.push(columns.map(c => csvCell(r[c.key])).join(",")));
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
}

/* --------------------------------------------------------- device detail */

function initDeviceRename() {
    const wrap = $("#deviceIdentity");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const display = $("#deviceNameDisplay");
    const trigger = $("#deviceNameEdit");
    if (!trigger) return;

    trigger.addEventListener("click", () => {
        const current = display.textContent;
        const input = document.createElement("input");
        input.value = current;
        display.replaceWith(input);
        input.focus();
        input.select();

        const commit = async () => {
            const val = input.value.trim();
            if (!val || val === current) { input.replaceWith(display); return; }
            try {
                const res = await fetch(`/api/devices/${deviceId}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ friendly_name: val }),
                });
                if (!res.ok) throw new Error("request failed");
                display.textContent = val;
                document.title = val + " · SecurePi Gateway";
                const topbarTitle = $(".topbar-title");
                if (topbarTitle) topbarTitle.textContent = val;
                toast("Device renamed", `Now labeled "${val}"`, "ok");
            } catch (err) {
                toast("Rename failed", "Could not update the device name.", "high");
            }
            input.replaceWith(display);
        };
        input.addEventListener("blur", commit);
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") input.blur();
            if (e.key === "Escape") { input.value = current; input.blur(); }
        });
    });
}

function initDeviceBaseline() {
    const badge = $("#baselineBadge");
    if (!badge) return;
    const deviceId = badge.dataset.deviceId;

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/baseline`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            if (d.flagged) {
                badge.textContent = "Baseline: unusual volume";
                badge.className = "chip high dot";
                badge.onclick = () => location.href = `/incidents/${d.incident_id}`;
            } else if (d.learning) {
                badge.textContent = `Baseline: learning (${d.days_seen}/${d.days_needed}d)`;
                badge.className = "chip neutral";
            } else {
                badge.textContent = "Baseline: normal";
                badge.className = "chip ok";
            }
        } catch (err) {
            badge.textContent = "Baseline: unknown";
        }
    }
    load();
}

function initDeviceFingerprint() {
    const wrap = $("#deviceFingerprint");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/fingerprint`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            const chips = [
                d.category ? `<span class="chip neutral">${esc(d.category)}</span>` : "",
                d.vendor ? `<span class="chip neutral">${esc(d.vendor)}</span>` : "",
                d.os ? `<span class="chip neutral">${esc(d.os)}</span>` : "",
                `<span class="chip dot ${d.confidence === "unknown" ? "neutral" : "ok"}">confidence: ${esc(d.confidence)}</span>`,
            ].join(" ");

            const evidenceRows = d.evidence.length
                ? d.evidence.map(e => `
                    <tr><td><span class="type-tag">${esc(e.source.replace(/_/g, " "))}</span></td>
                        <td class="truncate" title="${esc(e.detail)}">${esc(e.detail)}</td></tr>`).join("")
                : `<tr><td class="empty">No fingerprinting evidence yet</td></tr>`;

            const suggestion = d.suggested_profile ? `
                <div class="callout row" style="margin-top:12px">
                    <div>Looks like a ${esc(d.suggested_profile.label)} device - apply that native-tracker profile?</div>
                    <button class="btn primary sm" id="deviceFingerprintApplySuggestion">Apply profile</button>
                </div>` : "";

            wrap.innerHTML = `
                <div class="section-label">Fingerprint <span class="dim" style="text-transform:none; letter-spacing:0; font-weight:400">a second identity anchor, display only</span></div>
                <div class="hero-tags" style="margin:0 0 8px">${chips}</div>
                <table class="kv compact" style="margin:0 -16px; width:calc(100% + 32px)"><tbody>${evidenceRows}</tbody></table>
                ${suggestion}`;

            const applyBtn = $("#deviceFingerprintApplySuggestion");
            if (applyBtn) {
                applyBtn.addEventListener("click", () => {
                    const select = $("#deviceProfileSelect");
                    const apply = $("#deviceProfileApply");
                    if (!select || !apply) return;
                    // initDeviceProfiles() populates #deviceProfileSelect from its
                    // own async fetch, which may not have landed yet - wait
                    // briefly for the target option to actually exist rather than
                    // silently setting .value to something not there yet.
                    const trySelect = (attempt) => {
                        const has = Array.from(select.options).some(o => o.value === d.suggested_profile.vendor);
                        if (has) {
                            select.value = d.suggested_profile.vendor;
                            apply.click();
                        } else if (attempt < 20) {
                            setTimeout(() => trySelect(attempt + 1), 100);
                        } else {
                            toast("Could not apply profile", "The profile list hasn't loaded yet - try again.", "high");
                        }
                    };
                    trySelect(0);
                });
            }
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not load fingerprint</div>`;
        }
    }
    load();
}

function initDeviceActivity() {
    const el = $("#deviceActivityChart");
    if (!el) return;
    const deviceId = el.dataset.deviceId;

    async function load(range) {
        const res = await fetch(`/api/devices/${deviceId}/series?range=${range}`);
        const d = await res.json();
        const ctx = el.getContext("2d");
        upsertChart("deviceActivity", "deviceActivityChart", {
            type: "line",
            data: {
                labels: d.labels,
                datasets: [
                    { label: "Download", data: d.down_kbps, borderColor: PAL().accent,
                      backgroundColor: gradient(ctx, PAL().accent), fill: true, tension: .35,
                      pointRadius: 0, borderWidth: 2 },
                    { label: "Upload", data: d.up_kbps, borderColor: PAL().violet,
                      backgroundColor: gradient(ctx, PAL().violet), fill: true, tension: .35,
                      pointRadius: 0, borderWidth: 2 },
                ],
            },
            options: baseChartOpts({
                plugins: {
                    legend: { display: true, position: "top", align: "end",
                        labels: { color: CHART_TEXT, boxWidth: 8, boxHeight: 8,
                                  usePointStyle: true, font: { size: 11 } } },
                    tooltip: baseChartOpts().plugins.tooltip,
                },
            }),
        });
    }

    $$("#deviceRangeSel button").forEach(b => {
        b.classList.toggle("active", b.dataset.range === SP.range);
        b.addEventListener("click", () => {
            SP.range = b.dataset.range;
            localStorage.setItem("sp.range", SP.range);
            $$("#deviceRangeSel button").forEach(x => x.classList.toggle("active", x === b));
            load(SP.range);
        });
    });
    load(SP.range);
}

function humanizeSeconds(s) {
    if (s == null) return "";
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    return `${Math.round(s / 3600)}h`;
}

function initDeviceDpi() {
    const wrap = $("#deviceDpi");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const btn = $("#deviceDpiToggle");
    const expiryEl = $("#deviceDpiExpiry");

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/dpi`);
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            btn.textContent = data.enrolled ? "Enrolled · Unenroll" : "Enroll device";
            btn.classList.toggle("on", data.enrolled);
            btn.dataset.enrolled = data.enrolled ? "1" : "0";
            expiryEl.textContent = (data.enrolled && data.expires_in_s != null)
                ? `· auto-unenrolls in ${humanizeSeconds(data.expires_in_s)}` : "";
        } catch (err) {
            btn.textContent = "Unavailable";
        }
    }

    btn.addEventListener("click", async () => {
        const enrolled = btn.dataset.enrolled !== "1";
        try {
            const res = await fetch(`/api/devices/${deviceId}/dpi`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enrolled, hours: 24 }),
            });
            if (!res.ok) throw new Error("request failed");
            toast(enrolled ? "Device enrolled" : "Device unenrolled",
                  enrolled ? "HTTPS ad removal is active for this device for the next 24h. It needs the SecurePi CA installed - see the Filtering page."
                           : "This device's HTTPS traffic is no longer inspected.",
                  "ok");
            load();
        } catch (err) {
            toast("Update failed", "Could not reach the firewall.", "high");
        }
    });

    load();
}

function initDeviceBlocked() {
    const wrap = $("#deviceBlocked");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;

    async function askAndAllow(domain, temporary) {
        const reason = prompt(
            temporary
                ? `Why allow "${domain}" for this device for the next hour?`
                : `Why allow "${domain}" for this device from now on?`
        );
        if (reason === null || !reason.trim()) return;  // cancelled, or empty
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering/allow`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain, reason: reason.trim(), temporary, hours: 1 }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Allowed for this device", temporary ? `${domain} — for 1 hour` : domain, "ok");
            load();
        } catch (err) {
            toast("Could not allow domain", "The DNS filter did not accept the change.", "high");
        }
    }

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/blocked`);
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            if (!data.results.length) {
                wrap.innerHTML = `<div class="empty"><span class="empty-icon">✓</span>Nothing blocked for this device recently</div>`;
                return;
            }
            wrap.innerHTML = data.results.map(r => `
                <div class="list-row">
                    <span class="sev-dot high"></span>
                    <span class="mono grow" title="${esc(r.reason || '')}">${esc(r.domain)}</span>
                    <span class="dim">${r.count}× · ${esc(r.age)} ago</span>
                    <button class="btn" data-allow-1h="${esc(r.domain)}" title="Allow for this device for 1 hour">Allow 1h</button>
                    <button class="btn" data-allow="${esc(r.domain)}" title="Allow for this device from now on">Allow</button>
                </div>`).join("");
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not reach the DNS filter</div>`;
        }
    }

    wrap.addEventListener("click", (e) => {
        const oneHour = e.target.closest("[data-allow-1h]");
        if (oneHour) { askAndAllow(oneHour.dataset.allow1h, true); return; }
        const always = e.target.closest("[data-allow]");
        if (always) { askAndAllow(always.dataset.allow, false); }
    });

    const checkBtn = $("#deviceCheckBtn");
    const checkInput = $("#deviceCheckDomain");
    if (checkBtn) {
        async function runCheck() {
            const domain = checkInput.value.trim();
            if (!domain) return;
            try {
                const res = await fetch(`/api/filtering/check?domain=${encodeURIComponent(domain)}&device_id=${deviceId}`);
                if (!res.ok) throw new Error("request failed");
                const r = await res.json();
                const detail = r.cname ? `${r.reason} — via CNAME to ${r.cname}` : r.reason;
                if (r.blocked) {
                    toast("Blocked", detail, "high");
                } else {
                    toast("Allowed", detail, "ok");
                }
            } catch (err) {
                toast("Check failed", "Could not reach the DNS filter.", "high");
            }
        }
        checkBtn.addEventListener("click", runCheck);
        checkInput.addEventListener("keydown", (e) => { if (e.key === "Enter") runCheck(); });
    }

    load();
}

/* ---------------------------------------------------------------- filtering */

function initDevicePrivacy() {
    const wrap = $("#devicePrivacy");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;

    function tier2Html(t2) {
        if (!t2.active) {
            return `<div class="note" style="margin-top:12px">No HTTPS-inspected traffic for this device</div>`;
        }
        return `
            <div class="section-label" style="margin-top:16px">Tier 2 · HTTPS ad removal</div>
            <div class="metrics">
                <span class="metric"><span class="dim">Decrypted</span> <b>${t2.decrypt}</b></span>
                <span class="metric"><span class="dim">Passed through</span> <b>${t2.passthrough}</b></span>
                <span class="metric"><span class="dim">Ads stripped from</span> <b>${t2.ads_stripped}</b></span>
                <span class="metric"><span class="dim">Ad objects removed</span> <b>${t2.ads_removed}</b></span>
                <span class="metric"><span class="dim">Pinning bypasses</span> <b>${t2.pin_bypass}</b></span>
            </div>`;
    }

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/privacy`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            const t = d.trackers;
            const topRows = t.top.length ? t.top.map(c => `
                <tr><td class="truncate">${esc(c.company)}</td>
                    <td class="num dim">${c.contacted} contacted</td>
                    <td class="num ${c.blocked ? "text-high" : ""}">${c.blocked} blocked</td></tr>`).join("")
                : `<tr><td colspan="3" class="empty">No known tracker companies contacted</td></tr>`;
            wrap.innerHTML = `
                <div class="stats boxed" style="margin-bottom:14px">
                    <div class="stat"><div class="stat-label">Queries blocked</div>
                        <div class="stat-value">${d.dns_blocked.toLocaleString()} <span class="dim">/ ${d.dns_total.toLocaleString()} · ${d.block_pct}%</span></div></div>
                    <div class="stat"><div class="stat-label">Tracking companies</div>
                        <div class="stat-value">${t.companies_blocked} <span class="dim">blocked of ${t.companies_contacted}</span></div></div>
                    <div class="stat"><div class="stat-label">Estimated data saved</div>
                        <div class="stat-value">${d.savings.estimated_bytes_h}</div></div>
                </div>
                <table class="compact" style="margin:0 -16px; width:calc(100% + 32px)"><tbody>${topRows}</tbody></table>
                ${tier2Html(d.tier2)}`;
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not load privacy report</div>`;
        }
    }
    load();
}

function initDeviceProfiles() {
    const wrap = $("#deviceProfiles");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const select = $("#deviceProfileSelect");
    const appliedEl = $("#deviceProfilesApplied");

    function renderApplied(applied) {
        if (!applied.length) {
            appliedEl.innerHTML = `<div class="note">No native-tracker profile applied</div>`;
            return;
        }
        appliedEl.innerHTML = applied.map(a => `
            <div class="list-row" style="padding:6px 0">
                <span class="chip ok dot nocap">${esc(a.label)}</span>
                <span class="dim grow">${a.rule_count} domain${a.rule_count === 1 ? "" : "s"} blocked</span>
                <button class="btn danger" data-remove-profile="${esc(a.vendor)}">Remove</button>
            </div>`).join("");
    }

    async function loadApplied() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering/profiles`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            renderApplied(d.applied);
        } catch (err) {
            appliedEl.innerHTML = `<div class="empty">Could not load applied profiles</div>`;
        }
    }

    async function loadOptions() {
        try {
            const res = await fetch("/api/native-profiles");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            select.innerHTML = d.profiles.map(p =>
                `<option value="${esc(p.vendor)}">${esc(p.label)} (${p.domain_count})</option>`).join("");
        } catch (err) {
            select.innerHTML = `<option value="">Unavailable</option>`;
        }
    }

    $("#deviceProfileApply").addEventListener("click", async () => {
        const vendor = select.value;
        if (!vendor) return;
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering/profile`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ vendor }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Profile applied", select.options[select.selectedIndex].text, "ok");
            loadApplied();
        } catch (err) {
            toast("Could not apply profile", "The DNS filter did not accept the change.", "high");
        }
    });

    appliedEl.addEventListener("click", async (e) => {
        const btn = e.target.closest("[data-remove-profile]");
        if (!btn) return;
        const vendor = btn.dataset.removeProfile;
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering/profile/remove`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ vendor }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Profile removed", "", "ok");
            loadApplied();
        } catch (err) {
            toast("Could not remove profile", "The DNS filter did not accept the change.", "high");
        }
    });

    loadOptions();
    loadApplied();
}

const DPI_TRUST_META = {
    trusted:    { label: "CA trusted",       cls: "ok" },
    check_ca:   { label: "check CA install", cls: "high" },
    unverified: { label: "not verified yet", cls: "neutral" },
};

function initDpiOnboarding() {
    const caEl = $("#dpiCaInfo");
    if (!caEl) return;
    const listEl = $("#dpiEnrolledList");

    async function loadCa() {
        try {
            const res = await fetch("/api/filtering/ca");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            if (!d.available) {
                caEl.innerHTML = `<div class="empty">Tier 2 is not installed on this gateway (${esc(d.error || "no CA found")})</div>`;
                return;
            }
            caEl.innerHTML = `
                <div class="stats" style="margin-bottom:14px; align-items:center">
                    <div class="stat"><div class="stat-label">Valid until</div>
                        <div class="stat-value sm">${esc(d.not_after || "unknown")}</div></div>
                    <div class="stat" style="min-width:0"><div class="stat-label">Fingerprint (SHA-256)</div>
                        <div class="stat-value sm mono truncate" style="max-width:320px" title="${esc(d.fingerprint_sha256 || "")}">${esc(d.fingerprint_sha256 || "unknown")}</div></div>
                    <div style="margin-left:auto"><a class="btn primary" href="${esc(d.download_url)}" target="_blank" rel="noopener">
                        <svg class="icon" width="14" height="14"><use href="#i-download"/></svg> Download CA certificate</a></div>
                </div>
                <div class="prose">
                    Install this certificate as a trusted root on a device before enrolling it, or its HTTPS
                    traffic will fail to load once enrolled: iOS/macOS - open the link, Install in Settings ›
                    General › VPN & Device Management, then enable full trust under Certificate Trust Settings.
                    Android - open the link, install as a "CA certificate" under Settings › Security ›
                    Encryption. Windows - open the .crt file, install into "Trusted Root Certification
                    Authorities" for the local machine.
                </div>
                <div class="callout warn" style="margin-top:12px">
                    Remove this certificate from any device that is no longer enrolled below - the gateway
                    can't see or remind you of this itself, since it has no visibility into a device's own
                    certificate store.
                </div>`;
        } catch (err) {
            caEl.innerHTML = `<div class="empty">Could not load CA info</div>`;
        }
    }

    async function loadEnrolled() {
        try {
            const res = await fetch("/api/filtering/dpi/enrolled");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            if (!d.enrolled.length) {
                listEl.innerHTML = `<div class="empty">No devices enrolled</div>`;
                return;
            }
            listEl.innerHTML = d.enrolled.map(e => {
                const t = DPI_TRUST_META[e.trust] || DPI_TRUST_META.unverified;
                return `
                <div class="filter-row">
                    <span class="chip dot ${t.cls}">${t.label}</span>
                    <span class="grow">${e.device_id ? `<a href="/devices/${e.device_id}">${esc(e.name)}</a>` : esc(e.name)}</span>
                    <span class="dim mono">${esc(e.ip)}</span>
                    <span class="dim">${e.expires_in_s != null ? `expires in ${humanizeSeconds(e.expires_in_s)}` : ""}</span>
                </div>`;
            }).join("");
        } catch (err) {
            listEl.innerHTML = `<div class="empty">Could not load enrolled devices</div>`;
        }
    }

    async function loadPinned() {
        const wrap = $("#dpiPinnedList");
        if (!wrap) return;
        try {
            const res = await fetch("/api/filtering/dpi/pinned");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            if (!d.pinned.length) {
                wrap.innerHTML = `<div class="empty">No apps currently bypassed</div>`;
                return;
            }
            wrap.innerHTML = d.pinned.map(p => `
                <div class="filter-row">
                    <span class="chip neutral">bypassed</span>
                    <span class="truncate">${p.device_id ? `<a href="/devices/${p.device_id}">${esc(p.name)}</a>` : esc(p.name)}</span>
                    <span class="dim mono grow">${esc(p.sni)}</span>
                    <span class="dim">expires in ${humanizeSeconds(p.expires_in_s)}</span>
                </div>`).join("");
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not load pinned apps</div>`;
        }
    }

    async function loadPrivacyScope() {
        const badge = $("#privacyScopeBadge");
        if (!badge) return;
        try {
            const res = await fetch("/api/filtering/dpi/privacy-scope");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            if (d.failing) {
                badge.textContent = "Privacy scope: check failed - Tier 2 disabled";
                badge.className = "chip dot high";
                if (d.incident_id) badge.onclick = () => location.href = `/incidents/${d.incident_id}`;
            } else if (d.stale) {
                badge.textContent = d.last_checked ? `Privacy scope: stale (last checked ${d.age} ago)` : "Privacy scope: not yet checked";
                badge.className = "chip dot neutral";
            } else {
                badge.textContent = `Privacy scope verified ${d.age} ago`;
                badge.className = "chip dot ok";
            }
        } catch (err) {
            $("#privacyScopeBadge").textContent = "Privacy scope: unknown";
        }
    }

    async function loadEffectiveness() {
        const badge = $("#dpiEffectivenessBadge");
        if (!badge) return;
        try {
            const res = await fetch("/api/filtering/dpi/effectiveness");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            if (d.healthy) {
                badge.textContent = "Effectiveness: OK";
                badge.className = "chip dot ok";
            } else {
                const first = d.affected[0];
                badge.textContent = `Effectiveness: check ${esc(first.name)}` +
                    (d.affected.length > 1 ? ` (+${d.affected.length - 1} more)` : "");
                badge.className = "chip dot high";
                badge.onclick = () => location.href = `/incidents/${first.incident_id}`;
            }
        } catch (err) {
            badge.textContent = "Effectiveness: unknown";
        }
    }

    loadCa();
    loadEnrolled();
    loadPinned();
    loadPrivacyScope();
    loadEffectiveness();
}

function linesToList(text) {
    return text.split("\n").map(s => s.trim()).filter(Boolean);
}

function initWeeklyReport() {
    const picker = $("#reportWeekPicker");
    if (!picker) return;

    function shiftWeek(days) {
        const d = new Date(picker.value + "T00:00:00");
        d.setDate(d.getDate() + days);
        picker.value = d.toISOString().slice(0, 10);
        load();
    }

    async function load() {
        const params = picker.value ? `?week=${picker.value}` : "";
        try {
            const res = await fetch(`/api/reports/weekly${params}`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            picker.value = d.week_start;
            $("#reportWeekRange").textContent = `${d.week_start} to ${d.week_end}`;
            $("#reportIncidentTotal").textContent = `${d.incident_count} incidents this week`;

            renderBarList("#reportTactics", d.incidents_by_tactic.map(t => ({
                label: t.tactic, value: t.count, weight: t.count, tone: "violet",
            })), "No incidents this week.");

            $("#reportRiskiest").innerHTML = d.riskiest_devices.length ? d.riskiest_devices.map(r => `
                <div class="list-row">
                    <span class="chip ${r.band} dot">${esc(r.band)}</span>
                    <span class="grow row-title">${esc(r.name)}</span>
                    <span class="dim">score <b>${r.score}</b></span>
                </div>`).join("") : `<div class="empty">No devices carried risk this week.</div>`;

            const a = d.adblock;
            $("#reportAdblockSummary").innerHTML = `
                <dt>DNS queries</dt><dd>${a.dns_total.toLocaleString()}</dd>
                <dt>Blocked</dt><dd>${a.dns_blocked.toLocaleString()} (${a.block_pct}%)</dd>
                <dt>Tracker companies contacted</dt><dd>${a.trackers.companies_contacted} (${a.trackers.companies_blocked} at least partly blocked)</dd>
                <dt>Estimated savings</dt><dd>${esc(a.savings.estimated_bytes_h)} <span class="dim">(${esc(a.savings.method)})</span></dd>`;

            $("#reportTrackers").innerHTML = a.trackers.top.length ? `
                <div class="list-row head"><span class="grow">Top tracker companies</span><span class="dim">contacted · blocked</span></div>
                ${a.trackers.top.map(t => `
                <div class="list-row"><span class="grow">${esc(t.company)}</span><span class="dim">${t.contacted}× contacted · <span class="${t.blocked ? "text-high" : ""}">${t.blocked}× blocked</span></span></div>
                `).join("")}` : "";

            $("#reportTier2").innerHTML = a.tier2.active ? `
                <div class="list-row head"><span class="grow">Tier 2 (HTTPS ad removal)</span></div>
                <div class="list-row"><span class="grow">Ads removed</span><b>${a.tier2.ads_removed}</b></div>
                <div class="list-row"><span class="grow">Decrypted / passthrough / path-blocked</span><b>${a.tier2.decrypt} / ${a.tier2.passthrough} / ${a.tier2.path_blocked}</b></div>
            ` : `<div class="list-row"><span class="dim">No Tier 2 activity this week.</span></div>`;

            $("#reportPlatform").innerHTML = `
                <dt>Events ingested</dt><dd>${d.platform.events_ingested.toLocaleString()}</dd>
                <dt>Platform-effectiveness incidents</dt><dd>${d.platform.platform_incidents}</dd>`;
        } catch (err) {
            $("#reportTactics").innerHTML = `<div class="empty">Could not load the report.</div>`;
        }
    }

    picker.addEventListener("change", load);
    $("#reportPrevWeek").addEventListener("click", () => shiftWeek(-7));
    $("#reportNextWeek").addEventListener("click", () => shiftWeek(7));
    $("#reportPrint").addEventListener("click", () => window.print());

    load();
}

function initHunt() {
    const wrap = $("#huntResults");
    if (!wrap) return;

    function currentFilters() {
        return {
            device_id: $("#huntDevice").value || "",
            ip: $("#huntIp").value.trim(),
            domain: $("#huntDomain").value.trim(),
            port: $("#huntPort").value.trim(),
            event_type: $("#huntEventType").value || "",
            range: $("#huntRange").value || "1h",
        };
    }

    function applyFilters(f) {
        $("#huntDevice").value = f.device_id || "";
        $("#huntIp").value = f.ip || "";
        $("#huntDomain").value = f.domain || "";
        $("#huntPort").value = f.port || "";
        $("#huntEventType").value = f.event_type || "";
        $("#huntRange").value = f.range || "1h";
    }

    async function search() {
        const f = currentFilters();
        const params = new URLSearchParams();
        if (f.device_id) params.set("device_id", f.device_id);
        if (f.ip) params.set("ip", f.ip);
        if (f.domain) params.set("domain", f.domain);
        if (f.port) params.set("port", f.port);
        if (f.event_type) params.set("event_type", f.event_type);
        params.set("range", f.range);

        try {
            const res = await fetch(`/api/hunt?${params}`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();

            $("#huntResultsSummary").textContent =
                `${d.events.length} shown - ${d.range_label}`;

            wrap.innerHTML = d.events.length ? d.events.map(e => `
                <div class="feed-row with-device">
                    <span class="mono dim">${esc(e.time)}</span>
                    <span class="type-tag ${esc(e.type)}">${esc(e.type.replace('dns_query', 'dns'))}</span>
                    <span class="device" title="${esc(e.device || "")}">${esc(e.device || "—")}</span>
                    <span class="truncate mono" data-pivot-domain="${esc(e.detail)}" title="click to pivot">${esc(e.detail)}</span>
                    <span class="dim">${e.blocked ? `<span class="chip high">blocked</span>` : esc(e.extra || "")}</span>
                </div>`).join("") : `<div class="empty">No events matched this search.</div>`;

            $("#huntTalkers").innerHTML = d.top_talkers.length ? d.top_talkers.map(t => `
                <div class="list-row"><span class="grow">${esc(t.device)}</span><span class="dim">${esc(t.bytes_label)}</span></div>
            `).join("") : `<div class="empty">No device-attributed traffic in this search.</div>`;

            $("#huntDestinations").innerHTML = d.top_destinations.length ? d.top_destinations.map(x => `
                <div class="list-row"><span class="grow mono" data-pivot-domain="${esc(x.name)}" title="click to pivot">${esc(x.name)}</span><span class="dim">${x.count}×</span></div>
            `).join("") : `<div class="empty">No destinations in this search.</div>`;

            $("#huntProtocols").innerHTML = d.protocol_breakdown.length ? d.protocol_breakdown.map(p => `
                <div class="list-row"><span class="type-tag ${esc(p.type)}">${esc(p.type.replace('dns_query', 'dns').replace(/_/g, ' '))}</span><span class="grow"></span><span class="dim">${p.count}×</span></div>
            `).join("") : `<div class="empty">No events in this search.</div>`;
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Search failed.</div>`;
        }
    }

    async function loadSaved() {
        const box = $("#huntSaved");
        if (!box) return;
        try {
            const res = await fetch("/api/hunt/saved");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            box.innerHTML = d.searches.length ? d.searches.map(s => `
                <div class="list-row" data-search-id="${s.id}">
                    <svg class="icon dim" width="14" height="14"><use href="#i-search"/></svg>
                    <span class="grow row-title" title="${esc(s.name)}">${esc(s.name)}</span>
                    <span class="dim">${esc(s.created_at)}</span>
                    <button class="btn" data-load-search>Load</button>
                    <button class="btn danger" data-delete-search>Delete</button>
                </div>`).join("") : `<div class="empty">No saved searches yet.</div>`;
            box.dataset.searches = JSON.stringify(d.searches);
        } catch (err) {
            box.innerHTML = `<div class="empty">Could not load saved searches.</div>`;
        }
    }

    $("#huntSearch").addEventListener("click", search);
    ["huntIp", "huntDomain", "huntPort"].forEach(id => {
        $(`#${id}`).addEventListener("keydown", (e) => { if (e.key === "Enter") search(); });
    });

    $("#huntSaveSearch").addEventListener("click", async () => {
        const name = prompt("Name this search:");
        if (!name || !name.trim()) return;
        const f = currentFilters();
        try {
            const res = await fetch("/api/hunt/saved", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name: name.trim(),
                    device_id: f.device_id ? parseInt(f.device_id, 10) : null,
                    ip: f.ip || null, domain: f.domain || null,
                    port: f.port ? parseInt(f.port, 10) : null,
                    event_type: f.event_type || null, range: f.range,
                }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Search saved", name, "ok");
            loadSaved();
        } catch (err) {
            toast("Could not save search", "", "high");
        }
    });

    // Pivoting: clicking a domain/IP anywhere in the results or aggregate
    // cards re-runs the search filtered to that value - "everything device
    // X talked to" is two clicks (open the device, then Hunt) or, from
    // here, one click on any destination already shown.
    document.addEventListener("click", (e) => {
        const pivot = e.target.closest("[data-pivot-domain]");
        if (pivot) {
            const val = pivot.dataset.pivotDomain;
            if (!val || val === "-") return;
            $("#huntDomain").value = val;
            $("#huntIp").value = "";
            search();
            return;
        }
        const loadBtn = e.target.closest("[data-load-search]");
        if (loadBtn) {
            const row = loadBtn.closest("[data-search-id]");
            const box = $("#huntSaved");
            const searches = JSON.parse(box.dataset.searches || "[]");
            const found = searches.find(s => String(s.id) === row.dataset.searchId);
            if (found) { applyFilters(found.filters); search(); }
            return;
        }
        const delBtn = e.target.closest("[data-delete-search]");
        if (delBtn) {
            const row = delBtn.closest("[data-search-id]");
            fetch(`/api/hunt/saved/${row.dataset.searchId}/remove`, { method: "POST" })
                .then(res => { if (!res.ok) throw new Error(); toast("Saved search deleted", "", "ok"); loadSaved(); })
                .catch(() => toast("Could not delete", "", "high"));
        }
    });

    search();
    loadSaved();
}

function initSettings() {
    const wrap = $("#settingsThresholds");
    if (!wrap) return;

    async function loadThresholds() {
        try {
            const res = await fetch("/api/settings");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            wrap.innerHTML = Object.entries(d.settings).filter(([, s]) => s.group === "detection").map(([key, s]) => `
                <div class="filter-row setting-row" data-key="${esc(key)}">
                    <div class="setting-label">
                        <div class="row-title">${esc(s.label)}</div>
                        <div class="row-sub" title="${esc(s.help)}">${esc(s.help || key)}</div>
                    </div>
                    ${s.type === "bool"
                        ? `<button class="btn ${s.value ? "on" : ""}" data-setting-bool="${s.value ? 0 : 1}" aria-label="${esc(s.label)}">${s.value ? "On" : "Off"}</button>`
                        : `<input class="input" type="number" step="any" value="${s.value}"
                           min="${s.min ?? ''}" max="${s.max ?? ''}" data-setting-input aria-label="${esc(s.label)}">`}
                    <span class="setting-status">${s.overridden ? `<span class="chip low" title="default: ${s.type === "bool" ? (s.default ? "on" : "off") : s.default}">custom</span>` : `<span class="dim">default</span>`}</span>
                    <span class="setting-actions">
                        ${s.overridden ? `<button class="btn ghost" data-setting-reset>Reset</button>` : ""}
                        ${s.type === "bool" ? "" : `<button class="btn" data-setting-save>Save</button>`}
                    </span>
                </div>`).join("");
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not load settings</div>`;
        }
    }

    wrap.addEventListener("click", async (e) => {
        const row = e.target.closest(".filter-row");
        if (!row) return;
        const key = row.dataset.key;
        // On/off settings (e.g. the retired malicious-domain signal) toggle
        // with one button; numeric ones are typed in and saved.
        const boolButton = e.target.closest("[data-setting-bool]");
        if (boolButton || e.target.matches("[data-setting-save]")) {
            let value;
            if (boolButton) {
                value = boolButton.dataset.settingBool === "1";
            } else {
                const raw = row.querySelector("[data-setting-input]").value.trim();
                value = raw.includes(".") ? parseFloat(raw) : parseInt(raw, 10);
                if (Number.isNaN(value)) { toast("Invalid value", "Enter a number.", "high"); return; }
            }
            const reason = prompt(`Reason for changing ${key}?`);
            if (!reason || !reason.trim()) { toast("Reason required", "", "high"); return; }
            try {
                const res = await fetch(`/api/settings/${key}`, {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ value, reason }),
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.detail || "request failed");
                }
                toast("Setting updated", key, "ok");
                loadThresholds();
                loadAudit();
            } catch (err) {
                toast("Could not update setting", String(err.message || err), "high");
            }
        } else if (e.target.matches("[data-setting-reset]")) {
            try {
                const res = await fetch(`/api/settings/${key}/reset`, { method: "POST" });
                if (!res.ok) throw new Error("request failed");
                toast("Reverted to default", key, "ok");
                loadThresholds();
                loadAudit();
            } catch (err) {
                toast("Could not reset setting", "", "high");
            }
        }
    });

    async function loadAudit() {
        const el = $("#settingsAudit");
        if (!el) return;
        try {
            const res = await fetch("/api/audit?limit=100");
            const d = await res.json();
            if (!d.entries.length) { el.innerHTML = `<div class="empty">No audited actions yet</div>`; return; }
            el.innerHTML = d.entries.map(e => `
                <div class="audit-row">
                    <span class="mono dim">${esc(e.ts)}</span>
                    <span class="type-tag" title="${esc(e.action)}">${esc(e.action)}</span>
                    <span class="truncate mono" style="max-width:100%" title="${esc(e.target || '')}">${esc(e.target || '')}</span>
                    <span class="detail" title="${esc(e.detail || '')}">${esc(e.detail || '')}</span>
                </div>`).join("");
        } catch (err) {
            el.innerHTML = `<div class="empty">Could not load audit log</div>`;
        }
    }

    async function loadAttributions() {
        const el = $("#settingsAttributions");
        if (!el) return;
        try {
            const res = await fetch("/api/attributions");
            const d = await res.json();
            el.innerHTML = `<table><thead><tr><th>Component</th><th>Version</th><th>License</th><th>Role in this project</th></tr></thead><tbody>${d.attributions.map(a => `
                <tr>
                    <td style="white-space:nowrap"><a class="link" href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.name)}</a></td>
                    <td class="dim mono" style="white-space:nowrap">${esc(a.version)}</td>
                    <td><span class="chip neutral nocap">${esc(a.license)}</span></td>
                    <td class="dim">${esc(a.role)}</td>
                </tr>`).join("")}</tbody></table>`;
        } catch (err) {
            el.innerHTML = `<div class="empty">Could not load attributions</div>`;
        }
    }

    const pwBtn = $("#settingsPwSave");
    if (pwBtn) {
        pwBtn.addEventListener("click", async () => {
            const current_password = $("#settingsPwCurrent").value;
            const new_password = $("#settingsPwNew").value;
            if (!current_password || !new_password) {
                toast("Both fields required", "", "high"); return;
            }
            try {
                const res = await fetch("/api/settings/password", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ current_password, new_password }),
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.detail || "request failed");
                }
                $("#settingsPwCurrent").value = "";
                $("#settingsPwNew").value = "";
                toast("Password changed", "Use the new password next time you sign in. Any other signed-in sessions were signed out.", "ok");
                loadAudit();
            } catch (err) {
                toast("Could not change password", String(err.message || err), "high");
            }
        });
    }

    loadThresholds();
    loadAudit();
    loadAttributions();
}

function initDpiRules() {
    const form = $("#dpiRulesForm");
    if (!form) return;
    let baselineDecryptSuffixes = [];
    let cosmeticEnabled = false;
    const cosmeticBtn = $("#dpiCosmeticToggle");

    function summariseHits(items, elId) {
        const el = $(elId);
        if (!el) return;
        const dead = items.filter(i => i.hits === 0).length;
        el.textContent = dead ? `(${items.length} rules, ${dead} with zero hits)` : `(${items.length} rules)`;
    }

    function renderCosmeticToggle() {
        if (!cosmeticBtn) return;
        cosmeticBtn.textContent = cosmeticEnabled ? "On" : "Off";
        cosmeticBtn.classList.toggle("on", cosmeticEnabled);
    }

    async function load() {
        try {
            const res = await fetch("/api/filtering/dpi/rules");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            baselineDecryptSuffixes = d.decrypt_suffixes.slice();
            $("#dpiRuleDecryptSuffixes").value = d.decrypt_suffixes.join("\n");
            $("#dpiRuleAdFields").value = d.ad_fields.map(x => x.rule).join("\n");
            $("#dpiRuleAdRenderers").value = d.ad_renderers.map(x => x.rule).join("\n");
            $("#dpiRuleBlockedPaths").value = d.blocked_paths.map(x => x.rule).join("\n");
            $("#dpiRuleCosmeticSelectors").value = (d.cosmetic_selectors || []).join("\n");
            cosmeticEnabled = !!d.cosmetic_injection_enabled;
            renderCosmeticToggle();
            summariseHits(d.ad_fields, "#dpiRuleAdFieldsHits");
            summariseHits(d.ad_renderers, "#dpiRuleAdRenderersHits");
            summariseHits(d.blocked_paths, "#dpiRuleBlockedPathsHits");
            $("#dpiRulesVersion").textContent = `version ${d.version}` +
                (d.stats_age ? `, hit counts as of ${d.stats_age} ago` : ", no hit data yet");
        } catch (err) {
            $("#dpiRulesVersion").textContent = "could not load";
        }
    }

    if (cosmeticBtn) {
        cosmeticBtn.addEventListener("click", () => {
            cosmeticEnabled = !cosmeticEnabled;
            renderCosmeticToggle();
        });
    }

    $("#dpiRulesSave").addEventListener("click", async () => {
        const decrypt_suffixes = linesToList($("#dpiRuleDecryptSuffixes").value);
        const ad_fields = linesToList($("#dpiRuleAdFields").value);
        const ad_renderers = linesToList($("#dpiRuleAdRenderers").value);
        const blocked_paths = linesToList($("#dpiRuleBlockedPaths").value);
        const cosmetic_selectors = linesToList($("#dpiRuleCosmeticSelectors").value);
        const reason = $("#dpiRuleReason").value.trim();
        if (!reason) { toast("Reason required", "Say why you're changing the rules.", "high"); return; }

        const scopeChanged = decrypt_suffixes.length !== baselineDecryptSuffixes.length ||
            decrypt_suffixes.some(s => !baselineDecryptSuffixes.includes(s));
        let confirm_privacy_scope_change = false;
        if (scopeChanged) {
            if (!confirm("Changing the decrypt suffixes changes what this gateway is able to decrypt. Continue?")) return;
            confirm_privacy_scope_change = true;
        }

        try {
            const res = await fetch("/api/filtering/dpi/rules", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ decrypt_suffixes, ad_fields, ad_renderers, blocked_paths,
                                        reason, confirm_privacy_scope_change,
                                        cosmetic_injection_enabled: cosmeticEnabled, cosmetic_selectors }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || "request failed");
            }
            $("#dpiRuleReason").value = "";
            toast("Rules updated", "", "ok");
            load();
        } catch (err) {
            toast("Could not save rules", String(err.message || err), "high");
        }
    });

    load();
}

function initResolverQuality() {
    const wrap = $("#resolverQuality");
    if (!wrap) return;

    async function load() {
        try {
            const res = await fetch("/api/filtering/resolver?range=24h");
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            const cur = d.current, lat = d.latency;
            const needsTuning = !cur.cache_optimistic || !cur.dnssec_enabled || cur.upstream_dns.length < 2;
            wrap.innerHTML = `
                <div class="stats boxed" style="margin-bottom:12px">
                    <div class="stat"><div class="stat-label">Latency p50 / p95</div>
                        <div class="stat-value">${lat.p50_ms ?? "—"} <span class="dim">ms</span> / ${lat.p95_ms ?? "—"} <span class="dim">ms</span></div>
                        <div class="stat-sub">uncached · ${lat.sample_size} samples, ${esc(d.range_label)}</div></div>
                    <div class="stat"><div class="stat-label">Upstream resolvers</div>
                        <div class="stat-value sm mono" style="font-size:12px; overflow-wrap:anywhere">${cur.upstream_dns.map(esc).join(", ") || "none configured"}</div>
                        <div class="stat-sub">mode: ${esc(cur.upstream_mode)}</div></div>
                    <div class="stat"><div class="stat-label">Cache</div>
                        <div class="stat-value sm"><span class="chip dot ${cur.cache_enabled ? "ok" : "neutral"}">${cur.cache_enabled ? "on" : "off"}</span>${cur.cache_optimistic ? ` <span class="dim">optimistic</span>` : ""}</div></div>
                    <div class="stat"><div class="stat-label">DNSSEC</div>
                        <div class="stat-value sm"><span class="chip dot ${cur.dnssec_enabled ? "ok" : "neutral"}">${cur.dnssec_enabled ? "on" : "off"}</span></div></div>
                </div>
                ${needsTuning ? `
                    <div class="callout row warn">
                        <div>Recommended: optimistic caching, DNSSEC, and at least two independent
                            upstream resolvers queried in parallel. This changes DNS resolution for every device
                            on the network at once.</div>
                        <button class="btn primary" id="applyResolverTuning">Apply recommended tuning</button>
                    </div>` : `<div class="note" style="display:flex; align-items:center; gap:6px"><span class="sev-dot" style="background:var(--ok)"></span>Resolver is already tuned.</div>`}`;
            const applyBtn = $("#applyResolverTuning");
            if (applyBtn) applyBtn.addEventListener("click", async () => {
                if (!confirm("This changes DNS resolution for every device on the network right now. Continue?")) return;
                try {
                    const res = await fetch("/api/filtering/resolver/apply", {
                        method: "POST", headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ confirm: true }),
                    });
                    if (!res.ok) throw new Error("request failed");
                    toast("Resolver tuning applied", "", "ok");
                    load();
                } catch (err) {
                    toast("Could not apply tuning", "The DNS filter did not accept the change.", "high");
                }
            });
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not reach the DNS filter</div>`;
        }
    }
    load();
}

function initFilteringAnalytics() {
    const el = $("#blockPctChart");
    if (!el) return;
    let range = "24h";

    function renderTopDomains(domains) {
        const wrap = $("#analyticsTopDomains");
        if (!domains.length) { wrap.innerHTML = `<div class="empty">Nothing blocked in this range</div>`; return; }
        wrap.innerHTML = `<table><tbody>${domains.map(d => `
            <tr><td class="mono truncate">${esc(d.domain)}</td>
                <td class="num text-high">${d.count}</td></tr>`).join("")}</tbody></table>`;
    }

    function renderTopClients(clients) {
        const wrap = $("#analyticsTopClients");
        if (!clients.length) { wrap.innerHTML = `<div class="empty">No blocked activity in this range</div>`; return; }
        wrap.innerHTML = `<table><tbody>${clients.map(c => `
            <tr class="clickable" onclick="location.href='/devices/${c.id}'">
                <td class="truncate">${esc(c.name)}</td>
                <td class="num dim">${c.blocked} / ${c.dns_total}</td>
                <td class="num text-high">${c.block_pct}%</td>
            </tr>`).join("")}</tbody></table>`;
    }

    function renderTrackers(t) {
        $("#analyticsTrackerCount").textContent = `${t.companies_blocked} blocked of ${t.companies_contacted} contacted`;
        const wrap = $("#analyticsTrackers");
        if (!t.top.length) { wrap.innerHTML = `<div class="empty">No known tracker companies contacted in this range</div>`; return; }
        wrap.innerHTML = `<table><tbody>${t.top.map(c => `
            <tr><td class="truncate">${esc(c.company)}</td>
                <td class="num dim">${c.contacted} contacted</td>
                <td class="num ${c.blocked ? "text-high" : ""}">${c.blocked} blocked</td></tr>`).join("")}</tbody></table>`;
    }

    function renderTier2(t2) {
        const wrap = $("#analyticsTier2");
        if (!t2.active) {
            wrap.innerHTML = `<div class="empty">No HTTPS-inspected traffic in this range - no device is enrolled, or none has browsed since.</div>`;
            return;
        }
        wrap.innerHTML = `
            <div class="metrics">
                <span class="metric"><span class="dim">Decrypted</span> <b>${t2.decrypt}</b></span>
                <span class="metric"><span class="dim">Passed through</span> <b>${t2.passthrough}</b></span>
                <span class="metric"><span class="dim">Ads stripped from</span> <b>${t2.ads_stripped}</b> <span class="dim">responses</span></span>
                <span class="metric"><span class="dim">Blocked paths</span> <b>${t2.path_blocked}</b></span>
                <span class="metric"><span class="dim">Ad objects removed</span> <b>${t2.ads_removed}</b></span>
                <span class="metric"><span class="dim">TLS handshake failures</span> <b>${t2.tls_failed}</b></span>
                <span class="metric"><span class="dim">Pinning bypasses</span> <b>${t2.pin_bypass}</b></span>
            </div>`;
    }

    async function load() {
        try {
            const res = await fetch(`/api/filtering/analytics?range=${range}`);
            if (!res.ok) throw new Error("request failed");
            const d = await res.json();
            upsertChart("blockPct", "blockPctChart", {
                type: "line",
                data: {
                    labels: d.series.labels,
                    datasets: [
                        { label: "Block %", data: d.series.block_pct, borderColor: PAL().high,
                          backgroundColor: gradient(el.getContext("2d"), PAL().high), fill: true, tension: .35,
                          pointRadius: 0, borderWidth: 2 },
                    ],
                },
                options: baseChartOpts({
                    scales: Object.assign(baseChartOpts().scales, {
                        y: Object.assign(baseChartOpts().scales.y, {
                            ticks: { color: CHART_TEXT, maxTicksLimit: 5, font: { size: 10 },
                                     padding: 6, callback: v => v + "%" },
                        }),
                    }),
                }),
            });
            $("#analyticsRequestsBlocked").textContent = d.savings.requests_blocked.toLocaleString();
            $("#analyticsSavings").textContent = d.savings.estimated_bytes_h;
            $("#analyticsSavingsMethod").textContent = d.savings.method;
            renderTopDomains(d.top_blocked_domains);
            renderTopClients(d.top_blocked_clients);
            renderTrackers(d.trackers);
            renderTier2(d.tier2);
        } catch (err) {
            $("#analyticsTopDomains").innerHTML = `<div class="empty">Could not load analytics</div>`;
            $("#analyticsTopClients").innerHTML = "";
            $("#analyticsTrackers").innerHTML = "";
            $("#analyticsTier2").innerHTML = "";
        }
    }

    $$("#analyticsRangeSel button").forEach(b => {
        b.addEventListener("click", () => {
            range = b.dataset.arange;
            $$("#analyticsRangeSel button").forEach(x => x.classList.toggle("active", x === b));
            load();
        });
    });

    load();
}

function initFiltering() {
    const listsEl = $("#filterLists");
    if (!listsEl) return;
    const rulesEl = $("#filterRules");
    const masterBtn = $("#filteringMasterToggle");

    function renderLists(filters, healthByUrl) {
        healthByUrl = healthByUrl || {};
        $("#filterListCount").textContent = filters.length + " list" + (filters.length === 1 ? "" : "s");
        if (!filters.length) { listsEl.innerHTML = `<div class="empty">No blocklists configured</div>`; return; }
        const anyStale = filters.some(f => (healthByUrl[f.url] || {}).stale);
        const callout = anyStale ? `<div class="callout warn" style="margin:8px 16px">
            One or more blocklists haven't synced in over ${LIST_STALE_AFTER_H}h - check their source URL.</div>` : "";
        listsEl.innerHTML = callout + filters.map(f => {
            const h = healthByUrl[f.url];
            const badges = h ? `
                <span class="dim" title="share of all blocks we've matched back to a list">${h.share_pct}% of blocks</span>
                <span class="${h.stale ? "chip high nocap" : "dim"}" title="${h.age_h != null ? h.age_h + "h since last sync" : "sync age unknown"}">${h.age_h != null ? Math.round(h.age_h) + "h old" : "sync age unknown"}</span>
                ${h.low_contribution ? `<span class="chip neutral" title="Blocked very little of what we've actually seen">low contribution</span>` : ""}` : "";
            return `
            <div class="filter-row">
                <button class="btn ${f.enabled ? "on" : ""}" data-list-toggle="${esc(f.url)}" data-enabled="${f.enabled ? 1 : 0}">${f.enabled ? "On" : "Off"}</button>
                <span class="name">${esc(f.name)}</span>
                <span class="url truncate" title="${esc(f.url)}">${esc(f.url)}</span>
                <span class="dim">${f.rules_count.toLocaleString()} rules</span>
                ${badges}
                <button class="btn danger" data-list-remove="${esc(f.url)}">Remove</button>
            </div>`;
        }).join("");
    }

    function renderRules(rules) {
        if (!rules.length) { rulesEl.innerHTML = `<div class="empty">No custom rules yet</div>`; return; }
        rulesEl.innerHTML = rules.map(r => `
            <div class="filter-row">
                <span class="chip dot ${r.action === "block" ? "high" : "ok"}">${r.action}</span>
                <span class="url mono grow" style="color:var(--text)" title="${esc(r.rule)}">${esc(r.domain || r.rule)}</span>
                <button class="btn danger" data-rule-remove="${esc(r.rule)}">Remove</button>
            </div>`).join("");
    }

    async function loadStatus() {
        try {
            const res = await fetch("/api/filtering/status");
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            renderRules(data.rules);
            masterBtn.textContent = data.enabled ? "Filtering is on" : "Filtering is off";
            masterBtn.classList.toggle("on", data.enabled);
            masterBtn.dataset.enabled = data.enabled ? "1" : "0";

            // Health (staleness + contribution) is a second, independent
            // fetch: it's allowed to fail (a fresh DNS filter with no
            // telemetry yet) without taking down the list view itself.
            let healthByUrl = {};
            try {
                const hres = await fetch("/api/filtering/lists/health");
                if (hres.ok) {
                    const hdata = await hres.json();
                    healthByUrl = Object.fromEntries(hdata.lists.map(l => [l.url, l]));
                }
            } catch (err) { /* list rows just render without badges */ }
            renderLists(data.filters, healthByUrl);
        } catch (err) {
            listsEl.innerHTML = `<div class="empty">Could not reach the DNS filter. Is it running?</div>`;
            rulesEl.innerHTML = "";
            masterBtn.textContent = "Unavailable";
        }
    }

    listsEl.addEventListener("click", async (e) => {
        const t = e.target.closest("[data-list-toggle]");
        if (t) {
            try {
                const res = await fetch("/api/filtering/lists/toggle", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: t.dataset.listToggle, enabled: t.dataset.enabled !== "1" }),
                });
                if (!res.ok) throw new Error("request failed");
                toast("Blocklist updated", "", "ok");
                loadStatus();
            } catch (err) { toast("Update failed", "Could not reach the DNS filter.", "high"); }
            return;
        }
        const rm = e.target.closest("[data-list-remove]");
        if (rm) {
            try {
                const res = await fetch("/api/filtering/lists/remove", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: rm.dataset.listRemove }),
                });
                if (!res.ok) throw new Error("request failed");
                toast("Blocklist removed", "", "ok");
                loadStatus();
            } catch (err) { toast("Remove failed", "Could not reach the DNS filter.", "high"); }
        }
    });

    rulesEl.addEventListener("click", async (e) => {
        const rm = e.target.closest("[data-rule-remove]");
        if (!rm) return;
        try {
            const res = await fetch("/api/filtering/rules/remove", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ rule: rm.dataset.ruleRemove }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Rule removed", "", "ok");
            loadStatus();
        } catch (err) { toast("Remove failed", "Could not reach the DNS filter.", "high"); }
    });

    masterBtn.addEventListener("click", async () => {
        const enabled = masterBtn.dataset.enabled !== "1";
        try {
            const res = await fetch("/api/filtering/enabled", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Filtering " + (enabled ? "enabled" : "disabled"), "", "ok");
            loadStatus();
        } catch (err) { toast("Update failed", "Could not reach the DNS filter.", "high"); }
    });

    $("#filterListAddForm").addEventListener("submit", async (e) => {
        e.preventDefault();
        const nameEl = $("#filterListName"), urlEl = $("#filterListUrl");
        const name = nameEl.value.trim(), url = urlEl.value.trim();
        if (!name || !url) return;
        try {
            const res = await fetch("/api/filtering/lists", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name, url }),
            });
            if (!res.ok) throw new Error("request failed");
            nameEl.value = ""; urlEl.value = "";
            toast("Blocklist added", name, "ok");
            loadStatus();
        } catch (err) { toast("Add failed", "Could not reach the DNS filter.", "high"); }
    });

    async function addRule(action) {
        const domainEl = $("#filterRuleDomain");
        const domain = domainEl.value.trim();
        if (!domain) return;
        try {
            const res = await fetch("/api/filtering/rules", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain, action }),
            });
            if (!res.ok) throw new Error("request failed");
            domainEl.value = "";
            toast("Rule added", `${action} ${domain}`, "ok");
            loadStatus();
        } catch (err) { toast("Add failed", "Could not reach the DNS filter.", "high"); }
    }
    $("#filterRuleBlockBtn").addEventListener("click", () => addRule("block"));
    $("#filterRuleAllowBtn").addEventListener("click", () => addRule("allow"));
    $("#filterRuleDomain").addEventListener("keydown", (e) => { if (e.key === "Enter") addRule("block"); });

    const devSel = $("#qlDevice");
    const checkDevSel = $("#checkDevice");
    fetch("/api/devices").then(r => r.json()).then(d => {
        const options = d.devices.map(dv => `<option value="${dv.id}">${esc(dv.name)}</option>`).join("");
        devSel.insertAdjacentHTML("beforeend", options);
        if (checkDevSel) checkDevSel.insertAdjacentHTML("beforeend", options);
    }).catch(() => {});

    async function runCheck() {
        const domain = $("#checkDomain").value.trim();
        const resultEl = $("#checkResult");
        if (!domain) return;
        resultEl.innerHTML = `<div class="empty">Checking…</div>`;
        const qs = new URLSearchParams({ domain });
        const deviceId = checkDevSel ? checkDevSel.value : "";
        if (deviceId) qs.set("device_id", deviceId);
        try {
            const res = await fetch("/api/filtering/check?" + qs.toString());
            if (!res.ok) throw new Error("request failed");
            const r = await res.json();
            const scope = deviceId ? checkDevSel.options[checkDevSel.selectedIndex].text : "the whole network";
            resultEl.innerHTML = `
                <div class="callout ${r.blocked ? "high" : ""}" style="margin:4px 16px 10px; ${r.blocked ? "" : "border-color:var(--ok-line); border-left-color:var(--ok); background:linear-gradient(90deg, rgba(47,191,113,.08), rgba(47,191,113,.02))"}">
                    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:4px">
                        <span class="chip dot ${r.blocked ? "high" : "ok"}">${r.blocked ? "Blocked" : "Allowed"}</span>
                        <span class="mono" style="color:var(--text)">${esc(r.domain || domain)}</span>
                        <span class="dim">for ${esc(scope)}</span>
                    </div>
                    ${esc(r.reason)}${r.rule ? ` — <span class="mono">${esc(r.rule)}</span>` : ""}
                    ${r.cname ? ` — via CNAME to <span class="mono">${esc(r.cname)}</span>` : ""}
                </div>`;
        } catch (err) {
            resultEl.innerHTML = `<div class="empty">Could not reach the DNS filter</div>`;
        }
    }
    const checkBtn = $("#checkBtn");
    if (checkBtn) {
        checkBtn.addEventListener("click", runCheck);
        $("#checkDomain").addEventListener("keydown", (e) => { if (e.key === "Enter") runCheck(); });
    }

    async function runQuerylogSearch() {
        const qs = new URLSearchParams({
            domain: $("#qlDomain").value.trim(),
            device_id: $("#qlDevice").value,
            blocked: $("#qlBlocked").value,
            limit: 100,
        });
        const results = $("#qlResults");
        results.innerHTML = `<div class="empty">Searching…</div>`;
        try {
            const res = await fetch("/api/filtering/querylog?" + qs.toString());
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            if (!data.results.length) { results.innerHTML = `<div class="empty">No matching queries</div>`; return; }
            results.innerHTML = data.results.map(r => `
                <div class="feed-row">
                    <span class="mono dim">${r.time}</span>
                    <span class="type-tag ${r.type}">dns</span>
                    <span class="truncate mono" title="${esc(r.detail)}">${esc(r.detail)}</span>
                    <span class="dim">${r.blocked ? '<span class="chip high">blocked</span>' : esc(r.device || "")}</span>
                </div>`).join("");
        } catch (err) {
            results.innerHTML = `<div class="empty">Search failed</div>`;
        }
    }
    $("#qlSearch").addEventListener("click", runQuerylogSearch);
    $("#qlDomain").addEventListener("keydown", (e) => { if (e.key === "Enter") runQuerylogSearch(); });

    loadStatus();
}

/* ---------------------------------------------------- segmented controls */

/* One indicator per segmented control that glides to whichever option is
   active. Every existing handler just toggles .active on a button as
   before; a MutationObserver notices and moves the indicator, so no
   handler needs to know this exists. */
function initSegIndicators() {
    $$(".seg").forEach(seg => {
        const buttons = $$("button", seg);
        if (!buttons.length || seg.querySelector(".seg-indicator")) return;
        const ind = document.createElement("span");
        ind.className = "seg-indicator";
        seg.prepend(ind);
        seg.classList.add("has-indicator");

        const place = (animate) => {
            const active = buttons.find(b => b.classList.contains("active"));
            if (!active) { ind.style.opacity = "0"; return; }
            if (!animate) ind.classList.add("no-anim");
            ind.style.opacity = "1";
            ind.style.width = `${active.offsetWidth}px`;
            ind.style.height = `${active.offsetHeight}px`;
            ind.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`;
            if (!animate) { void ind.offsetWidth; ind.classList.remove("no-anim"); }
        };
        const mo = new MutationObserver(() => place(true));
        buttons.forEach(b => mo.observe(b, { attributes: true, attributeFilter: ["class"] }));
        // Counts inside a button (e.g. "High 7") and wrapping on narrow
        // screens change geometry without a class change.
        if ("ResizeObserver" in window) {
            const ro = new ResizeObserver(() => place(false));
            ro.observe(seg);
            buttons.forEach(b => ro.observe(b));
        }
        place(false);
    });
}

/* Gives the topbar its shadow only once content has scrolled beneath it. */
function initTopbarElevation() {
    const bar = $(".topbar");
    if (!bar) return;
    let ticking = false;
    const update = () => { bar.classList.toggle("scrolled", window.scrollY > 4); ticking = false; };
    window.addEventListener("scroll", () => {
        if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    update();
}

/* ------------------------------------------------------- section subnav */

/* Highlights the jump link for whichever section is currently at the top
   of the viewport on long pages (Filtering). Purely presentational. */
function initSubnav() {
    const nav = $(".subnav");
    if (!nav || !("IntersectionObserver" in window)) return;
    const links = $$("a[href^='#']", nav);
    const targets = links.map(a => document.getElementById(a.getAttribute("href").slice(1))).filter(Boolean);
    const visible = new Map();
    const obs = new IntersectionObserver(entries => {
        entries.forEach(en => visible.set(en.target.id, en.isIntersecting));
        const current = targets.find(t => visible.get(t.id));
        if (current) links.forEach(a => a.classList.toggle("active", a.getAttribute("href") === "#" + current.id));
    }, { rootMargin: "-120px 0px -55% 0px" });
    targets.forEach(t => obs.observe(t));
}

/* ------------------------------------------------------- command palette */

const CMDK_PAGES = [
    { label: "Dashboard", href: "/", icon: "i-grid" },
    { label: "Devices", href: "/devices", icon: "i-monitor" },
    { label: "Incidents", href: "/incidents", icon: "i-alert" },
    { label: "Filtering", href: "/filtering", icon: "i-filter" },
    { label: "Hunt", href: "/hunt", icon: "i-search" },
    { label: "Weekly Report", href: "/reports/weekly", icon: "i-report" },
    { label: "Settings", href: "/settings", icon: "i-sliders" },
];
const CMDK_THEME_HREF = "#toggle-theme";

let cmdkItems = [];
let cmdkActive = 0;

function cmdkOpen() {
    const overlay = $("#cmdkOverlay");
    if (!overlay) return;
    overlay.hidden = false;
    const input = $("#cmdkInput");
    input.value = "";
    cmdkFilter("");
    setTimeout(() => input.focus(), 0);
    cmdkEnsureData();
}

function cmdkClose() {
    const overlay = $("#cmdkOverlay");
    if (overlay) overlay.hidden = true;
}

async function cmdkEnsureData() {
    if (!window.__devices) {
        try { const r = await fetch("/api/devices"); window.__devices = (await r.json()).devices; }
        catch (e) { /* command palette degrades to pages-only */ }
    }
    if (!window.__incidents) {
        try { const r = await fetch("/api/incidents"); window.__incidents = (await r.json()).incidents; }
        catch (e) { /* command palette degrades to pages-only */ }
    }
    cmdkFilter($("#cmdkInput").value);
}

function cmdkFilter(q) {
    q = (q || "").toLowerCase().trim();
    const groups = [];

    const pages = CMDK_PAGES.filter(p => !q || p.label.toLowerCase().includes(q));
    if (pages.length) groups.push({ label: "Pages", items: pages });

    const devices = (window.__devices || [])
        .filter(d => !q || (d.name + " " + (d.ip || "")).toLowerCase().includes(q)).slice(0, 6);
    if (devices.length) groups.push({
        label: "Devices",
        items: devices.map(d => ({ label: d.name, hint: d.ip, icon: "i-monitor", href: `/devices/${d.id}` })),
    });

    const incidents = (window.__incidents || [])
        .filter(i => !q || (i.title + " " + i.signal_type).toLowerCase().includes(q)).slice(0, 6);
    if (incidents.length) groups.push({
        label: "Incidents",
        items: incidents.map(i => ({ label: i.title, hint: i.severity, icon: "i-alert", href: `/incidents/${i.id}` })),
    });

    const themeLabel = currentTheme() === "light" ? "Switch to dark mode" : "Switch to light mode";
    if (!q || themeLabel.toLowerCase().includes(q) || "theme appearance".includes(q)) {
        groups.push({ label: "Preferences", items: [{
            label: themeLabel, hint: "theme", href: CMDK_THEME_HREF,
            icon: currentTheme() === "light" ? "i-moon" : "i-sun",
        }] });
    }

    cmdkItems = groups.flatMap(g => g.items);
    cmdkActive = 0;

    const el = $("#cmdkResults");
    if (!cmdkItems.length) { el.innerHTML = `<div class="cmdk-empty">No matches</div>`; return; }

    let idx = 0;
    el.innerHTML = groups.map(g => `
        <div class="cmdk-group-label">${esc(g.label)}</div>
        ${g.items.map(item => {
            const i = idx++;
            return `<div class="cmdk-item${i === 0 ? " active" : ""}" data-idx="${i}" data-href="${item.href}">
                <svg class="icon" width="15" height="15"><use href="#${item.icon || "i-search"}"/></svg>
                <span class="label">${esc(item.label)}</span>
                ${item.hint ? `<span class="hint">${esc(item.hint)}</span>` : ""}
            </div>`;
        }).join("")}
    `).join("");
}

function cmdkHighlight() {
    $$(".cmdk-item").forEach(el => el.classList.toggle("active", Number(el.dataset.idx) === cmdkActive));
    const active = $(`.cmdk-item[data-idx="${cmdkActive}"]`);
    if (active) active.scrollIntoView({ block: "nearest" });
}

function cmdkGo(idx) {
    const el = $(`.cmdk-item[data-idx="${idx}"]`);
    if (!el) return;
    if (el.dataset.href === CMDK_THEME_HREF) { cmdkClose(); toggleTheme(); return; }
    location.href = el.dataset.href;
}

/* ----------------------------------------------------------------- boot */

/* ================================================================ Stage 4
   Response and policy orchestration (ENHANCEMENT-PLAN.md steps 4.1-4.5):
   the dialog every response action uses, device trust / quarantine /
   profile / pause controls, the incident page's Respond card, the Response
   page, filtering profiles, network-wide pause and notification channels.
   Every change goes through the policy orchestrator's own endpoints, which
   verify it took and roll it back if it didn't - so the UI only ever shows
   the server's answer, never an optimistic guess. */

/* JSON request helper. Throws an Error carrying the server's own reason
   (FastAPI's `detail`), so a toast can say exactly why something failed. */
async function api(url, body, method) {
    const opts = (body === undefined && !method) ? {} : {
        method: method || "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
    };
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty body */ }
    if (!res.ok) {
        let msg = `request failed (${res.status})`;
        if (data && data.detail) {
            msg = typeof data.detail === "string" ? data.detail
                : (Array.isArray(data.detail) && data.detail[0] && data.detail[0].msg) || msg;
        }
        throw new Error(msg);
    }
    return data;
}

/* "42m", "3h 10m", "2d 4h" - for policy countdowns. */
function fmtLeft(s) {
    if (s == null) return "";
    if (s < 60) return "<1m";
    const m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d) return `${d}d ${h % 24}h`;
    if (h) return `${h}h ${m % 60}m`;
    return `${m}m`;
}

function fmtAgo(s) {
    if (s == null) return "never";
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
}

const DURATIONS = [
    { minutes: 15, label: "15 minutes" }, { minutes: 60, label: "1 hour" },
    { minutes: 1440, label: "24 hours" }, { minutes: 0, label: "Until released" },
];
const PAUSES = [{ minutes: 5, label: "5 minutes" }, { minutes: 15, label: "15 minutes" }, { minutes: 60, label: "1 hour" }];

/* A dropdown built on the existing row-menu component (and its global
   open/close delegate). Each item carries data-<attr>=value. */
function menuHtml(label, items, attr, cls) {
    return `<div class="row-menu">
        <button class="btn ${cls || ""}" data-toggle-menu>${label}
            <svg class="icon" width="12" height="12"><use href="#i-chevron-down"/></svg></button>
        <div class="row-menu-list">${items.map(i =>
            `<button data-${attr}="${esc(i.value)}">${esc(i.label)}</button>`).join("")}</div>
    </div>`;
}

/* ---------------------------------------------------------------- dialog */

/* A promise-based modal for anything that needs a reason, a choice or a
   confirmation - replaces window.prompt() for every Stage 4 action (a
   browser dialog blocks the whole page and can't show context).
   fields: [{name, label, type, value, options, required, hint, placeholder,
             min, max, showWhen: {name, in: [...]}}]
   Resolves with {name: value} or null if cancelled. */
function spDialog(opts) {
    return new Promise(resolve => {
        const overlay = document.createElement("div");
        overlay.className = "sp-dialog-overlay";
        const fieldHtml = (f) => {
            const id = `spf-${f.name}`;
            const show = f.showWhen ? ` data-show-name="${esc(f.showWhen.name)}" data-show-in="${esc(f.showWhen.in.join(","))}"` : "";
            const hint = f.hint ? `<span class="field-hint">${f.hint}</span>` : "";
            let input;
            if (f.type === "select") {
                input = `<select class="input" id="${id}" name="${esc(f.name)}">${f.options.map(o =>
                    `<option value="${esc(o.value)}" ${String(o.value) === String(f.value ?? "") ? "selected" : ""}>${esc(o.label)}</option>`).join("")}</select>`;
            } else if (f.type === "textarea") {
                input = `<textarea class="input" id="${id}" name="${esc(f.name)}" rows="3" placeholder="${esc(f.placeholder || "")}">${esc(f.value || "")}</textarea>`;
            } else if (f.type === "checkbox") {
                return `<label class="check-field"${show}><input type="checkbox" name="${esc(f.name)}" ${f.value ? "checked" : ""}>
                    <span><span class="check-label">${esc(f.label)}</span>${hint}</span></label>`;
            } else if (f.type === "html") {
                return `<div class="field"${show}>${f.html}</div>`;
            } else {
                input = `<input class="input" id="${id}" name="${esc(f.name)}" type="${f.type || "text"}"
                    value="${esc(f.value ?? "")}" placeholder="${esc(f.placeholder || "")}"
                    ${f.min != null ? `min="${f.min}"` : ""} ${f.max != null ? `max="${f.max}"` : ""} autocomplete="off">`;
            }
            return `<label class="field"${show} for="${id}"><span class="field-label">${esc(f.label)}${f.required ? "" : ' <span class="dim">optional</span>'}</span>${input}${hint}</label>`;
        };
        overlay.innerHTML = `
            <form class="sp-dialog ${opts.tone ? "tone-" + opts.tone : ""}" role="dialog" aria-modal="true" aria-labelledby="spDialogTitle" novalidate>
                <div class="sp-dialog-head">
                    ${opts.icon ? `<span class="sp-dialog-icon"><svg class="icon" width="17" height="17"><use href="#${opts.icon}"/></svg></span>` : ""}
                    <div><h3 id="spDialogTitle">${esc(opts.title)}</h3>
                    ${opts.description ? `<p>${opts.description}</p>` : ""}</div>
                </div>
                <div class="sp-dialog-body">${(opts.fields || []).map(fieldHtml).join("")}</div>
                <div class="sp-dialog-error" hidden></div>
                <div class="sp-dialog-foot">
                    <button type="button" class="btn ghost" data-cancel>Cancel</button>
                    <button type="submit" class="btn ${opts.tone === "danger" ? "danger" : "primary"}">${esc(opts.confirm || "Confirm")}</button>
                </div>
            </form>`;
        document.body.appendChild(overlay);
        const form = overlay.querySelector("form");
        const errEl = overlay.querySelector(".sp-dialog-error");

        function applyShowWhen() {
            $$("[data-show-name]", form).forEach(el => {
                const ctl = form.elements[el.dataset.showName];
                const val = ctl ? ctl.value : "";
                el.hidden = !el.dataset.showIn.split(",").includes(val);
            });
        }
        applyShowWhen();
        form.addEventListener("change", applyShowWhen);

        const previouslyFocused = document.activeElement;
        function close(result) {
            overlay.classList.add("closing");
            document.removeEventListener("keydown", onKey, true);
            setTimeout(() => overlay.remove(), 160);
            if (previouslyFocused && previouslyFocused.focus) previouslyFocused.focus();
            resolve(result);
        }
        function onKey(e) { if (e.key === "Escape") { e.preventDefault(); close(null); } }
        document.addEventListener("keydown", onKey, true);
        overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) close(null); });
        form.querySelector("[data-cancel]").addEventListener("click", () => close(null));
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            const values = {};
            for (const f of opts.fields || []) {
                if (f.type === "html") continue;
                const wrap = form.querySelector(`[name="${f.name}"]`);
                if (!wrap) continue;
                const hidden = wrap.closest("[data-show-name]") && wrap.closest("[data-show-name]").hidden;
                let v = f.type === "checkbox" ? wrap.checked : wrap.value.trim();
                if (f.type === "number" && v !== "") v = Number(v);
                if (f.required && !hidden && (v === "" || v == null)) {
                    errEl.textContent = `${f.label} is required.`;
                    errEl.hidden = false;
                    wrap.focus();
                    return;
                }
                if (!hidden) values[f.name] = v;
            }
            if (opts.collect) {
                const extra = opts.collect(form);
                if (extra && extra.error) { errEl.textContent = extra.error; errEl.hidden = false; return; }
                Object.assign(values, extra);
            }
            close(values);
        });
        if (opts.onRender) opts.onRender(form);
        requestAnimationFrame(() => {
            const first = form.querySelector("input:not([type=checkbox]), select, textarea");
            (first || form.querySelector("[type=submit]")).focus();
        });
    });
}

function reasonField(value, hint) {
    return { name: "reason", label: "Reason", type: "text", value: value || "", required: true,
             hint: hint || "Recorded with the policy and in the audit log." };
}

/* Everything on a device page that reads enforcement state listens for this,
   so one change (say, blocking the device) refreshes every card it affects. */
function deviceChanged() { document.dispatchEvent(new CustomEvent("sp:device-changed")); }

/* ------------------------------------------------------------ device trust */

const TRUST_META = {
    approved: { label: "Approved", cls: "ok" },
    unknown:  { label: "Unknown",  cls: "medium" },
    blocked:  { label: "Blocked",  cls: "high" },
};

function initDeviceTrust() {
    const wrap = $("#deviceTrust");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const name = ($(".hero h1") || {}).textContent || "this device";
    let trust = wrap.dataset.trust;
    let restrict = false;

    function render() {
        const m = TRUST_META[trust] || TRUST_META.unknown;
        const chip = $("#deviceTrustChip");
        chip.className = `chip dot nocap ${m.cls}`;
        chip.textContent = m.label;
        const desc = {
            approved: "A known device - normal access.",
            unknown: restrict
                ? "Restricted until approved. It can still reach DHCP, DNS and this console."
                : "Not approved yet. Unknown devices keep normal access while \"Restrict unknown devices\" is off.",
            blocked: "No internet access until approved. It keeps DHCP, DNS and this console.",
        }[trust];
        $("#deviceTrustDesc").textContent = desc;
        const actions = $("#deviceTrustActions");
        if (trust === "unknown") {
            actions.innerHTML = `<button class="btn success" data-trust-set="approved">Approve</button>
                                 <button class="btn" data-trust-set="blocked">Block</button>`;
        } else if (trust === "blocked") {
            actions.innerHTML = `<button class="btn success" data-trust-set="approved">Unblock</button>`;
        } else {
            actions.innerHTML = menuHtml("Change", [
                { value: "blocked", label: "Block this device" }, { value: "unknown", label: "Mark as unknown" }],
                "trust-set", "");
        }
    }

    async function set(next) {
        let reason = "";
        if (next === "blocked") {
            const v = await spDialog({
                title: `Block ${name}?`, tone: "danger", icon: "i-ban", confirm: "Block device",
                description: "Cuts off all internet traffic from this device at the firewall until it's approved. " +
                    "It can still get an address, resolve names and open this console.",
                fields: [reasonField("")],
            });
            if (!v) return;
            reason = v.reason;
        }
        try {
            const d = await api(`/api/devices/${deviceId}/trust`, { trust: next, reason });
            trust = d.trust;
            render();
            toast(next === "approved" ? "Device approved" : next === "blocked" ? "Device blocked" : "Marked as unknown",
                  next === "blocked" ? "All traffic from this device is now dropped at the gateway." : name,
                  next === "blocked" ? "high" : "ok");
            deviceChanged();
        } catch (err) {
            toast("Could not change trust", err.message, "high");
        }
    }

    wrap.addEventListener("click", (e) => {
        const b = e.target.closest("[data-trust-set]");
        if (b) set(b.dataset.trustSet);
    });

    api("/api/trust").then(t => { restrict = t.restrict_unknown; render(); }).catch(() => render());
    render();
}

/* ----------------------------------------------------- device quarantine */

function initDeviceQuarantine() {
    const wrap = $("#deviceQuarantine");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const compact = wrap.dataset.compact === "1";
    const actions = $("#deviceQuarantineActions");
    const desc = $("#deviceQuarantineDesc");

    async function load() {
        let d;
        try {
            d = await api(`/api/devices/${deviceId}/quarantine`);
        } catch (err) {
            actions.innerHTML = `<button class="btn" disabled>Unavailable</button>`;
            if (desc) desc.textContent = err.message;
            return;
        }
        const manual = d.policies.filter(p => p.source !== "trust");
        if (!d.quarantined) {
            if (desc) desc.innerHTML = `Full access. Quarantine drops all traffic from this device's
                ${d.macs.length === 1 ? "MAC" : `${d.macs.length} MACs`} at the firewall, so it holds across DHCP renewals.`;
            actions.innerHTML = menuHtml(`<svg class="icon" width="14" height="14"><use href="#i-ban"/></svg> Quarantine`,
                DURATIONS.map(x => ({ value: x.minutes, label: x.label })), "quarantine-for", "");
            return;
        }
        const left = d.expires_in_s != null ? ` · ${fmtLeft(d.expires_in_s)} left` : "";
        const by = d.policies.map(p => p.source_label).filter((v, i, a) => a.indexOf(v) === i).join(", ");
        const enforced = d.enforced
            ? `<span class="text-ok">enforced at the firewall</span>`
            : `<span class="text-high">not yet enforced - see the Response page</span>`;
        if (desc) desc.innerHTML = `<span class="text-high">Quarantined</span>${left} · ${esc(by)} · ${enforced}`;
        if (!manual.length) {
            actions.innerHTML = compact
                ? `<button class="btn danger" disabled title="Approve the device to lift this">Restricted · unknown device</button>`
                : `<span class="dim" style="font-size:11.5px">Approve the device to lift this</span>`;
            return;
        }
        const release = `<button class="btn success" data-quarantine-release>Release</button>`;
        if (compact) {
            actions.innerHTML = `<button class="btn danger" data-quarantine-release title="Release quarantine">
                Quarantined${left.replace(" · ", " · ")} · Release</button>`;
        } else {
            actions.innerHTML = menuHtml("Extend", DURATIONS.slice(0, 3).map(x => ({ value: x.minutes, label: `${x.label} from now` })),
                "quarantine-extend", "") + release;
        }
        actions.dataset.policyId = manual[0].id;
    }

    wrap.addEventListener("click", async (e) => {
        const q = e.target.closest("[data-quarantine-for]");
        if (q) {
            const minutes = Number(q.dataset.quarantineFor);
            const v = await spDialog({
                title: "Quarantine this device", tone: "danger", icon: "i-ban", confirm: "Quarantine",
                description: `All internet traffic from this device is dropped at the gateway ${minutes
                    ? `for <b>${esc(DURATIONS.find(x => x.minutes === minutes).label)}</b>, then released automatically`
                    : "<b>until you release it</b>"}. It can still reach the gateway's DHCP, DNS and this console.`,
                fields: [reasonField("")],
            });
            if (!v) return;
            try {
                await api(`/api/devices/${deviceId}/quarantine`, { quarantined: true, minutes: minutes || null, reason: v.reason });
                toast("Device quarantined", minutes ? `Released automatically in ${fmtLeft(minutes * 60)}.` : "Until you release it.", "high");
                deviceChanged();
            } catch (err) {
                toast("Quarantine failed", err.message, "high");
            }
            return;
        }
        const ext = e.target.closest("[data-quarantine-extend]");
        if (ext) {
            try {
                await api(`/api/policies/${actions.dataset.policyId}/extend`, { minutes: Number(ext.dataset.quarantineExtend) });
                toast("Quarantine extended", `Now ends in ${fmtLeft(Number(ext.dataset.quarantineExtend) * 60)}.`, "ok");
                deviceChanged();
            } catch (err) {
                toast("Could not extend", err.message, "high");
            }
            return;
        }
        if (e.target.closest("[data-quarantine-release]")) {
            try {
                const d = await api(`/api/devices/${deviceId}/quarantine`, { quarantined: false, reason: "released from the console" });
                toast(d.trust_based ? "Released - still restricted" : "Quarantine released",
                      d.trust_based ? "The device is unknown or blocked; approve it to restore access." : "Network access restored.",
                      d.trust_based ? "medium" : "ok");
                deviceChanged();
            } catch (err) {
                toast("Release failed", err.message, "high");
            }
        }
    });

    document.addEventListener("sp:device-changed", load);
    load();
    setInterval(() => { if (!document.hidden) load(); }, 30000);
}

/* --------------------------------------------- device profile and pause */

function initDeviceFiltering() {
    const wrap = $("#deviceFiltering");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const pick = $("#deviceProfilePick");
    const desc = $("#deviceFilteringDesc");
    const pauseEl = $("#devicePauseActions");
    let profiles = [];
    let current = null;

    async function load() {
        try {
            const [p, f] = await Promise.all([
                profiles.length ? Promise.resolve({ profiles }) : api("/api/profiles"),
                api(`/api/devices/${deviceId}/filtering`),
            ]);
            profiles = p.profiles;
            current = f;
            pick.innerHTML = profiles.map(x => `<option value="${esc(x.key)}" ${x.key === f.profile ? "selected" : ""}>${esc(x.label)}</option>`).join("");
            let text = esc(f.profile_label);
            if (f.schedule_label) text += ` · schedule ${esc(f.schedule_label)}${f.schedule_active ? ' <span class="text-medium">(active now)</span>' : ""}`;
            if (f.paused) text = `<span class="text-medium">Paused · ${fmtLeft(f.pause_remaining_s)} left</span> · ${text}`;
            else if (f.managed && f.filtering_enabled === false && f.profile !== "unrestricted") {
                text += ` · <span class="text-high">the DNS filter reports filtering off - the orchestrator will correct it</span>`;
            }
            desc.innerHTML = text;
            if (f.paused) {
                pauseEl.innerHTML = `<button class="btn" data-device-resume>Resume</button>`;
            } else if (f.profile === "unrestricted") {
                pauseEl.innerHTML = "";
            } else {
                pauseEl.innerHTML = menuHtml(`<svg class="icon" width="13" height="13"><use href="#i-pause"/></svg> Pause`,
                    PAUSES.map(x => ({ value: x.minutes, label: x.label })), "device-pause", "");
            }
        } catch (err) {
            desc.textContent = err.message;
        }
    }

    pick.addEventListener("change", async () => {
        const key = pick.value;
        const label = pick.options[pick.selectedIndex].text;
        if (key === "unrestricted") {
            const v = await spDialog({
                title: "Turn DNS filtering off for this device?", tone: "danger", confirm: "Turn off filtering",
                description: "Ads, trackers and known-malicious domains will resolve normally for this device. " +
                    "Quarantine, detection and incident alerts still apply.",
                fields: [reasonField("")],
            });
            if (!v) { pick.value = current.profile; return; }
            return apply(key, label, v.reason);
        }
        apply(key, label, `profile set to ${label} from the console`);
    });

    async function apply(key, label, reason) {
        pick.disabled = true;
        try {
            await api(`/api/devices/${deviceId}/profile`, { profile: key, reason });
            toast("Profile applied", `${label} - verified in the DNS filter.`, "ok");
            deviceChanged();
        } catch (err) {
            toast("Profile not applied", err.message, "high");
            pick.value = current.profile;
        } finally {
            pick.disabled = false;
        }
    }

    wrap.addEventListener("click", async (e) => {
        const p = e.target.closest("[data-device-pause]");
        if (p) {
            try {
                await api(`/api/devices/${deviceId}/pause`, { minutes: Number(p.dataset.devicePause), reason: "paused from the device page" });
                toast("Filtering paused", `Resumes automatically in ${fmtLeft(Number(p.dataset.devicePause) * 60)}.`, "medium");
                deviceChanged();
            } catch (err) { toast("Could not pause", err.message, "high"); }
            return;
        }
        if (e.target.closest("[data-device-resume]")) {
            try {
                await api(`/api/devices/${deviceId}/resume`, {});
                toast("Filtering resumed", "", "ok");
                deviceChanged();
            } catch (err) { toast("Could not resume", err.message, "high"); }
        }
    });

    document.addEventListener("sp:device-changed", load);
    load();
}

/* ------------------------------------------------- device active policies */

function policyChipCls(kind) {
    return { quarantine: "high", block_ip: "high", block_domain: "medium", allow_domain: "ok",
             pause: "medium", enroll: "low", profile: "neutral", native_profile: "neutral" }[kind] || "neutral";
}

function policyTargetHtml(p) {
    if (p.kind === "quarantine") return `<span class="dim">all traffic</span>`;
    if (p.kind === "pause") return `<span class="dim">DNS filtering</span>`;
    if (p.kind === "enroll") return `<span class="dim">HTTPS ad removal</span>`;
    if (p.kind === "profile" || p.kind === "native_profile") return esc(p.target_label);
    return `<span class="mono">${esc(p.target)}</span>`;
}

function policyVerifiedHtml(p) {
    if (p.last_error) return `<span class="text-high" title="${esc(p.last_error)}">check failed</span>`;
    if (p.verified_age_s == null) return `<span class="dim">pending</span>`;
    return `<span class="text-ok" title="Read back from the firewall / DNS filter">✓</span> <span class="dim">${fmtAgo(p.verified_age_s)}</span>`;
}

async function endPolicyFlow(p, onDone) {
    if (p.source === "trust") {
        toast("Approve the device instead", "This restriction comes from the device's trust state.", "medium");
        return;
    }
    const v = await spDialog({
        title: `End this ${p.kind_label.toLowerCase()}?`, confirm: "End policy",
        description: `${esc(p.kind_label)} · ${policyTargetHtml(p)}${p.device_name ? ` · ${esc(p.device_name)}` : " · every device"}`,
        fields: [{ name: "reason", label: "Reason", type: "text", required: false, value: "" }],
    });
    if (!v) return;
    try {
        await api(`/api/policies/${p.id}/end`, { reason: v.reason || "" });
        toast("Policy ended", "Removed and verified.", "ok");
        if (onDone) onDone();
    } catch (err) {
        toast("Could not end policy", err.message, "high");
    }
}

function initDevicePolicies() {
    const wrap = $("#devicePolicies");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const body = $("#devicePoliciesBody");
    let rows = [];

    async function load() {
        try {
            rows = (await api(`/api/policies?device_id=${deviceId}`)).policies;
        } catch (err) {
            body.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
            return;
        }
        const count = $("#devicePoliciesCount");
        count.hidden = !rows.length;
        count.textContent = rows.length;
        if (!rows.length) {
            body.innerHTML = `<div class="empty"><span class="empty-icon">✓</span>Nothing enforced on this device beyond the network defaults</div>`;
            return;
        }
        body.innerHTML = rows.map(p => `
            <div class="list-row policy-row" data-key="${p.id}">
                <span class="chip ${policyChipCls(p.kind)} nocap">${esc(p.kind_label)}</span>
                <span class="grow">${policyTargetHtml(p)} <span class="dim">· ${esc(p.source_label)}</span></span>
                <span class="dim num">${p.remaining_s != null ? fmtLeft(p.remaining_s) + " left" : "no end"}</span>
                <span class="num">${policyVerifiedHtml(p)}</span>
                ${p.source === "trust" ? "" : `<button class="btn ghost" data-end-policy="${p.id}" title="End this policy">End</button>`}
            </div>`).join("");
        markNewRows(body, ".policy-row", true);
    }

    body.addEventListener("click", (e) => {
        const b = e.target.closest("[data-end-policy]");
        if (!b) return;
        const p = rows.find(r => String(r.id) === b.dataset.endPolicy);
        if (p) endPolicyFlow(p, deviceChanged);
    });
    document.addEventListener("sp:device-changed", load);
    load();
    setInterval(() => { if (!document.hidden) load(); }, 30000);
}

/* -------------------------------------------------- incident Respond card */

function initIncidentResponse() {
    const card = $("#incidentResponse");
    if (!card) return;
    const incidentId = card.dataset.incidentId;
    const deviceId = card.dataset.deviceId;
    const deviceName = card.dataset.deviceName;
    const body = $("#incidentResponseBody");
    const title = ($(".hero h1") || {}).textContent || `incident #${incidentId}`;
    const defaultReason = `response to incident #${incidentId}: ${title}`.slice(0, 200);

    async function load() {
        let d;
        try {
            d = await api(`/api/incidents/${incidentId}/response`);
        } catch (err) {
            body.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
            return;
        }
        const sections = [];
        if (d.device_id != null) {
            let contain;
            if (!d.device_has_mac) {
                contain = `<span class="dim">No MAC known for this device, so it can't be quarantined at the firewall.</span>`;
            } else if (d.device_quarantined) {
                contain = `<span class="chip high nocap dot">Quarantined</span> <a class="link" href="/devices/${d.device_id}">manage on the device page →</a>`;
            } else {
                contain = `<div class="btn-group">${DURATIONS.map(x =>
                    `<button class="btn" data-resp-quarantine="${x.minutes}">${x.minutes ? esc(x.label.replace(" minutes", " min").replace(" hours", " h").replace(" hour", " h")) : "Until released"}</button>`).join("")}</div>`;
            }
            let trust = "";
            if (d.device_trust === "unknown") {
                trust = `<div class="resp-row"><div class="resp-label"><div class="row-title">Trust</div>
                    <div class="row-sub">${esc(d.device_name)} is not approved yet</div></div>
                    <div class="resp-actions"><button class="btn success" data-resp-trust="approved">Approve device</button>
                    <button class="btn" data-resp-trust="blocked">Block device</button></div></div>`;
            }
            sections.push(`<div class="resp-row"><div class="resp-label"><div class="row-title">Quarantine ${esc(d.device_name)}</div>
                <div class="row-sub">cut off all its internet traffic, keyed on MAC</div></div>
                <div class="resp-actions">${contain}</div></div>${trust}`);
        }
        const target = (kind, v, scopeDevice) => v.blocked_by
            ? `<span class="chip ok nocap dot">blocked${v.scope === "device" ? " for this device" : ""}</span>`
            : (kind === "domain"
                ? `${d.device_id != null ? `<button class="btn" data-resp-block="block_domain" data-scope="device" data-target="${esc(v.value)}">This device</button>` : ""}
                   <button class="btn" data-resp-block="block_domain" data-scope="network" data-target="${esc(v.value)}">Every device</button>`
                : `<button class="btn" data-resp-block="block_ip" data-scope="network" data-target="${esc(v.value)}">Block for every device</button>`);
        if (d.domains.length) {
            sections.push(`<div class="section-label" style="margin:14px 0 4px">Domains in the evidence</div>` + d.domains.map(v => `
                <div class="resp-row"><div class="resp-label"><span class="mono">${esc(v.value)}</span>
                    <span class="dim"> · ${v.events} event${v.events === 1 ? "" : "s"}</span></div>
                    <div class="resp-actions">${target("domain", v)}</div></div>`).join(""));
        }
        if (d.ips.length) {
            sections.push(`<div class="section-label" style="margin:14px 0 4px">Internet addresses in the evidence</div>` + d.ips.map(v => `
                <div class="resp-row"><div class="resp-label"><span class="mono">${esc(v.value)}</span>
                    <span class="dim"> · ${v.events} event${v.events === 1 ? "" : "s"}</span></div>
                    <div class="resp-actions">${target("ip", v)}</div></div>`).join(""));
        }
        if (!d.domains.length && !d.ips.length) {
            sections.push(`<p class="note" style="margin-top:10px">The evidence has no internet domain or address to block - LAN
                addresses (like the target of a scan) are left out on purpose.</p>`);
        }
        if (d.policies.length) {
            sections.push(`<div class="section-label" style="margin:14px 0 4px">Taken from this incident</div>` + d.policies.map(p => `
                <div class="resp-row"><div class="resp-label"><span class="chip ${policyChipCls(p.kind)} nocap">${esc(p.kind_label)}</span>
                    ${policyTargetHtml(p)} <span class="dim">· ${esc(p.created)}</span></div>
                    <div class="resp-actions"><span class="status-pill ${p.status === "active" ? "investigating" : "resolved"}">${esc(p.status)}</span></div></div>`).join(""));
        }
        body.innerHTML = sections.join("");
    }

    body.addEventListener("click", async (e) => {
        const q = e.target.closest("[data-resp-quarantine]");
        if (q) {
            const minutes = Number(q.dataset.respQuarantine);
            const v = await spDialog({
                title: `Quarantine ${deviceName}`, tone: "danger", icon: "i-ban", confirm: "Quarantine",
                description: minutes ? `Released automatically after ${esc(DURATIONS.find(x => x.minutes === minutes).label)}.` : "Until you release it.",
                fields: [reasonField(defaultReason)],
            });
            if (!v) return;
            try {
                await api("/api/policies", { kind: "quarantine", device_id: Number(deviceId), minutes: minutes || null,
                                             reason: v.reason, incident_id: Number(incidentId) });
                toast("Device quarantined", deviceName, "high");
                load(); deviceChanged();
            } catch (err) { toast("Quarantine failed", err.message, "high"); }
            return;
        }
        const b = e.target.closest("[data-resp-block]");
        if (b) {
            const everyone = b.dataset.scope === "network";
            const v = await spDialog({
                title: `Block ${b.dataset.target}`, icon: "i-ban", confirm: "Block",
                description: everyone ? "Blocked for every device on the network." : `Blocked for ${esc(deviceName)} only.`,
                fields: [
                    { name: "minutes", label: "For", type: "select", value: "0", required: true, options: [
                        { value: "0", label: "Until removed" }, { value: "60", label: "1 hour" },
                        { value: "1440", label: "24 hours" }, { value: "10080", label: "7 days" }] },
                    reasonField(defaultReason)],
            });
            if (!v) return;
            try {
                await api("/api/policies", {
                    kind: b.dataset.respBlock, target: b.dataset.target, reason: v.reason,
                    device_id: everyone ? null : Number(deviceId), minutes: Number(v.minutes) || null,
                    incident_id: Number(incidentId) });
                toast("Blocked", b.dataset.target, "ok");
                load();
            } catch (err) { toast("Block failed", err.message, "high"); }
            return;
        }
        const t = e.target.closest("[data-resp-trust]");
        if (t) {
            try {
                await api(`/api/devices/${deviceId}/trust`, { trust: t.dataset.respTrust, reason: defaultReason });
                toast(t.dataset.respTrust === "approved" ? "Device approved" : "Device blocked", deviceName,
                      t.dataset.respTrust === "approved" ? "ok" : "high");
                load(); deviceChanged();
            } catch (err) { toast("Could not change trust", err.message, "high"); }
        }
    });
    document.addEventListener("sp:device-changed", load);
    load();
}

/* ------------------------------------------------------------ response page */

let responseState = { filter: "", policies: [] };

const POLICY_FILTERS = {
    quarantine: k => k === "quarantine",
    block: k => ["block_ip", "block_domain", "allow_domain"].includes(k),
    filtering: k => ["profile", "pause", "native_profile"].includes(k),
    enroll: k => k === "enroll",
};

function renderPolicyTable() {
    const el = $("#policyTable");
    if (!el) return;
    const f = POLICY_FILTERS[responseState.filter];
    const rows = responseState.policies.filter(p => !f || f(p.kind));
    if (!rows.length) {
        el.innerHTML = `<div class="empty"><span class="empty-icon">✓</span>${responseState.filter
            ? "No active policies of this kind" : "Nothing is being enforced beyond the network defaults"}</div>`;
        return;
    }
    el.innerHTML = `<table><thead><tr><th>Policy</th><th>Target</th><th>Device</th><th>Source</th>
        <th class="num">Ends</th><th class="num">Verified</th><th></th></tr></thead><tbody>${rows.map(p => `
        <tr data-key="${p.id}">
            <td style="white-space:nowrap"><span class="chip ${policyChipCls(p.kind)} nocap">${esc(p.kind_label)}</span></td>
            <td class="truncate" title="${esc(p.reason)}">${policyTargetHtml(p)}<div class="row-sub">${esc(p.reason)}</div></td>
            <td>${p.device_id != null ? `<a class="link" href="/devices/${p.device_id}">${esc(p.device_name)}</a>` : '<span class="dim">every device</span>'}</td>
            <td class="dim" style="white-space:nowrap">${esc(p.source_label)}</td>
            <td class="num" style="white-space:nowrap">${p.remaining_s != null ? fmtLeft(p.remaining_s) : '<span class="dim">—</span>'}</td>
            <td class="num" style="white-space:nowrap">${policyVerifiedHtml(p)}</td>
            <td class="num" style="width:1%">${p.source === "trust" ? "" : `
                <div class="row-menu"><button class="icon-btn row-menu-btn" data-toggle-menu aria-label="Policy actions">
                    <svg class="icon" width="15" height="15"><use href="#i-more"/></svg></button>
                    <div class="row-menu-list">
                        ${p.expires_at ? `<button data-policy-extend="${p.id}" data-minutes="60">Extend 1 hour from now</button>
                                          <button data-policy-extend="${p.id}" data-minutes="1440">Extend 24 hours from now</button>
                                          <div class="divider"></div>` : ""}
                        <button data-policy-end="${p.id}">End policy</button>
                    </div></div>`}</td>
        </tr>`).join("")}</tbody></table>`;
    markNewRows($("#policyTable tbody"), "tr[data-key]", true);
}

async function refreshResponse() {
    if (!$("#policyTable")) return;
    const [st, act, ended, sets, trust] = await Promise.all([
        api("/api/orchestrator/status"), api("/api/policies?status=active"),
        api("/api/policies?status=ended&limit=25"), api("/api/settings"), api("/api/trust"),
    ]);
    responseState.policies = act.policies;
    renderPolicyTable();

    const quarantined = new Set(act.policies.filter(p => p.kind === "quarantine").map(p => p.device_id));
    animateNumber($("#kpiPolicies"), st.total_active);
    const KPI_KIND = { quarantine: "quarantine", block_ip: "IP block", block_domain: "domain block", allow_domain: "allow",
                       profile: "profile", pause: "pause", enroll: "inspection", native_profile: "telemetry block" };
    $("#kpiPoliciesSub").textContent = Object.entries(st.counts)
        .map(([k, n]) => `${n} ${KPI_KIND[k] || k}${n === 1 || k === "enroll" ? "" : "s"}`).join(" · ") || "nothing beyond the defaults";
    animateNumber($("#kpiQuarantined"), quarantined.size);
    $("#kpiQuarantinedSub").textContent = `${act.policies.filter(p => p.kind === "quarantine" && p.source.startsWith("auto:")).length} by auto-response`;
    animateNumber($("#kpiDrift"), st.drift_24h);
    $("#kpiDriftSub").textContent = `${st.rollbacks_24h} rollback${st.rollbacks_24h === 1 ? "" : "s"} in 24h`;
    const o = st.status;
    $("#kpiOrch").innerHTML = o.healthy ? `<span class="text-ok">Healthy</span>` : `<span class="text-high">${o.last_run ? "Degraded" : "Not run yet"}</span>`;
    $("#kpiOrchSub").textContent = o.last_run ? `last cycle ${fmtAgo(o.last_run_age_s)}` : "waiting for the engine";

    $("#orchDomains").innerHTML = Object.entries(o.domains).map(([k, dm]) => `
        <div class="list-row"><span class="status-dot ${dm.ok ? "online" : dm.checked_at ? "failed" : "offline"}"></span>
            <span class="grow">${esc(dm.label)}${dm.error ? `<div class="row-sub text-high" title="${esc(dm.error)}">${esc(dm.error)}</div>` : ""}</span>
            <span class="dim num">${dm.checked_at ? fmtAgo(Math.round(Date.now() / 1000 - dm.checked_at)) : "not checked"}</span></div>`).join("");

    const actEl = $("#orchActivity");
    actEl.innerHTML = st.activity.length ? st.activity.map(a => `
        <div class="audit-row compact" data-key="${esc(a.ts + a.action)}"><span class="mono dim">${esc(a.age)}</span>
            <span class="type-tag ${a.action.includes("drift") || a.action.includes("rolled_back") ? "alert" : ""}">${esc(a.action.replace("policy.", "").replace(/_/g, " "))}</span>
            <span class="desc" title="${esc(a.detail || "")}">${esc(a.detail || a.target || "")}</span>
            <span class="detail">${esc(a.actor)}</span></div>`).join("")
        : `<div class="empty">No orchestrator activity yet</div>`;
    markNewRows(actEl, ".audit-row", true);

    $("#policyEnded").innerHTML = ended.policies.length ? `<table class="compact"><tbody>${ended.policies.map(p => `
        <tr><td style="width:1%;white-space:nowrap"><span class="chip ${policyChipCls(p.kind)} nocap">${esc(p.kind_label)}</span></td>
            <td class="truncate">${policyTargetHtml(p)} ${p.device_name ? `<span class="dim">· ${esc(p.device_name)}</span>` : ""}
                <div class="row-sub" title="${esc(p.ended_reason || p.last_error || "")}">${esc(p.ended_reason || p.last_error || "")}</div></td>
            <td style="width:1%"><span class="status-pill ${p.status === "failed" ? "new" : "resolved"}">${esc(p.status)}</span></td>
            <td class="num dim" style="white-space:nowrap">${esc(p.ended || p.created)}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">Nothing has ended yet</div>`;

    renderAutoResponse(sets.settings);
    renderTrustCard(trust);
}

function renderAutoResponse(s) {
    const on = s.auto_quarantine_enabled.value;
    const chip = $("#autoResponseChip");
    chip.className = `chip nocap dot ${on ? "ok" : "neutral"}`;
    chip.textContent = on ? "On" : "Off";
    $("#autoResponseBody").innerHTML = `
        <p class="note" style="margin-bottom:12px">When a campaign links incidents across at least
            <b>${s.auto_quarantine_min_tactics.value}</b> distinct ATT&amp;CK tactics, its device is quarantined for
            <b>${fmtLeft(s.auto_quarantine_minutes.value * 60)}</b> without waiting for a person. Each campaign is acted on
            once, and only campaigns that start after this is switched on.</p>
        <div class="toolbar">
            <button class="btn ${on ? "danger" : "primary"}" data-auto-toggle="${on ? 0 : 1}">${on ? "Turn off" : "Turn on"}</button>
            <label class="field inline"><span class="field-label">Tactics</span>
                <input class="input" type="number" id="autoMinTactics" min="2" max="5" value="${s.auto_quarantine_min_tactics.value}" style="width:72px;min-width:0"></label>
            <label class="field inline"><span class="field-label">Minutes</span>
                <input class="input" type="number" id="autoMinutes" min="5" max="10080" value="${s.auto_quarantine_minutes.value}" style="width:92px;min-width:0"></label>
            <button class="btn" data-auto-save>Save</button>
        </div>`;
}

function renderTrustCard(t) {
    const chip = $("#trustChip");
    chip.className = `chip nocap dot ${t.restrict_unknown ? "ok" : "neutral"}`;
    chip.textContent = t.restrict_unknown ? "Restricting unknown devices" : "Unknown devices allowed";
    $("#trustBody").innerHTML = `
        <div class="stats boxed" style="margin-bottom:12px">
            <div class="stat"><div class="stat-label">Approved</div><div class="stat-value">${t.counts.approved}</div></div>
            <div class="stat"><div class="stat-label">Unknown</div><div class="stat-value ${t.counts.unknown ? "text-medium" : ""}">${t.counts.unknown}</div></div>
            <div class="stat"><div class="stat-label">Blocked</div><div class="stat-value ${t.counts.blocked ? "text-high" : ""}">${t.counts.blocked}</div></div>
        </div>
        <div class="toolbar" style="margin-bottom:${t.unknown.length ? 10 : 0}px">
            <button class="btn ${t.restrict_unknown ? "" : "primary"}" data-restrict-toggle="${t.restrict_unknown ? 0 : 1}">
                ${t.restrict_unknown ? "Stop restricting unknown devices" : "Restrict unknown devices"}</button>
            <span class="note">A restricted device keeps DHCP, DNS and this console, so it can always be approved.</span>
        </div>
        ${t.unknown.map(d => `
            <div class="list-row"><span class="grow"><a class="link" href="/devices/${d.id}">${esc(d.name)}</a>
                <span class="dim"> · first seen ${esc(d.first_seen_age)} ago</span>
                ${d.restricted ? '<span class="chip medium nocap" style="margin-left:6px">restricted</span>' : ""}</span>
                <button class="btn success" data-trust-device="${d.id}" data-trust="approved">Approve</button>
                <button class="btn" data-trust-device="${d.id}" data-trust="blocked">Block</button></div>`).join("")}`;
}

function initResponsePage() {
    if (!$("#policyTable")) return;
    const reload = () => refreshResponse().catch(err => toast("Could not load", err.message, "high"));

    $("#policyFilter").addEventListener("click", (e) => {
        const b = e.target.closest("button[data-filter]");
        if (!b) return;
        $$("#policyFilter button").forEach(x => x.classList.toggle("active", x === b));
        responseState.filter = b.dataset.filter;
        renderPolicyTable();
    });

    $("#orchVerify").addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        btn.disabled = true;
        try {
            const d = await api("/api/orchestrator/reconcile", {});
            const s = d.summary;
            toast(Object.keys(s.errors).length ? "Verified with errors" : "Everything verified",
                  s.drift.length ? `${s.drift.length} change(s) outside the console were put back.` : "Every enforcement point matches the console.",
                  Object.keys(s.errors).length ? "high" : "ok");
            reload();
        } catch (err) { toast("Verify failed", err.message, "high"); }
        finally { btn.disabled = false; }
    });

    $("#policyAdd").addEventListener("click", async () => {
        let devices = [];
        try { devices = (await api("/api/devices")).devices; } catch (e) { /* network-wide still works */ }
        const v = await spDialog({
            title: "Block or allow", icon: "i-ban", confirm: "Apply",
            description: "Applied through the orchestrator and read back before it counts as done.",
            fields: [
                { name: "kind", label: "Action", type: "select", value: "block_domain", required: true, options: [
                    { value: "block_domain", label: "Block a domain (and its subdomains)" },
                    { value: "allow_domain", label: "Allow a domain (overrides blocklists)" },
                    { value: "block_ip", label: "Block an internet address (every device)" }] },
                { name: "target", label: "Domain or address", type: "text", required: true, placeholder: "tracker.example.com or 203.0.113.9" },
                { name: "device_id", label: "Applies to", type: "select", value: "", required: false,
                  showWhen: { name: "kind", in: ["block_domain", "allow_domain"] },
                  options: [{ value: "", label: "Every device" }].concat(devices.map(d => ({ value: d.id, label: d.name }))) },
                { name: "minutes", label: "For", type: "select", value: "0", required: true, options: [
                    { value: "0", label: "Until removed" }, { value: "60", label: "1 hour" },
                    { value: "1440", label: "24 hours" }, { value: "10080", label: "7 days" }] },
                reasonField(""),
            ],
        });
        if (!v) return;
        try {
            await api("/api/policies", { kind: v.kind, target: v.target, reason: v.reason,
                device_id: v.kind === "block_ip" || !v.device_id ? null : Number(v.device_id),
                minutes: Number(v.minutes) || null });
            toast("Applied and verified", v.target, "ok");
            reload();
        } catch (err) { toast("Not applied", err.message, "high"); }
    });

    document.addEventListener("click", async (e) => {
        const end = e.target.closest("[data-policy-end]");
        if (end) {
            const p = responseState.policies.find(r => String(r.id) === end.dataset.policyEnd);
            if (p) endPolicyFlow(p, reload);
            return;
        }
        const ext = e.target.closest("[data-policy-extend]");
        if (ext) {
            try {
                await api(`/api/policies/${ext.dataset.policyExtend}/extend`, { minutes: Number(ext.dataset.minutes) });
                toast("Extended", "", "ok");
                reload();
            } catch (err) { toast("Could not extend", err.message, "high"); }
            return;
        }
        const at = e.target.closest("[data-auto-toggle]");
        if (at) {
            const on = at.dataset.autoToggle === "1";
            const v = await spDialog({
                title: on ? "Turn on auto-response?" : "Turn off auto-response?", tone: on ? "danger" : "",
                confirm: on ? "Turn on" : "Turn off",
                description: on ? "A false-positive campaign will cut a real device off without anyone deciding to. " +
                    "It's released automatically when the time runs out, and can be released sooner from its device page." : "",
                fields: [reasonField("")],
            });
            if (!v) return;
            try {
                await api("/api/settings/auto_quarantine_enabled", { value: on, reason: v.reason });
                toast(on ? "Auto-response on" : "Auto-response off", "", on ? "medium" : "ok");
                reload();
            } catch (err) { toast("Could not change setting", err.message, "high"); }
            return;
        }
        if (e.target.closest("[data-auto-save]")) {
            const v = await spDialog({ title: "Save auto-response settings", fields: [reasonField("")] });
            if (!v) return;
            try {
                await api("/api/settings/auto_quarantine_min_tactics", { value: parseInt($("#autoMinTactics").value, 10), reason: v.reason });
                await api("/api/settings/auto_quarantine_minutes", { value: parseInt($("#autoMinutes").value, 10), reason: v.reason });
                toast("Saved", "", "ok");
                reload();
            } catch (err) { toast("Could not save", err.message, "high"); }
            return;
        }
        const rt = e.target.closest("[data-restrict-toggle]");
        if (rt) {
            const on = rt.dataset.restrictToggle === "1";
            const trust = await api("/api/trust");
            const v = await spDialog({
                title: on ? "Restrict unknown devices?" : "Stop restricting unknown devices?",
                confirm: on ? "Restrict" : "Stop restricting", tone: on ? "danger" : "",
                description: on
                    ? "From now on, a device the gateway hasn't seen before has no internet access until you approve it. " +
                      "It can still get an address, resolve names and open this console - so approving it from the device itself works."
                    : "Unknown devices get normal access again. Blocked devices stay blocked.",
                fields: on ? [{ name: "approve", type: "checkbox", value: true,
                    label: `Approve the ${trust.counts.unknown} unknown device${trust.counts.unknown === 1 ? "" : "s"} already on the network first`,
                    hint: "Recommended - otherwise they lose access the moment this is switched on." }] : [],
            });
            if (!v) return;
            try {
                const d = await api("/api/trust/restrict", { enabled: on, approve_existing: on ? !!v.approve : false });
                toast(on ? "Unknown devices restricted" : "Restriction off",
                      on && d.approved ? `${d.approved} existing device(s) approved first.` : "", "ok");
                reload();
            } catch (err) { toast("Could not change setting", err.message, "high"); }
            return;
        }
        const td = e.target.closest("[data-trust-device]");
        if (td) {
            try {
                await api(`/api/devices/${td.dataset.trustDevice}/trust`, { trust: td.dataset.trust, reason: "from the Response page" });
                toast(td.dataset.trust === "approved" ? "Approved" : "Blocked", "", td.dataset.trust === "approved" ? "ok" : "high");
                reload();
            } catch (err) { toast("Could not change trust", err.message, "high"); }
        }
    });

    reload();
}

/* ------------------------------------------------- filtering: profiles */

const GROUP_LABELS = {
    ai: "AI assistants", cdn: "CDNs", dating: "Dating", gambling: "Gambling", gaming: "Gaming", hosting: "File hosting",
    messenger: "Messaging", privacy: "VPN & privacy relays", shopping: "Shopping", social_network: "Social media",
    software: "App stores & software", streaming: "Video & music streaming", other: "Other",
};

function servicesSummary(list) {
    if (!list.length) return "none";
    return list.map(s => s.startsWith("group:") ? (GROUP_LABELS[s.slice(6)] || s.slice(6)) : s).join(", ");
}

function initProfiles() {
    const el = $("#profileList");
    if (!el) return;
    let data = null;

    async function load() {
        try { data = await api("/api/profiles"); } catch (err) {
            el.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
            return;
        }
        el.innerHTML = data.profiles.map(p => `
            <div class="profile-row">
                <div class="profile-main">
                    <div class="row-title">${esc(p.label)}
                        ${p.customized ? '<span class="chip low nocap" style="margin-left:6px">edited</span>' : ""}
                        ${p.devices ? `<span class="chip neutral nocap" style="margin-left:6px">${p.devices} device${p.devices === 1 ? "" : "s"}</span>` : ""}</div>
                    <div class="row-sub">${esc(p.description)}</div>
                    <div class="profile-facts">
                        ${!p.filtering ? '<span class="fact"><b>Filtering</b> off</span>' : ""}
                        ${p.safe_search ? '<span class="fact"><b>Safe search</b> on</span>' : ""}
                        ${p.blocked_services.length ? `<span class="fact"><b>Always blocked</b> ${esc(servicesSummary(p.blocked_services))}${p.blocked_count != null ? ` <span class="dim">(${p.blocked_count} services)</span>` : ""}</span>` : ""}
                        ${p.schedule ? `<span class="fact"><b>${esc(p.schedule.start)}–${esc(p.schedule.end)}</b> ${esc(servicesSummary(p.schedule.services))}
                            ${p.schedule_active ? '<span class="chip medium nocap" style="margin-left:4px">active now</span>' : ""}</span>` : ""}
                        ${p.native_trackers ? '<span class="fact"><b>Vendor telemetry</b> blocked</span>' : ""}
                    </div>
                </div>
                <div class="profile-actions">${p.editable ? `<button class="btn" data-profile-edit="${esc(p.key)}">Edit</button>
                    ${p.customized ? `<button class="btn ghost" data-profile-reset="${esc(p.key)}">Reset</button>` : ""}` : ""}</div>
            </div>`).join("");
    }

    function groupChecks(name, selected) {
        return `<div class="check-grid">${data.service_groups.map(g => `
            <label class="check-chip"><input type="checkbox" data-group-check="${name}" value="group:${esc(g.id)}"
                ${selected.includes("group:" + g.id) ? "checked" : ""}>
                <span>${esc(GROUP_LABELS[g.id] || g.id)} <span class="dim">${g.services.length}</span></span></label>`).join("")}</div>`;
    }

    el.addEventListener("click", async (e) => {
        const r = e.target.closest("[data-profile-reset]");
        if (r) {
            try { await api(`/api/profiles/${r.dataset.profileReset}/reset`, {}); toast("Profile reset", "", "ok"); load(); }
            catch (err) { toast("Could not reset", err.message, "high"); }
            return;
        }
        const b = e.target.closest("[data-profile-edit]");
        if (!b) return;
        const p = data.profiles.find(x => x.key === b.dataset.profileEdit);
        const alwaysGroups = p.blocked_services.filter(s => s.startsWith("group:"));
        const alwaysSingles = p.blocked_services.filter(s => !s.startsWith("group:"));
        const sched = p.schedule || { start: "21:00", end: "07:00", services: [] };
        const v = await spDialog({
            title: `Edit ${p.label}`, confirm: "Save and apply",
            description: `Applies to ${p.devices} device${p.devices === 1 ? "" : "s"} on this profile within seconds.`,
            fields: [
                { name: "safe_search", label: "Enforce safe search on every search engine and YouTube", type: "checkbox", value: p.safe_search },
                { name: "always_html", type: "html", html: `<span class="field-label">Always blocked - categories</span>${groupChecks("always", alwaysGroups)}` },
                { name: "singles", label: "Always blocked - individual services", type: "text", value: alwaysSingles.join(", "),
                  placeholder: "tiktok, snapchat", hint: "DNS-filter service ids, comma-separated." },
                { name: "sched_on", label: "Also block some services during a daily window", type: "checkbox", value: !!p.schedule },
                { name: "sched_html", type: "html", html: `<div class="toolbar" style="margin-bottom:8px">
                    <label class="field inline"><span class="field-label">From</span><input class="input" type="time" id="schedStart" value="${esc(sched.start)}" style="min-width:0;width:120px"></label>
                    <label class="field inline"><span class="field-label">Until</span><input class="input" type="time" id="schedEnd" value="${esc(sched.end)}" style="min-width:0;width:120px"></label>
                    <span class="note">A window like 21:00–07:00 runs overnight.</span></div>
                    <span class="field-label">Blocked during the window</span>${groupChecks("sched", sched.services)}` },
                reasonField(""),
            ],
            collect: (form) => {
                const always = $$('[data-group-check="always"]:checked', form).map(x => x.value);
                const singles = form.elements.singles.value.split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
                const out = { blocked_services: always.concat(singles) };
                if (form.elements.sched_on.checked) {
                    const services = $$('[data-group-check="sched"]:checked', form).map(x => x.value);
                    if (!services.length) return { error: "Pick at least one category to block during the window." };
                    out.schedule = { start: $("#schedStart", form).value, end: $("#schedEnd", form).value, services };
                } else {
                    out.clear_schedule = true;
                }
                return out;
            },
        });
        if (!v) return;
        try {
            await api(`/api/profiles/${p.key}`, { safe_search: v.safe_search, blocked_services: v.blocked_services,
                schedule: v.schedule || null, clear_schedule: !!v.clear_schedule, reason: v.reason });
            toast("Profile saved", `${p.label} - applied to its devices.`, "ok");
            load();
        } catch (err) { toast("Not saved", err.message, "high"); }
    });

    load();
}

/* ----------------------------------------------- filtering: network pause */

function initNetworkPause() {
    const el = $("#networkPause");
    if (!el) return;

    async function load() {
        try {
            const d = await api("/api/filtering/pause");
            el.innerHTML = d.paused
                ? `<span class="chip medium nocap dot">Paused · ${fmtLeft(d.remaining_s)} left</span>
                   <button class="btn" data-net-resume>Resume now</button>`
                : menuHtml(`<svg class="icon" width="13" height="13"><use href="#i-pause"/></svg> Pause for everyone`,
                           PAUSES.map(x => ({ value: x.minutes, label: x.label })), "net-pause", "");
        } catch (err) { el.innerHTML = ""; }
    }

    el.addEventListener("click", async (e) => {
        const p = e.target.closest("[data-net-pause]");
        if (p) {
            const minutes = Number(p.dataset.netPause);
            const v = await spDialog({
                title: `Pause filtering for every device for ${fmtLeft(minutes * 60)}?`, tone: "danger", icon: "i-pause",
                confirm: "Pause filtering",
                description: "Ads, trackers and known-malicious domains resolve normally on the whole network until it resumes. " +
                    "The DNS filter resumes on its own when the time is up.",
                fields: [reasonField("")],
            });
            if (!v) return;
            try {
                await api("/api/filtering/pause", { minutes, reason: v.reason });
                toast("Filtering paused", `Resumes automatically in ${fmtLeft(minutes * 60)}.`, "medium");
                load();
            } catch (err) { toast("Could not pause", err.message, "high"); }
            return;
        }
        if (e.target.closest("[data-net-resume]")) {
            try { await api("/api/filtering/resume", {}); toast("Filtering resumed", "", "ok"); load(); }
            catch (err) { toast("Could not resume", err.message, "high"); }
        }
    });
    load();
    setInterval(() => { if (!document.hidden) load(); }, 20000);
}

/* ---------------------------------------------- settings: notifications */

const CHANNEL_META = {
    ntfy: { label: "ntfy", summary: c => `${c.server}/${c.topic}` },
    telegram: { label: "Telegram", summary: c => `chat ${c.chat_id}` },
    email: { label: "Email", summary: c => `${c.recipient} via ${c.host}:${c.port}` },
    webhook: { label: "Webhook", summary: c => c.url + (c.secret ? " · signed" : "") },
};

/* Renders a group of settings as editable rows - numbers get an input and
   Save, true/false settings get an on/off button. Used for delivery rules;
   the detection thresholds list keeps its own original renderer. */
function renderSettingGroup(el, settingsMap, group, onSaved) {
    const rows = Object.entries(settingsMap).filter(([, s]) => s.group === group && !s.dedicated);
    el.innerHTML = rows.map(([key, s]) => `
        <div class="filter-row setting-row" data-key="${esc(key)}">
            <div class="setting-label"><div class="row-title">${esc(s.label)}</div>
                <div class="row-sub" title="${esc(s.help)}">${esc(s.help)}</div></div>
            ${s.type === "bool"
                ? `<button class="btn ${s.value ? "on" : ""}" data-bool-toggle="${s.value ? 0 : 1}">${s.value ? "On" : "Off"}</button>`
                : `<input class="input" type="number" step="1" value="${s.value}" min="${s.min ?? ""}" max="${s.max ?? ""}" data-setting-input aria-label="${esc(s.label)}" style="width:90px;min-width:0">
                   <button class="btn" data-group-save>Save</button>`}
        </div>`).join("");
    el.onclick = async (e) => {
        const row = e.target.closest(".setting-row");
        if (!row) return;
        let value;
        if (e.target.closest("[data-bool-toggle]")) value = e.target.closest("[data-bool-toggle]").dataset.boolToggle === "1";
        else if (e.target.closest("[data-group-save]")) value = parseInt(row.querySelector("[data-setting-input]").value, 10);
        else return;
        if (typeof value === "number" && Number.isNaN(value)) { toast("Enter a whole number", "", "high"); return; }
        const v = await spDialog({ title: `Change ${settingsMap[row.dataset.key].label.toLowerCase()}`, fields: [reasonField("")] });
        if (!v) return;
        try {
            await api(`/api/settings/${row.dataset.key}`, { value, reason: v.reason });
            toast("Saved", settingsMap[row.dataset.key].label, "ok");
            onSaved();
        } catch (err) { toast("Could not save", err.message, "high"); }
    };
}

function initNotifications() {
    const el = $("#settingsChannels");
    if (!el) return;

    async function loadChannels() {
        let d;
        try { d = await api("/api/notifications/channels"); } catch (err) {
            el.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
            return;
        }
        if (!d.channels.length) {
            el.innerHTML = `<div class="empty"><span class="empty-icon"><svg class="icon" width="18" height="18"><use href="#i-send"/></svg></span>
                No channels yet - incidents are only visible here and in the gateway's journal.</div>`;
            return;
        }
        el.innerHTML = d.channels.map(c => `
            <div class="filter-row channel-row" data-key="${c.id}" data-channel="${c.id}">
                <span class="chip neutral nocap">${esc(CHANNEL_META[c.kind].label)}</span>
                <div class="grow"><div class="row-title">${esc(c.name)}${c.config.include_details ? ' <span class="chip low nocap" style="margin-left:4px">details</span>' : ""}</div>
                    <div class="row-sub mono">${esc(CHANNEL_META[c.kind].summary(c.config))}</div>
                    ${c.last_error && (!c.last_sent_at || c.last_error_at > c.last_sent_at)
                        ? `<div class="row-sub text-high" title="${esc(c.last_error)}">Last attempt failed: ${esc(c.last_error)}</div>`
                        : c.last_sent_at ? `<div class="row-sub">Last sent ${esc(new Date(c.last_sent_at * 1000).toLocaleString())}</div>` : ""}</div>
                <select class="input" data-channel-sev aria-label="Minimum severity" style="min-width:0;width:auto">
                    ${["low", "medium", "high"].map(s => `<option value="${s}" ${c.min_severity === s ? "selected" : ""}>${s} and above</option>`).join("")}</select>
                <button class="btn ${c.enabled ? "on" : ""}" data-channel-toggle>${c.enabled ? "On" : "Off"}</button>
                <button class="btn" data-channel-test>Send test</button>
                <button class="btn ghost" data-channel-remove title="Remove channel">Remove</button>
            </div>`).join("");
        markNewRows(el, ".channel-row", false);
    }

    async function loadRules() {
        const d = await api("/api/settings");
        renderSettingGroup($("#settingsNotifyRules"), d.settings, "notifications", () => { loadRules(); loadRecent(); });
    }

    async function loadRecent() {
        const box = $("#settingsNotifyRecent");
        try {
            const d = await api("/api/notifications/recent");
            $("#quietNowChip").hidden = !d.quiet_now;
            const tone = { sent: "ok", failed: "high", held: "medium", digested: "neutral", skipped: "neutral" };
            box.innerHTML = d.notifications.length ? d.notifications.map(n => `
                <div class="audit-row compact" data-key="${n.id}"><span class="mono dim">${esc(n.age)}</span>
                    <span class="chip ${tone[n.status] || "neutral"} nocap">${esc(n.status)}</span>
                    <span class="desc" title="${esc(n.detail || n.title || "")}">${n.incident_id
                        ? `<a class="link" href="/incidents/${n.incident_id}">${esc(n.title || "")}</a>` : esc(n.title || "")}</span>
                    <span class="detail">${esc(n.channel)}</span></div>`).join("")
                : `<div class="empty">Nothing sent yet</div>`;
            markNewRows(box, ".audit-row", true);
        } catch (err) { box.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
    }

    el.addEventListener("change", async (e) => {
        const sel = e.target.closest("[data-channel-sev]");
        if (!sel) return;
        const id = sel.closest("[data-channel]").dataset.channel;
        try { await api(`/api/notifications/channels/${id}`, { min_severity: sel.value }); toast("Saved", "", "ok"); }
        catch (err) { toast("Could not save", err.message, "high"); }
    });

    el.addEventListener("click", async (e) => {
        const row = e.target.closest("[data-channel]");
        if (!row) return;
        const id = row.dataset.channel;
        if (e.target.closest("[data-channel-toggle]")) {
            const on = !e.target.closest("[data-channel-toggle]").classList.contains("on");
            try { await api(`/api/notifications/channels/${id}`, { enabled: on }); loadChannels(); }
            catch (err) { toast("Could not change", err.message, "high"); }
        } else if (e.target.closest("[data-channel-test]")) {
            const btn = e.target.closest("[data-channel-test]");
            btn.disabled = true;
            try { await api(`/api/notifications/channels/${id}/test`, {}); toast("Test sent", "Check the channel for it.", "ok"); }
            catch (err) { toast("Test failed", err.message, "high"); }
            finally { btn.disabled = false; loadChannels(); }
        } else if (e.target.closest("[data-channel-remove]")) {
            const v = await spDialog({ title: "Remove this channel?", tone: "danger", confirm: "Remove",
                description: "Its saved settings and secrets are deleted from the gateway.", fields: [] });
            if (!v) return;
            try { await api(`/api/notifications/channels/${id}/remove`, {}); toast("Channel removed", "", "ok"); loadChannels(); }
            catch (err) { toast("Could not remove", err.message, "high"); }
        }
    });

    $("#channelAdd").addEventListener("click", async () => {
        const kinds = ["ntfy", "telegram", "email", "webhook"];
        const when = (k) => ({ name: "kind", in: [k] });
        const v = await spDialog({
            title: "Add a notification channel", icon: "i-send", confirm: "Add channel",
            description: "Send a test from the list afterwards to confirm it works.",
            fields: [
                { name: "kind", label: "Type", type: "select", value: "ntfy", required: true,
                  options: kinds.map(k => ({ value: k, label: CHANNEL_META[k].label })) },
                { name: "name", label: "Name", type: "text", required: true, placeholder: "My phone" },
                { name: "server", label: "ntfy server", type: "text", value: "https://ntfy.sh", required: true, showWhen: when("ntfy"),
                  hint: "Public ntfy.sh or your own server." },
                { name: "topic", label: "Topic", type: "text", required: true, showWhen: when("ntfy"),
                  hint: "On a public server, anyone who knows the topic can read it - use a long random one." },
                { name: "token", label: "Access token", type: "password", showWhen: when("ntfy") },
                { name: "bot_token", label: "Bot token", type: "password", required: true, showWhen: when("telegram"),
                  hint: "From @BotFather, like 123456789:AA..." },
                { name: "chat_id", label: "Chat id", type: "text", required: true, showWhen: when("telegram") },
                { name: "host", label: "SMTP server", type: "text", required: true, showWhen: when("email"), placeholder: "smtp.gmail.com" },
                { name: "port", label: "Port", type: "number", value: 587, required: true, showWhen: when("email") },
                { name: "security", label: "Security", type: "select", value: "starttls", required: true, showWhen: when("email"),
                  options: [{ value: "starttls", label: "STARTTLS (port 587)" }, { value: "ssl", label: "SSL/TLS (port 465)" }, { value: "none", label: "None" }] },
                { name: "username", label: "Username", type: "text", showWhen: when("email") },
                { name: "password", label: "Password", type: "password", showWhen: when("email"), hint: "For Gmail, an app password." },
                { name: "sender", label: "From address", type: "email", required: true, showWhen: when("email") },
                { name: "recipient", label: "To address", type: "email", required: true, showWhen: when("email") },
                { name: "url", label: "Webhook URL", type: "url", required: true, showWhen: when("webhook") },
                { name: "secret", label: "Signing secret", type: "password", showWhen: when("webhook"),
                  hint: "If set, each request carries X-SecurePi-Signature: sha256=HMAC of the body." },
                { name: "min_severity", label: "Send incidents of at least", type: "select", value: "medium", required: true,
                  options: [{ value: "low", label: "Low" }, { value: "medium", label: "Medium" }, { value: "high", label: "High" }] },
                { name: "include_details", label: "Include incident details (can contain domains and IP addresses)", type: "checkbox", value: false },
            ],
        });
        if (!v) return;
        const { kind, name, min_severity, ...config } = v;
        try {
            await api("/api/notifications/channels", { kind, name, min_severity, config });
            toast("Channel added", "Use Send test to check it.", "ok");
            loadChannels();
        } catch (err) { toast("Channel not added", err.message, "high"); }
    });

    loadChannels();
    loadRules();
    loadRecent();
    setInterval(() => { if (!document.hidden) loadRecent(); }, 20000);
}

function initRetention() {
    const el = $("#settingsRetention");
    if (!el) return;
    api("/api/settings/retention").then(d => {
        $("#settingsRetentionLast").textContent = d.last_run ? `last run ${d.last_run}` : "not run yet";
        el.innerHTML = `<table class="compact"><tbody>${d.rows.map(r => `
            <tr><td class="truncate">${esc(r.what)}</td>
                <td class="num">${r.days == null ? '<span class="dim">kept forever</span>' : `${r.days} days`}</td></tr>`).join("")}</tbody></table>`;
    }).catch(err => { el.innerHTML = `<div class="empty">${esc(err.message)}</div>`; });
}

function refresh() {
    const page = document.body.dataset.page;
    const fn = { dashboard: refreshDashboard, devices: refreshDevices, incidents: refreshIncidents,
                 response: refreshResponse }[page];
    if (fn) fn().catch(err => console.error("refresh failed", err));
}

document.addEventListener("DOMContentLoaded", () => {
    initSidebar();
    initSubnav();
    updateThemeToggle();
    const themeBtn = $("#themeToggle");
    if (themeBtn) themeBtn.addEventListener("click", toggleTheme);
    initDeviceRename();
    initDeviceBaseline();
    initDeviceFingerprint();
    initDeviceActivity();
    initDeviceTrust();
    initDeviceFiltering();
    initDeviceQuarantine();
    initDevicePolicies();
    initDeviceDpi();
    initDeviceBlocked();
    initDevicePrivacy();
    initDeviceProfiles();
    initFiltering();
    initFilteringAnalytics();
    initResolverQuality();
    initDpiOnboarding();
    initDpiRules();
    initSettings();
    initHunt();
    initWeeklyReport();
    initIncidentNotes();
    initIncidentBlockDomain();
    initIncidentResponse();
    initResponsePage();
    initProfiles();
    initNetworkPause();
    initNotifications();
    initRetention();

    // Global row-action delegate: works across incidents list + detail page.
    // Registered on the capture phase because row markup calls
    // event.stopPropagation() in the bubble phase (to stop a row's own
    // onclick from navigating when its action menu is clicked) - a bubble
    // listener on document would never see these clicks at all.
    document.addEventListener("click", (e) => {
        const toggle = e.target.closest("[data-toggle-menu]");
        if (toggle) {
            e.stopPropagation();
            const menu = toggle.closest(".row-menu");
            $$(".row-menu.open").forEach(m => { if (m !== menu) m.classList.remove("open"); });
            if (menu) menu.classList.toggle("open");
            return;
        }
        const setBtn = e.target.closest("[data-set-status]");
        if (setBtn) {
            e.stopPropagation();
            const menu = setBtn.closest(".row-menu");
            if (menu) menu.classList.remove("open");
            updateIncidentStatus(setBtn.dataset.incidentId, setBtn.dataset.setStatus);
            return;
        }
        $$(".row-menu.open").forEach(m => m.classList.remove("open"));
    }, true);

    // Notification bell
    const notifBtn = $("#notifBtn");
    const notifPanel = $("#notifPanel");
    if (notifBtn && notifPanel) {
        notifBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            notifPanel.hidden = !notifPanel.hidden;
        });
        document.addEventListener("click", (e) => {
            if (!notifPanel.hidden && !notifPanel.contains(e.target) && e.target !== notifBtn) {
                notifPanel.hidden = true;
            }
        });
    }

    // Command palette
    const cmdkTrigger = $("#cmdkTrigger");
    const cmdkOverlay = $("#cmdkOverlay");
    const cmdkInput = $("#cmdkInput");
    const cmdkResults = $("#cmdkResults");
    if (cmdkTrigger) cmdkTrigger.addEventListener("click", cmdkOpen);
    if (cmdkOverlay) cmdkOverlay.addEventListener("click", (e) => { if (e.target === cmdkOverlay) cmdkClose(); });
    if (cmdkInput) {
        cmdkInput.addEventListener("input", () => cmdkFilter(cmdkInput.value));
        cmdkInput.addEventListener("keydown", (e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); cmdkActive = Math.min(cmdkActive + 1, cmdkItems.length - 1); cmdkHighlight(); }
            else if (e.key === "ArrowUp") { e.preventDefault(); cmdkActive = Math.max(cmdkActive - 1, 0); cmdkHighlight(); }
            else if (e.key === "Enter") { e.preventDefault(); cmdkGo(cmdkActive); }
        });
    }
    if (cmdkResults) cmdkResults.addEventListener("click", (e) => {
        const item = e.target.closest(".cmdk-item");
        if (item) cmdkGo(Number(item.dataset.idx));
    });
    document.addEventListener("keydown", (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            cmdkOpen();
        } else if (e.key === "Escape") {
            cmdkClose();
        }
    });

    // Range selector (dashboard)
    $$("#rangeSel button").forEach(b => {
        b.classList.toggle("active", b.dataset.range === SP.range);
        b.addEventListener("click", () => {
            SP.range = b.dataset.range;
            localStorage.setItem("sp.range", SP.range);
            $$("#rangeSel button").forEach(x => x.classList.toggle("active", x === b));
            refresh();
        });
    });

    const lt = $("#liveToggle");
    if (lt) lt.addEventListener("click", () => setLive(!SP.live));

    const ds = $("#deviceSearch");
    if (ds) ds.addEventListener("input", renderDevices);
    const ht = $("#hideTest");
    if (ht) ht.addEventListener("click", () => { ht.classList.toggle("on"); renderDevices(); });

    $$("th.sortable").forEach(th => th.addEventListener("click", () => {
        const k = th.dataset.key;
        deviceSort.dir = deviceSort.key === k ? -deviceSort.dir : -1;
        deviceSort.key = k;
        $$("th.sortable .arrow").forEach(a => a.textContent = "");
        const arrow = $(".arrow", th);
        if (arrow) arrow.textContent = deviceSort.dir === -1 ? "▼" : "▲";
        renderDevices();
    }));

    const devExport = $("#devicesExport");
    if (devExport) devExport.addEventListener("click", () => exportCsv("devices.csv", window.__devices || [], [
        { key: "name", label: "Device" }, { key: "ip", label: "IP" }, { key: "hostname", label: "Hostname" },
        { key: "down_h", label: "Down" }, { key: "up_h", label: "Up" }, { key: "dns", label: "DNS Queries" },
        { key: "blocked", label: "Blocked" }, { key: "incidents", label: "Incidents" }, { key: "age", label: "Last Seen" },
    ]));

    const is = $("#incidentSearch");
    if (is) is.addEventListener("input", renderIncidents);
    $$("#sevFilter button").forEach(b => b.addEventListener("click", () => {
        $$("#sevFilter button").forEach(x => x.classList.toggle("active", x === b));
        incidentFilter.severity = b.dataset.sev || "";
        refreshIncidents("user");
    }));
    $$("#statusFilter button").forEach(b => b.addEventListener("click", () => {
        $$("#statusFilter button").forEach(x => x.classList.toggle("active", x === b));
        incidentFilter.status = b.dataset.status || "";
        refreshIncidents("user");
    }));

    const incExport = $("#incidentsExport");
    if (incExport) incExport.addEventListener("click", () => exportCsv("incidents.csv", window.__incidents || [], [
        { key: "severity", label: "Severity" }, { key: "title", label: "Title" }, { key: "signal_type", label: "Signal" },
        { key: "device", label: "Device" }, { key: "status", label: "Status" },
        { key: "evidence_count", label: "Evidence" }, { key: "age", label: "Last Seen" },
    ]));

    initSegIndicators();
    initTopbarElevation();

    setLive(SP.live);
    tick();
});
