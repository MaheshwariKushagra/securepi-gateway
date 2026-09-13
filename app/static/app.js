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

/* ------------------------------------------------------------- sidebar */

function initSidebar() {
    const shell = $("#shell");
    if (!shell) return;
    const collapsed = localStorage.getItem("sp.sidebarCollapsed") === "1";
    shell.classList.toggle("collapsed", collapsed);

    const setCollapsed = (v) => {
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
        if (badge) { badge.textContent = openCount; badge.hidden = openCount === 0; }
        const navBadge = $("#navIncidentBadge");
        if (navBadge) { navBadge.textContent = openCount; navBadge.hidden = openCount === 0; }

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
        el.innerHTML = `<div class="empty" style="padding:22px 14px">No open incidents. The network is quiet.</div>`;
        return;
    }
    el.innerHTML = items.map(i => `
        <a class="notif-row" href="/incidents/${i.id}">
            <span class="chip ${esc(i.severity)} dot" style="margin-top:3px"></span>
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
                <div class="health-item">
                    <span class="label"><span class="dot ${i.healthy ? "" : "bad"}"></span>${esc(i.label)}</span>
                    <span class="value">${esc(i.value)}</span>
                </div>`).join("");
        }
    } catch (err) { console.error("system refresh failed", err); }
}

/* --------------------------------------------------------------- charts */

const CHART_GRID = "rgba(34,43,60,.7)";
const CHART_TEXT = "#5a6679";

function baseChartOpts(extra) {
    return Object.assign({
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        interaction: { mode: "index", intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: "#161d2b",
                borderColor: "#2e3a50",
                borderWidth: 1,
                titleColor: "#e6ecf5",
                bodyColor: "#8d99ad",
                padding: 10,
                cornerRadius: 6,
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

    $("#lastUpdated").textContent = d.generated_at;

    renderSparkline("sparkEvents", "sparkEvents", d.series.events, "#4f9cf9");
    renderSparkline("sparkBlocked", "sparkBlocked", d.series.blocked, "#f2545b");
    const traffic = d.series.down_kbps.map((v, i) => v + (d.series.up_kbps[i] || 0));
    renderSparkline("sparkTraffic", "sparkTraffic", traffic, "#7b5cf0");

    // Throughput
    const tctx = document.getElementById("throughputChart").getContext("2d");
    upsertChart("throughput", "throughputChart", {
        type: "line",
        data: {
            labels: d.series.labels,
            datasets: [
                { label: "Download", data: d.series.down_kbps, borderColor: "#4f9cf9",
                  backgroundColor: gradient(tctx, "#4f9cf9"), fill: true, tension: .35,
                  pointRadius: 0, borderWidth: 2 },
                { label: "Upload", data: d.series.up_kbps, borderColor: "#7b5cf0",
                  backgroundColor: gradient(tctx, "#7b5cf0"), fill: true, tension: .35,
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
                { label: "Allowed", data: d.series.allowed, backgroundColor: "#2e3a50",
                  borderRadius: 2, stack: "dns" },
                { label: "Blocked", data: d.series.blocked, backgroundColor: "#f2545b",
                  borderRadius: 2, stack: "dns" },
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
                backgroundColor: ["#f2545b", "#f5a524", "#4f9cf9"],
                borderColor: "#111722", borderWidth: 3, hoverOffset: 6,
            }],
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: "66%",
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
        tone: s.signal === "port_scan" || s.signal === "brute_force" ? "high" : "",
    })), "No detections yet");

    renderBarList("#protocolMix", d.protocols.map(p => ({
        label: (p.name || "unknown").toUpperCase(), value: p.count, weight: p.count,
    })), "No protocol data in this window");

    renderBarList("#eventTypes", d.event_types.map(e => ({
        label: e.name.replace(/_/g, " "), value: e.count, weight: e.count,
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
            ? `style="background:rgba(79,156,249,${(0.14 + pct * 0.75).toFixed(2)})"`
            : "";
        return `<div class="heatmap-cell" ${style} title="${v.toLocaleString()} events"></div>`;
    }).join("") + `</div>`).join("");
    if (daysEl) daysEl.innerHTML = days.map(d => `<span>${esc(d)}</span>`).join("");
}

function renderBarList(sel, items, emptyMsg) {
    const el = $(sel);
    if (!el) return;
    if (!items.length) { el.innerHTML = `<div class="empty">${esc(emptyMsg)}</div>`; return; }
    const max = Math.max(...items.map(i => i.weight)) || 1;
    el.innerHTML = `<div class="barlist">` + items.map(i => {
        const pct = Math.max(2, (i.weight / max) * 100);
        const label = i.href
            ? `<a class="link barlabel" href="${i.href}">${esc(i.label)}</a>`
            : `<span class="barlabel" title="${esc(i.label)}">${esc(i.label)}</span>`;
        return `<div class="barrow">
            ${label}
            <span class="num dim">${esc(i.value)}</span>
            <span class="bartrack"><span class="barfill ${i.tone || ""}" style="width:${pct}%"></span></span>
        </div>`;
    }).join("") + `</div>`;
}

function renderFeed(events) {
    const el = $("#eventFeed");
    if (!el) return;
    if (!events.length) { el.innerHTML = `<div class="empty">No events yet</div>`; return; }
    el.innerHTML = events.map(e => `
        <div class="feed-row">
            <span class="mono dim">${esc(e.time)}</span>
            <span class="type-tag ${esc(e.type)}">${esc(e.type.replace("dns_query", "dns"))}</span>
            <span class="truncate mono" title="${esc(e.detail)}">${esc(e.detail)}</span>
            <span class="dim" style="font-size:11px">${e.blocked ? '<span class="chip high">blocked</span>' : esc(e.device || e.src || "")}</span>
        </div>`).join("");
}

function renderActiveIncidents(items) {
    const el = $("#activeIncidents");
    if (!el) return;
    if (!items.length) {
        el.innerHTML = `<div class="empty"><span class="empty-icon">✓</span>No open incidents. The network is quiet.</div>`;
        return;
    }
    el.innerHTML = `<table><tbody>` + items.map(i => `
        <tr class="clickable" onclick="location.href='/incidents/${i.id}'">
            <td style="width:1%"><span class="chip ${esc(i.severity)} dot">${esc(i.severity)}</span></td>
            <td><div>${esc(i.title)}</div>
                <div class="dim" style="font-size:11px">${esc(i.device || "—")} · ${esc(i.evidence_count)} events</div></td>
            <td class="num dim" style="width:1%; white-space:nowrap">${esc(i.age)} ago</td>
        </tr>`).join("") + `</tbody></table>`;
}

/* -------------------------------------------------------------- devices */

let deviceSort = { key: "down", dir: -1 };

async function refreshDevices() {
    const res = await fetch("/api/devices");
    const d = await res.json();
    window.__devices = d.devices;
    renderDevices();
    $("#lastUpdated").textContent = new Date().toLocaleTimeString();
}

function renderDevices() {
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
        <tr class="clickable" onclick="location.href='/devices/${d.id}'">
            <td><span class="status-dot ${d.online ? "online" : "offline"}"></span>${esc(d.name)}
                ${d.is_test ? '<span class="chip neutral" style="margin-left:6px">test</span>' : ""}</td>
            <td class="mono dim">${esc(d.ip || "—")}</td>
            <td>${d.randomized ? '<span class="chip neutral" title="Uses a randomized MAC">randomized</span>' : '<span class="dim">hardware</span>'}${d.mac_count > 1 ? `<span class="dim"> ·${d.mac_count} MACs</span>` : ""}</td>
            <td class="num">${esc(d.down_h)}</td>
            <td class="num">${esc(d.up_h)}</td>
            <td class="num">${d.dns.toLocaleString()}</td>
            <td class="num">${d.blocked ? `<span style="color:var(--high)">${d.blocked.toLocaleString()}</span>` : '<span class="dim">0</span>'}</td>
            <td class="num">${d.incidents ? `<span class="chip ${d.incidents_high ? "high" : "low"}">${d.incidents}</span>` : '<span class="dim">0</span>'}</td>
            <td class="num dim" style="white-space:nowrap">${esc(d.age)}</td>
        </tr>`).join("");
}

/* ------------------------------------------------------------ incidents */

let incidentFilter = { severity: "", status: "" };

function statusMenuHtml(current, id) {
    return STATUS_ORDER.filter(s => s !== current).map(s =>
        `<button data-set-status="${s}" data-incident-id="${id}">Mark ${esc(STATUS_META[s].label.toLowerCase())}</button>`
    ).join("");
}

async function refreshIncidents() {
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

    renderIncidents();
    $("#lastUpdated").textContent = new Date().toLocaleTimeString();
}

function renderIncidents() {
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
        <tr class="clickable" onclick="location.href='/incidents/${i.id}'">
            <td><span class="chip ${esc(i.severity)} dot">${esc(i.severity)}</span></td>
            <td><div>${esc(i.title)}</div>
                <div class="dim truncate" style="font-size:11px; max-width:460px">${esc(i.description || "")}</div></td>
            <td class="mono dim">${esc(i.signal_type.replace(/_/g, " "))}</td>
            <td>${i.device ? `<a class="link" href="/devices/${i.device_id}" onclick="event.stopPropagation()">${esc(i.device)}</a>` : '<span class="dim">—</span>'}</td>
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
                `<span class="chip ${d.confidence === "unknown" ? "neutral" : "ok"}">confidence: ${esc(d.confidence)}</span>`,
            ].join(" ");

            const evidenceRows = d.evidence.length
                ? d.evidence.map(e => `
                    <tr><td class="dim" style="width:1%; white-space:nowrap">${esc(e.source)}</td>
                        <td class="truncate">${esc(e.detail)}</td></tr>`).join("")
                : `<tr><td class="empty">No fingerprinting evidence yet</td></tr>`;

            const suggestion = d.suggested_profile ? `
                <div class="callout" style="margin-top:10px; display:flex; align-items:center; gap:10px">
                    <div style="flex:1">Looks like a ${esc(d.suggested_profile.label)} device - apply that native-tracker profile?</div>
                    <button class="btn" id="deviceFingerprintApplySuggestion">Apply</button>
                </div>` : "";

            wrap.innerHTML = `
                <div style="margin-bottom:8px">${chips}</div>
                <table><tbody>${evidenceRows}</tbody></table>
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
                    { label: "Download", data: d.down_kbps, borderColor: "#4f9cf9",
                      backgroundColor: gradient(ctx, "#4f9cf9"), fill: true, tension: .35,
                      pointRadius: 0, borderWidth: 2 },
                    { label: "Upload", data: d.up_kbps, borderColor: "#7b5cf0",
                      backgroundColor: gradient(ctx, "#7b5cf0"), fill: true, tension: .35,
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

function initDeviceFiltering() {
    const wrap = $("#deviceFiltering");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const btn = $("#deviceFilterToggle");

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering`);
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            btn.textContent = data.filtering_enabled ? "On" : "Off";
            btn.classList.toggle("on", data.filtering_enabled);
            btn.dataset.enabled = data.filtering_enabled ? "1" : "0";
        } catch (err) {
            btn.textContent = "Unavailable";
        }
    }

    btn.addEventListener("click", async () => {
        const enabled = btn.dataset.enabled !== "1";
        try {
            const res = await fetch(`/api/devices/${deviceId}/filtering`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled }),
            });
            if (!res.ok) throw new Error("request failed");
            toast("Filtering updated", enabled ? "Enabled for this device" : "Disabled for this device", "ok");
            load();
        } catch (err) {
            toast("Update failed", "Could not reach AdGuard Home.", "high");
        }
    });

    load();
}

function initDeviceQuarantine() {
    const wrap = $("#deviceQuarantine");
    if (!wrap) return;
    const deviceId = wrap.dataset.deviceId;
    const btn = $("#deviceQuarantineToggle");

    async function load() {
        try {
            const res = await fetch(`/api/devices/${deviceId}/quarantine`);
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            btn.textContent = data.quarantined ? "Quarantined — click to release" : "Quarantine this device";
            btn.classList.toggle("danger", data.quarantined);
            btn.dataset.quarantined = data.quarantined ? "1" : "0";
        } catch (err) {
            btn.textContent = "Unavailable";
        }
    }

    btn.addEventListener("click", async () => {
        const quarantined = btn.dataset.quarantined !== "1";
        try {
            const res = await fetch(`/api/devices/${deviceId}/quarantine`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ quarantined }),
            });
            if (!res.ok) throw new Error("request failed");
            toast(quarantined ? "Device quarantined" : "Quarantine released",
                  quarantined ? "All network traffic from this device is now blocked at the gateway."
                              : "Network access has been restored.",
                  quarantined ? "high" : "ok");
            load();
        } catch (err) {
            toast("Update failed", "Could not reach the firewall.", "high");
        }
    });

    load();
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
            btn.textContent = data.enrolled ? "Enrolled — click to unenroll" : "Enroll this device";
            btn.classList.toggle("on", data.enrolled);
            btn.dataset.enrolled = data.enrolled ? "1" : "0";
            expiryEl.textContent = (data.enrolled && data.expires_in_s != null)
                ? `— auto-unenrolls in ${humanizeSeconds(data.expires_in_s)}` : "";
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
            toast("Could not allow domain", "AdGuard Home did not accept the change.", "high");
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
                <div class="filter-row">
                    <span class="mono truncate" title="${esc(r.reason || '')}">${esc(r.domain)}</span>
                    <span class="dim" style="font-size:11px">${r.count}x · ${esc(r.age)} ago</span>
                    <button class="btn" data-allow-1h="${esc(r.domain)}" title="Allow for this device for 1 hour">Allow 1h</button>
                    <button class="btn" data-allow="${esc(r.domain)}" title="Allow for this device from now on">Allow</button>
                </div>`).join("");
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not reach AdGuard Home</div>`;
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
                toast("Check failed", "Could not reach AdGuard Home.", "high");
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
            return `<div class="dim" style="font-size:12px; margin-top:10px">No HTTPS-inspected traffic for this device</div>`;
        }
        return `
            <div style="display:flex; gap:20px; flex-wrap:wrap; margin-top:10px">
                <div><span class="dim">Decrypted</span> <b>${t2.decrypt}</b></div>
                <div><span class="dim">Passed through</span> <b>${t2.passthrough}</b></div>
                <div><span class="dim">Ads stripped from</span> <b>${t2.ads_stripped}</b></div>
                <div><span class="dim">Ad objects removed</span> <b>${t2.ads_removed}</b></div>
                <div><span class="dim">Pinning bypasses</span> <b>${t2.pin_bypass}</b></div>
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
                    <td class="num" style="color:${c.blocked ? "var(--high)" : "inherit"}">${c.blocked} blocked</td></tr>`).join("")
                : `<tr><td colspan="3" class="empty">No known tracker companies contacted</td></tr>`;
            wrap.innerHTML = `
                <div style="display:flex; gap:24px; flex-wrap:wrap; margin-bottom:10px">
                    <div><div class="dim" style="font-size:11px">Blocked</div>
                        <div style="font-size:20px; font-weight:600">${d.dns_blocked.toLocaleString()} / ${d.dns_total.toLocaleString()}
                            <span class="dim" style="font-size:13px">(${d.block_pct}%)</span></div></div>
                    <div><div class="dim" style="font-size:11px">Tracking companies</div>
                        <div style="font-size:20px; font-weight:600">${t.companies_blocked} blocked of ${t.companies_contacted}</div></div>
                    <div><div class="dim" style="font-size:11px">Estimated data saved</div>
                        <div style="font-size:20px; font-weight:600">${d.savings.estimated_bytes_h}</div></div>
                </div>
                <table><tbody>${topRows}</tbody></table>
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
            appliedEl.innerHTML = `<div class="dim" style="font-size:11px">No native-tracker profile applied</div>`;
            return;
        }
        appliedEl.innerHTML = applied.map(a => `
            <div class="filter-row">
                <span class="chip ok">${esc(a.label)}</span>
                <span class="dim">${a.rule_count} domain${a.rule_count === 1 ? "" : "s"} blocked</span>
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
            toast("Could not apply profile", "AdGuard Home did not accept the change.", "high");
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
            toast("Could not remove profile", "AdGuard Home did not accept the change.", "high");
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
                <div style="display:flex; gap:24px; flex-wrap:wrap; margin-bottom:10px">
                    <div><div class="dim" style="font-size:11px">Valid until</div>
                        <div style="font-size:14px">${esc(d.not_after || "unknown")}</div></div>
                    <div><div class="dim" style="font-size:11px">Fingerprint (SHA-256)</div>
                        <div class="mono truncate" style="font-size:11px; max-width:280px">${esc(d.fingerprint_sha256 || "unknown")}</div></div>
                    <div><a class="btn" href="${esc(d.download_url)}" target="_blank" rel="noopener">Download CA certificate</a></div>
                </div>
                <div class="dim" style="font-size:12px; line-height:1.6">
                    Install this certificate as a trusted root on a device before enrolling it, or its HTTPS
                    traffic will fail to load once enrolled: iOS/macOS - open the link, Install in Settings ›
                    General › VPN & Device Management, then enable full trust under Certificate Trust Settings.
                    Android - open the link, install as a "CA certificate" under Settings › Security ›
                    Encryption. Windows - open the .crt file, install into "Trusted Root Certification
                    Authorities" for the local machine.
                </div>
                <div class="callout" style="margin-top:10px">
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
                    <span class="chip ${t.cls}">${t.label}</span>
                    <span class="truncate">${e.device_id ? `<a href="/devices/${e.device_id}">${esc(e.name)}</a>` : esc(e.name)}</span>
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
                    <span class="dim mono truncate">${esc(p.sni)}</span>
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
                badge.className = "chip high";
                if (d.incident_id) badge.onclick = () => location.href = `/incidents/${d.incident_id}`;
            } else if (d.stale) {
                badge.textContent = d.last_checked ? `Privacy scope: stale (last checked ${d.age} ago)` : "Privacy scope: not yet checked";
                badge.className = "chip neutral";
            } else {
                badge.textContent = `Privacy scope verified ${d.age} ago`;
                badge.className = "chip ok";
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
                badge.className = "chip ok";
            } else {
                const first = d.affected[0];
                badge.textContent = `Effectiveness: check ${esc(first.name)}` +
                    (d.affected.length > 1 ? ` (+${d.affected.length - 1} more)` : "");
                badge.className = "chip high";
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
                <div style="display:flex; gap:24px; flex-wrap:wrap; margin-bottom:10px">
                    <div><div class="dim" style="font-size:11px">DNS latency (uncached), p50 / p95</div>
                        <div style="font-size:18px; font-weight:600">${lat.p50_ms ?? "—"} ms / ${lat.p95_ms ?? "—"} ms</div>
                        <div class="dim" style="font-size:11px">${lat.sample_size} samples, ${esc(d.range_label)}</div></div>
                    <div><div class="dim" style="font-size:11px">Upstream resolvers</div>
                        <div class="mono" style="font-size:13px">${cur.upstream_dns.map(esc).join(", ") || "none configured"}</div>
                        <div class="dim" style="font-size:11px">mode: ${esc(cur.upstream_mode)}</div></div>
                    <div><div class="dim" style="font-size:11px">Cache</div>
                        <div style="font-size:13px">${cur.cache_enabled ? "on" : "off"}${cur.cache_optimistic ? ", optimistic" : ""}</div></div>
                    <div><div class="dim" style="font-size:11px">DNSSEC</div>
                        <div style="font-size:13px">${cur.dnssec_enabled ? "on" : "off"}</div></div>
                </div>
                ${needsTuning ? `
                    <div class="callout" style="display:flex; align-items:center; gap:10px; flex-wrap:wrap">
                        <div style="flex:1">Recommended: optimistic caching, DNSSEC, and at least two independent
                            upstream resolvers queried in parallel. This changes DNS resolution for every device
                            on the network at once.</div>
                        <button class="btn" id="applyResolverTuning">Apply recommended tuning</button>
                    </div>` : `<div class="dim" style="font-size:12px">Resolver is already tuned.</div>`}`;
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
                    toast("Could not apply tuning", "AdGuard Home did not accept the change.", "high");
                }
            });
        } catch (err) {
            wrap.innerHTML = `<div class="empty">Could not reach AdGuard Home</div>`;
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
                <td class="num" style="color:var(--high)">${d.count}</td></tr>`).join("")}</tbody></table>`;
    }

    function renderTopClients(clients) {
        const wrap = $("#analyticsTopClients");
        if (!clients.length) { wrap.innerHTML = `<div class="empty">No blocked activity in this range</div>`; return; }
        wrap.innerHTML = `<table><tbody>${clients.map(c => `
            <tr class="clickable" onclick="location.href='/devices/${c.id}'">
                <td class="truncate">${esc(c.name)}</td>
                <td class="num dim">${c.blocked} / ${c.dns_total}</td>
                <td class="num" style="color:var(--high)">${c.block_pct}%</td>
            </tr>`).join("")}</tbody></table>`;
    }

    function renderTrackers(t) {
        $("#analyticsTrackerCount").textContent = `${t.companies_blocked} blocked of ${t.companies_contacted} contacted`;
        const wrap = $("#analyticsTrackers");
        if (!t.top.length) { wrap.innerHTML = `<div class="empty">No known tracker companies contacted in this range</div>`; return; }
        wrap.innerHTML = `<table><tbody>${t.top.map(c => `
            <tr><td class="truncate">${esc(c.company)}</td>
                <td class="num dim">${c.contacted} contacted</td>
                <td class="num" style="color:${c.blocked ? "var(--high)" : "inherit"}">${c.blocked} blocked</td></tr>`).join("")}</tbody></table>`;
    }

    function renderTier2(t2) {
        const wrap = $("#analyticsTier2");
        if (!t2.active) {
            wrap.innerHTML = `<div class="empty">No HTTPS-inspected traffic in this range - no device is enrolled, or none has browsed since.</div>`;
            return;
        }
        wrap.innerHTML = `
            <div style="display:flex; gap:20px; flex-wrap:wrap">
                <div><span class="dim">Decrypted</span> <b>${t2.decrypt}</b></div>
                <div><span class="dim">Passed through</span> <b>${t2.passthrough}</b></div>
                <div><span class="dim">Ads stripped from</span> <b>${t2.ads_stripped}</b> <span class="dim">responses</span></div>
                <div><span class="dim">Blocked paths</span> <b>${t2.path_blocked}</b></div>
                <div><span class="dim">Ad objects removed</span> <b>${t2.ads_removed}</b></div>
                <div><span class="dim">TLS handshake failures</span> <b>${t2.tls_failed}</b></div>
                <div><span class="dim">Pinning bypasses</span> <b>${t2.pin_bypass}</b></div>
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
                        { label: "Block %", data: d.series.block_pct, borderColor: "#f2545b",
                          backgroundColor: "rgba(242,84,91,.12)", fill: true, tension: .35,
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
        const callout = anyStale ? `<div class="callout" style="margin-bottom:8px">
            One or more blocklists haven't synced in over ${LIST_STALE_AFTER_H}h - check their source URL.</div>` : "";
        listsEl.innerHTML = callout + filters.map(f => {
            const h = healthByUrl[f.url];
            const badges = h ? `
                <span class="dim" title="share of all blocks we've matched back to a list">${h.share_pct}% of blocks</span>
                <span class="${h.stale ? "chip high" : "dim"}" title="${h.age_h != null ? h.age_h + "h since last sync" : "sync age unknown"}">${h.age_h != null ? Math.round(h.age_h) + "h old" : "sync age unknown"}</span>
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
                <span class="chip ${r.action === "block" ? "high" : "ok"}">${r.action}</span>
                <span class="url truncate" title="${esc(r.rule)}">${esc(r.domain || r.rule)}</span>
                <button class="btn danger" data-rule-remove="${esc(r.rule)}">Remove</button>
            </div>`).join("");
    }

    async function loadStatus() {
        try {
            const res = await fetch("/api/filtering/status");
            if (!res.ok) throw new Error("request failed");
            const data = await res.json();
            renderRules(data.rules);
            masterBtn.textContent = data.enabled ? "Filtering: on" : "Filtering: off";
            masterBtn.classList.toggle("on", data.enabled);
            masterBtn.dataset.enabled = data.enabled ? "1" : "0";

            // Health (staleness + contribution) is a second, independent
            // fetch: it's allowed to fail (a fresh AdGuard with no
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
            listsEl.innerHTML = `<div class="empty">Could not reach AdGuard Home. Is it running?</div>`;
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
            } catch (err) { toast("Update failed", "Could not reach AdGuard Home.", "high"); }
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
            } catch (err) { toast("Remove failed", "Could not reach AdGuard Home.", "high"); }
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
        } catch (err) { toast("Remove failed", "Could not reach AdGuard Home.", "high"); }
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
        } catch (err) { toast("Update failed", "Could not reach AdGuard Home.", "high"); }
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
        } catch (err) { toast("Add failed", "Could not reach AdGuard Home.", "high"); }
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
        } catch (err) { toast("Add failed", "Could not reach AdGuard Home.", "high"); }
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
                <div class="filter-row">
                    <span class="chip ${r.blocked ? "high" : "ok"}">${r.blocked ? "Blocked" : "Allowed"}</span>
                    <span class="mono truncate">${esc(r.domain || domain)}</span>
                    <span class="dim">for ${esc(scope)}</span>
                </div>
                <div class="dim" style="font-size:12px; margin-top:6px; padding-left:2px">
                    ${esc(r.reason)}${r.rule ? ` — <span class="mono">${esc(r.rule)}</span>` : ""}
                    ${r.cname ? ` — via CNAME to <span class="mono">${esc(r.cname)}</span>` : ""}
                </div>`;
        } catch (err) {
            resultEl.innerHTML = `<div class="empty">Could not reach AdGuard Home</div>`;
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
                    <span class="dim" style="font-size:11px">${r.blocked ? '<span class="chip high">blocked</span>' : esc(r.device || "")}</span>
                </div>`).join("");
        } catch (err) {
            results.innerHTML = `<div class="empty">Search failed</div>`;
        }
    }
    $("#qlSearch").addEventListener("click", runQuerylogSearch);
    $("#qlDomain").addEventListener("keydown", (e) => { if (e.key === "Enter") runQuerylogSearch(); });

    loadStatus();
}

/* ------------------------------------------------------- command palette */

const CMDK_PAGES = [
    { label: "Dashboard", href: "/", icon: "i-grid" },
    { label: "Devices", href: "/devices", icon: "i-monitor" },
    { label: "Incidents", href: "/incidents", icon: "i-alert" },
    { label: "Filtering", href: "/filtering", icon: "i-filter" },
];

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
    if (el) location.href = el.dataset.href;
}

/* ----------------------------------------------------------------- boot */

function refresh() {
    const page = document.body.dataset.page;
    const fn = { dashboard: refreshDashboard, devices: refreshDevices, incidents: refreshIncidents }[page];
    if (fn) fn().catch(err => console.error("refresh failed", err));
}

document.addEventListener("DOMContentLoaded", () => {
    initSidebar();
    initDeviceRename();
    initDeviceBaseline();
    initDeviceFingerprint();
    initDeviceActivity();
    initDeviceFiltering();
    initDeviceQuarantine();
    initDeviceDpi();
    initDeviceBlocked();
    initDevicePrivacy();
    initDeviceProfiles();
    initFiltering();
    initFilteringAnalytics();
    initResolverQuality();
    initDpiOnboarding();
    initDpiRules();

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
        if (item) location.href = item.dataset.href;
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
        refreshIncidents();
    }));
    $$("#statusFilter button").forEach(b => b.addEventListener("click", () => {
        $$("#statusFilter button").forEach(x => x.classList.toggle("active", x === b));
        incidentFilter.status = b.dataset.status || "";
        refreshIncidents();
    }));

    const incExport = $("#incidentsExport");
    if (incExport) incExport.addEventListener("click", () => exportCsv("incidents.csv", window.__incidents || [], [
        { key: "severity", label: "Severity" }, { key: "title", label: "Title" }, { key: "signal_type", label: "Signal" },
        { key: "device", label: "Device" }, { key: "status", label: "Status" },
        { key: "evidence_count", label: "Evidence" }, { key: "age", label: "Last Seen" },
    ]));

    setLive(SP.live);
    tick();
});
