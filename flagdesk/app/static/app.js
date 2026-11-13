const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const state = { notifs: [], resources: [], notifTimer: null, firstNotif: true, user: null, cfg: {}, challenges: [], tab: "challenges", mode: "login", timers: [], current: null, failures: 0 };
let modal, toast;

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-FD": "1" }, credentials: "same-origin" };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 15000);
  init.signal = ctl.signal;
  let res;
  try { res = await fetch(path, init); } catch (e) { const err = new Error("Network problem. Retrying shortly."); err.status = 0; throw err; } finally { clearTimeout(t); }
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) {
    const err = new Error((data && (typeof data.detail === "string" ? data.detail : data.detail && data.detail[0] && data.detail[0].msg)) || "Request failed");
    err.status = res.status;
    throw err;
  }
  return data;
}

function notify(msg, kind = "success") {
  const el = $("#toast");
  el.className = `toast align-items-center border-0 text-bg-${kind}`;
  $("#toast-body").textContent = msg;
  toast.show();
}

function show(view) { $$("main > section").forEach((s) => (s.hidden = s.id !== `view-${view}`)); }
function clearTimers() { state.timers.forEach(clearTimeout); state.timers = []; }

function poll(fn, base) {
  const tick = async () => {
    const ok = await fn();
    state.failures = ok ? 0 : Math.min(state.failures + 1, 5);
    const delay = base * Math.pow(2, state.failures) * (0.8 + Math.random() * 0.4);
    state.timers.push(setTimeout(tick, delay));
  };
  tick();
}

function isOrganizer() { return state.user && state.user.role === "organizer"; }

function setTab(tab) {
  if (isOrganizer()) tab = "admin";
  else if (tab === "admin") tab = "challenges";
  state.tab = tab;
  clearTimers();
  $$("#tabs .nav-link").forEach((a) => a.classList.toggle("active", a.dataset.tab === tab));
  show(tab);
  if (tab === "challenges") loadChallenges();
  if (tab === "wordlists") loadWordlists();
  if (tab === "scoreboard") poll(loadBoard, 8000);
  if (tab === "admin") poll(loadAdmin, 10000);
}

function enterApp() {
  const org = isOrganizer();
  $("#tabs").hidden = false;
  $$("#tabs .nav-item").forEach((li) => (li.hidden = org ? li.id !== "admin-tab" : li.id === "admin-tab"));
  $("#userbox").hidden = false;
  $("#score-badge").hidden = org;
  $("#whoami").textContent = state.user.username;
  $("#open-shop").href = (state.cfg.shop_url || "") + "/api/sso/login";
  if (!org) refreshScore();
  startNotifs();
  setTab((location.hash || "#challenges").slice(1) || "challenges");
}

async function refreshScore() {
  try { const me = await api("/api/me"); state.user = { ...state.user, ...me }; $("#score-badge").textContent = `${me.score} pts`; } catch (e) {}
}

function leaveApp() {
  clearTimers();
  stopNotifs();
  state.user = null;
  $("#tabs").hidden = true;
  $("#userbox").hidden = true;
  show(location.hash === "#organizer" ? "organizer-login" : "auth");
}

async function loadChallenges() {
  try { state.challenges = await api("/api/challenges"); } catch (e) {
    if (e.status === 401) return leaveApp();
    return notify(e.message, "danger");
  }
  renderChallenges();
}

function renderChallenges() {
  const list = state.challenges;
  const solved = list.filter((c) => c.solved).length;
  $("#progress-label").textContent = `${solved} of ${list.length} solved`;
  $("#progress-bar").style.width = list.length ? `${(solved / list.length) * 100}%` : "0";
  $("#challenge-grid").innerHTML = list.map((c) => `
    <div class="col-md-6 col-lg-4"><div class="card chal ${c.solved ? "solved" : ""}" data-id="${esc(c.id)}"><div class="card-body">
      <div class="d-flex justify-content-between mb-2"><span class="mono small text-accent">${esc(c.id)}</span>${c.solved ? '<span class="badge text-bg-success"><i class="bi bi-check-lg"></i> Solved</span>' : `<span class="mono small text-secondary">${c.points} pts</span>`}</div>
      <h5 class="card-title">${esc(c.title)}</h5>
      <div class="d-flex justify-content-between align-items-center mt-3"><span class="badge text-bg-secondary">${esc(c.category)}</span><span class="small text-secondary"><i class="bi bi-people me-1"></i>${c.solve_count}</span></div>
    </div></div></div>`).join("");
}

function openChallenge(id) {
  const c = state.challenges.find((x) => x.id === id);
  if (!c) return;
  state.current = c;
  $("#m-id").textContent = c.id;
  $("#m-title").textContent = c.title;
  $("#m-cat").textContent = c.category;
  $("#m-points").textContent = `${c.points} pts`;
  $("#m-solves").textContent = `${c.solve_count} solves`;
  $("#m-desc").textContent = c.description;
  $("#m-flag").value = "";
  $("#m-flag").disabled = c.solved;
  $("#m-submit").disabled = c.solved;
  const r = $("#m-result");
  r.hidden = !c.solved;
  if (c.solved) { r.className = "alert alert-success mt-3 mb-0"; r.textContent = "You already solved this one."; }
  modal.show();
  setTimeout(() => $("#m-flag").focus(), 300);
}

const MESSAGES = { correct: "Correct! Points awarded.", incorrect: "That flag is not correct for you.", already_solved: "You already solved this challenge." };
let submitting = false;

async function submitFlag(ev) {
  ev.preventDefault();
  if (submitting) return;
  submitting = true;
  const c = state.current;
  const btn = $("#m-submit");
  const r = $("#m-result");
  btn.disabled = true;
  try {
    const res = await api(`/api/challenges/${encodeURIComponent(c.id)}/submit`, { method: "POST", body: { flag: $("#m-flag").value.trim() } });
    r.hidden = false;
    r.className = `alert mt-3 mb-0 alert-${res.status === "incorrect" ? "danger" : "success"}`;
    r.textContent = res.status === "correct" ? `Correct! +${res.points} points.` : MESSAGES[res.status] || res.status;
    if (res.status === "correct" || res.status === "already_solved") {
      c.solved = true;
      if (res.status === "correct") c.solve_count += 1;
      $("#m-flag").disabled = true;
      renderChallenges();
      refreshScore();
      submitting = false;
      return;
    }
  } catch (e) {
    r.hidden = false;
    r.className = "alert mt-3 mb-0 alert-warning";
    r.textContent = e.message;
  }
  submitting = false;
  btn.disabled = c.solved;
}

async function loadBoard() {
  try {
    const board = await api("/api/scoreboard");
    $("#board-body").innerHTML = board.rows.length ? board.rows.map((r) => `<tr class="${r.username === state.user.username ? "me" : ""}"><td class="mono">${r.rank}</td><td>${esc(r.username)}</td><td class="text-end mono">${r.solved}</td><td class="text-end mono">${r.score}</td></tr>`).join("") : '<tr><td colspan="4" class="text-center text-secondary py-4">No solves yet.</td></tr>';
    $("#board-count").textContent = `${board.participants} participants`;
    $("#board-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    return true;
  } catch (e) {
    if (e.status === 401) leaveApp();
    return false;
  }
}

async function loadAdmin() {
  try {
    const [sum, chals, users, subs, audit] = await Promise.all([api("/api/admin/stats"), api("/api/admin/challenges"), api("/api/admin/participants"), api("/api/admin/submissions"), api("/api/admin/audit")]);
    $("#admin-stats").innerHTML = [["Participants", sum.participants], ["Submissions", sum.submissions], ["Wrong", sum.wrong], ["Solves", sum.solves]].map(([k, v]) => `<div class="col-6 col-md-3"><div class="card"><div class="card-body"><div class="text-secondary small">${k}</div><div class="h3 mono mb-0">${v}</div></div></div></div>`).join("");
    if (!$("#admin-challenges").contains(document.activeElement)) {
      $("#admin-challenges").innerHTML = chals.map((c) => `<tr data-id="${esc(c.id)}"><td class="mono text-accent">${esc(c.id)}</td><td>${esc(c.title)}</td><td><input class="form-control form-control-sm mono" type="number" min="0" max="10000" value="${c.points}" data-f="points"></td><td><input type="checkbox" class="form-check-input" data-f="enabled" ${c.enabled ? "checked" : ""}></td><td><input type="checkbox" class="form-check-input" data-f="visible" ${c.visible ? "checked" : ""}></td><td class="text-end mono">${c.solves}</td><td class="text-end"><button class="btn btn-sm btn-outline-secondary" data-save>Save</button></td></tr>`).join("");
    }
    $("#admin-users").innerHTML = users.map((u) => `<tr data-uid="${esc(u.id)}"><td>${esc(u.username)}</td><td>${u.status === "active" ? "active" : '<span class="badge text-bg-warning">disabled</span>'}</td><td class="text-end mono">${u.solved}</td><td class="text-end mono">${u.score}</td><td class="text-end"><button class="btn btn-sm btn-outline-${u.status === "active" ? "danger" : "success"}" data-act="${u.status === "active" ? "disabled" : "active"}">${u.status === "active" ? "Disable" : "Enable"}</button></td></tr>`).join("");
    $("#admin-subs").innerHTML = subs.map((s) => `<tr><td>${new Date(s.time).toLocaleTimeString()}</td><td>${esc(s.username)}</td><td>${esc(s.challenge)}</td><td>${esc(s.outcome)}</td></tr>`).join("");
    loadOrganizerComms();
    $("#admin-audit").innerHTML = audit.map((a) => `<tr><td>${new Date(a.time).toLocaleTimeString()}</td><td>${esc(a.action)}</td><td>${esc(a.target)}</td></tr>`).join("");
    return true;
  } catch (e) {
    if (e.status === 401 || e.status === 404) leaveApp();
    return false;
  }
}

async function adminClick(ev) {
  const save = ev.target.closest("[data-save]");
  if (save) {
    const row = save.closest("tr");
    const body = { points: parseInt($('[data-f="points"]', row).value, 10), enabled: $('[data-f="enabled"]', row).checked, visible: $('[data-f="visible"]', row).checked };
    try { await api(`/api/admin/challenges/${row.dataset.id}`, { method: "PATCH", body }); notify("Saved"); loadAdmin(); } catch (e) { notify(e.message, "danger"); }
    return;
  }
  const act = ev.target.closest("[data-act]");
  if (!act) return;
  try { await api(`/api/admin/participants/${act.closest("tr").dataset.uid}/status`, { method: "POST", body: { status: act.dataset.act } }); loadAdmin(); } catch (e) { notify(e.message, "danger"); }
}

function setMode(mode) {
  state.mode = mode;
  $$("#auth-pills .nav-link").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#auth-submit").textContent = mode === "login" ? "Sign in" : "Create account";
  $("#code-row").hidden = !(mode === "register" && state.cfg.code_required);
  $("#f-pass").autocomplete = mode === "login" ? "current-password" : "new-password";
  $("#auth-error").hidden = true;
}

function afterLogin() {
  const next = new URLSearchParams(location.search).get("next");
  if (next && next.startsWith("/sso/authorize?")) { location.href = next; return true; }
  return false;
}

async function authSubmit(ev) {
  ev.preventDefault();
  const err = $("#auth-error");
  err.hidden = true;
  const body = { username: $("#f-user").value.trim(), password: $("#f-pass").value };
  if (state.mode === "register") body.code = $("#f-code").value;
  $("#auth-submit").disabled = true;
  try {
    state.user = await api(state.mode === "login" ? "/api/login" : "/api/register", { method: "POST", body });
    $("#f-pass").value = "";
    if (!afterLogin()) enterApp();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
  $("#auth-submit").disabled = false;
}

async function orgSubmit(ev) {
  ev.preventDefault();
  const err = $("#org-error");
  err.hidden = true;
  $("#org-submit").disabled = true;
  try {
    state.user = await api("/api/organizer/login", { method: "POST", body: { username: $("#o-user").value.trim(), password: $("#o-pass").value, totp: $("#o-totp").value.trim() } });
    $("#o-pass").value = ""; $("#o-totp").value = "";
    enterApp();
  } catch (e) {
    err.textContent = e.status === 429 ? e.message : "Invalid credentials";
    err.hidden = false;
  }
  $("#org-submit").disabled = false;
}

async function init() {
  modal = new bootstrap.Modal($("#flag-modal"));
  toast = new bootstrap.Toast($("#toast"), { delay: 3500 });
  try { state.cfg = await api("/api/config"); } catch (e) { state.cfg = {}; }
  document.title = state.cfg.event_name || "CTF";
  $("#event-name").textContent = state.cfg.event_name || "CTF";
  $("#register-pill").parentElement.hidden = !state.cfg.registration_open;
  $$("#auth-pills .nav-link").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  $("#auth-form").addEventListener("submit", authSubmit);
  $("#org-form").addEventListener("submit", orgSubmit);
  $("#flag-form").addEventListener("submit", submitFlag);
  $("#challenge-grid").addEventListener("click", (e) => { const c = e.target.closest(".chal"); if (c) openChallenge(c.dataset.id); });
  $("#view-admin").addEventListener("click", adminClick);
  bindComms();
  $("#flag-ctl").addEventListener("submit", async (e) => {
    e.preventDefault();
    const action = e.submitter && e.submitter.dataset.a;
    if (!confirm(`${action} the flag for this participant and challenge?`)) return;
    try { await api("/api/admin/flags", { method: "POST", body: { username: $("#fc-user").value.trim(), challenge_id: $("#fc-chal").value.trim(), action } }); notify(`Flag ${action}d`); loadAdmin(); } catch (er) { notify(er.message, "danger"); }
  });
  $("#logout").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }).catch(() => {}); leaveApp(); });
  window.addEventListener("hashchange", () => { if (state.user) setTab(location.hash.slice(1) || "challenges"); else leaveApp(); });
  try {
    state.user = await api("/api/me");
    if (!afterLogin()) enterApp();
  } catch (e) {
    leaveApp();
  }
}

init();

const SAFE_LINK = /^(https?:\/\/|\/(?!\/))/;
const seenKey = () => `fd_seen_${state.user ? state.user.username : ""}`;
const lastSeen = () => parseInt(localStorage.getItem(seenKey()) || "0", 10) || 0;

function fmtTime(iso) { return new Date(iso).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }); }

function linkHtml(n) {
  if (!n.link || !SAFE_LINK.test(n.link)) return "";
  const ext = /^https?:/.test(n.link);
  const label = n.kind === "wordlist" ? "Download" : "Open";
  return `<a class="btn btn-sm btn-outline-secondary mt-2" href="${esc(n.link)}"${ext ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>`;
}

function renderNotifs() {
  const seen = lastSeen();
  const unread = state.notifs.filter((n) => n.id > seen).length;
  const badge = $("#bell-count");
  badge.hidden = unread === 0;
  badge.textContent = unread > 9 ? "9+" : unread;
  $("#notif-list").innerHTML = state.notifs.length ? state.notifs.map((n) => `<div class="notif-item ${n.id > seen ? "new" : ""}"><div class="d-flex justify-content-between gap-2"><strong>${esc(n.title)}</strong>${n.challenge_id ? `<span class="badge text-bg-secondary mono">${esc(n.challenge_id)}</span>` : ""}</div>${n.body ? `<div class="small mt-1">${esc(n.body)}</div>` : ""}${linkHtml(n)}<div class="small text-secondary mt-1">${fmtTime(n.created_at)}</div></div>`).join("") : '<div class="text-center text-secondary py-4 small">No notifications yet.</div>';
}

async function loadNotifs() {
  try {
    const list = await api("/api/notifications");
    const prevTop = state.notifs.length ? state.notifs[0].id : 0;
    state.notifs = list;
    const top = list.length ? list[0].id : 0;
    if (!state.firstNotif && top > prevTop) {
      const fresh = list.filter((n) => n.id > prevTop && n.id > lastSeen());
      if (fresh.length) notify(fresh[0].title + (fresh.length > 1 ? ` (+${fresh.length - 1} more)` : ""), "info");
      if (state.tab === "wordlists") loadWordlists();
    }
    state.firstNotif = false;
    renderNotifs();
    return true;
  } catch (e) {
    if (e.status === 401) leaveApp();
    return false;
  }
}

function startNotifs() {
  stopNotifs();
  state.firstNotif = true;
  state.notifFails = 0;
  const tick = async () => {
    const ok = await loadNotifs();
    state.notifFails = ok ? 0 : Math.min((state.notifFails || 0) + 1, 4);
    state.notifTimer = setTimeout(tick, 15000 * Math.pow(2, state.notifFails) * (0.8 + Math.random() * 0.4));
  };
  tick();
}

function stopNotifs() { clearTimeout(state.notifTimer); state.notifTimer = null; state.notifs = []; }

function markAllRead() {
  if (state.notifs.length) localStorage.setItem(seenKey(), String(state.notifs[0].id));
  renderNotifs();
}

async function loadWordlists() {
  try { state.resources = await api("/api/resources"); } catch (e) {
    if (e.status === 401) return leaveApp();
    return notify(e.message, "danger");
  }
  $("#wordlist-grid").innerHTML = state.resources.length ? state.resources.map((r) => `<div class="col-md-6 col-lg-4"><div class="card h-100"><div class="card-body d-flex flex-column"><h5 class="card-title">${esc(r.title)}</h5><p class="small text-secondary">${esc(r.description)}</p><div class="mb-3">${r.released_labs.map((l) => `<span class="badge text-bg-secondary mono me-1">${esc(l)}</span>`).join("")}</div><div class="mt-auto d-flex justify-content-between align-items-center"><span class="small text-secondary mono">${r.lines} lines</span><a class="btn btn-sm btn-accent" href="/api/resources/${encodeURIComponent(r.id)}/download"><i class="bi bi-download me-1"></i>${esc(r.filename)}</a></div></div></div></div>`).join("") : '<div class="col-12 text-secondary">No wordlists have been released yet. Check back when the organizers announce one.</div>';
}

async function loadOrganizerComms() {
  try {
    const [anns, res] = await Promise.all([api("/api/admin/announcements"), api("/api/admin/resources")]);
    $("#admin-anns").innerHTML = anns.length ? anns.map((a) => `<tr data-aid="${a.id}"><td>${fmtTime(a.created_at)}</td><td>${esc(a.title)}</td><td class="mono">${esc(a.challenge_id)}</td><td class="mono small">${esc(a.link)}</td><td class="text-end"><button class="btn btn-sm btn-outline-danger" data-delann>Delete</button></td></tr>`).join("") : '<tr><td colspan="5" class="text-secondary text-center">Nothing sent yet.</td></tr>';
    if (!$("#admin-res").contains(document.activeElement)) {
      $("#admin-res").innerHTML = res.map((r) => `<tr data-rid="${esc(r.id)}"><td><div>${esc(r.title)}</div><div class="small text-secondary mono">${esc(r.filename)}</div></td><td class="mono">${r.lines}</td><td>${[...new Set([...r.labs, ...r.released_labs])].sort().map((l) => `<label class="me-3 text-nowrap"><input type="checkbox" class="form-check-input me-1" data-lab="${esc(l)}" ${r.released_labs.includes(l) ? "checked" : ""}>${esc(l)}</label>`).join("")}</td><td class="text-end text-nowrap"><button class="btn btn-sm btn-accent" data-release>Apply</button> <button class="btn btn-sm btn-outline-secondary" data-releaseall>All</button> <button class="btn btn-sm btn-outline-danger" data-delres>Delete</button></td></tr>`).join("");
    }
  } catch (e) {}
}

async function commsClick(ev) {
  const t = ev.target;
  const ann = t.closest("[data-delann]");
  if (ann) {
    if (!confirm("Delete this notification?")) return;
    try { await api(`/api/admin/announcements/${ann.closest("tr").dataset.aid}`, { method: "DELETE" }); loadOrganizerComms(); } catch (e) { notify(e.message, "danger"); }
    return;
  }
  const row = t.closest("#admin-res tr");
  if (!row) return;
  const rid = row.dataset.rid;
  if (t.closest("[data-delres]")) {
    if (!confirm("Delete this wordlist?")) return;
    try { await api(`/api/admin/resources/${encodeURIComponent(rid)}`, { method: "DELETE" }); loadOrganizerComms(); } catch (e) { notify(e.message, "danger"); }
    return;
  }
  const all = t.closest("[data-releaseall]");
  if (!all && !t.closest("[data-release]")) return;
  if (all) $$("[data-lab]", row).forEach((c) => (c.checked = true));
  const labs = $$("[data-lab]", row).filter((c) => c.checked).map((c) => c.dataset.lab);
  try { await api(`/api/admin/resources/${encodeURIComponent(rid)}`, { method: "PATCH", body: { released_labs: labs } }); notify(labs.length ? "Released and announced" : "Hidden from participants"); loadOrganizerComms(); loadNotifs(); } catch (e) { notify(e.message, "danger"); }
}

function bindComms() {
  $("#notif-read").addEventListener("click", markAllRead);
  $("#bell").addEventListener("shown.bs.dropdown", () => setTimeout(markAllRead, 1500));
  $("#view-admin").addEventListener("click", commsClick);
  $("#ann-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = { title: $("#an-title").value.trim(), body: $("#an-body").value.trim(), link: $("#an-link").value.trim(), challenge_id: $("#an-chal").value.trim().toUpperCase() };
    try { await api("/api/admin/announcements", { method: "POST", body }); e.target.reset(); notify("Sent to all participants"); loadOrganizerComms(); loadNotifs(); } catch (er) { notify(er.message, "danger"); }
  });
  $("#res-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const labs = $("#rs-labs").value.split(",").map((x) => x.trim().toUpperCase()).filter(Boolean);
    try { await api("/api/admin/resources", { method: "POST", body: { title: $("#rs-title").value.trim(), filename: $("#rs-file").value.trim(), labs, content: $("#rs-content").value } }); e.target.reset(); notify("Wordlist added (hidden until released)"); loadOrganizerComms(); } catch (er) { notify(er.message, "danger"); }
  });
}
