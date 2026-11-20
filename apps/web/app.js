const content = document.getElementById("content");
const navigation = document.getElementById("navigation");
const sidebar = document.getElementById("sidebar");
const navToggle = document.getElementById("nav-toggle");
const logoutButton = document.getElementById("logout");
const apiBase = "/api/v1";
const routeNames = {
  dashboard:"Overview", upload:"New APK scan", history:"Scan history", compare:"Compare scans",
  reports:"Reports", catalog:"Publisher catalog", operations:"Operations",
  business:"Business calculator", settings:"Settings",
};
const labels = {
  low_observed:"Low observed", moderate:"Moderate", high:"High", critical:"Critical findings", inconclusive:"Inconclusive",
  verified_match:"Verified match", identity_mismatch:"Identity mismatch",
  possible_impersonation:"Possible impersonation", unverified_identity:"Unverified identity",
  insufficient_evidence:"Insufficient evidence",
};
const state = {user:null, generation:0, history:{offset:0, q:"", status:"", sort:"newest"}};
let timer;
const $ = (selector) => content.querySelector(selector);
const h = (value) => String(value ?? "Unavailable").replace(/[&<>"']/g, (c) =>
  ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"})[c]);
const human = (value) => labels[value] || String(value || "Pending").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
const date = (epoch) => epoch ? new Date(epoch * 1000).toLocaleString() : "Pending";
const badge = (value) => '<span class="pill" data-level="' + h(value) + '">' + h(human(value)) + '</span>';
const pretty = (data) => '<pre>' + h(JSON.stringify(data, null, 2)) + '</pre>';
const list = (items) => items.length ? '<ul>' + items.map((item) => '<li>' + h(item) + '</li>').join("") + '</ul>' : '<p class="muted">None recorded</p>';
const icon = (name) => '<span class="icon icon-' + name + '" aria-hidden="true"></span>';
const iconBox = (name, style = "empty-icon") => '<span class="' + style + '">' + icon(name) + '</span>';
const heading = (title, subtitle, cta = "") => '<div class="heading"><div><h1>' + title + '</h1><p class="subtitle">' + subtitle + '</p></div>' + cta + '</div>';
const action = (href, label, kind = "quiet") => '<a class="' + kind + '" href="' + href + '">' + label + '</a>';
const panelTitle = (title, description = "", link = "") => '<div class="panel-title"><div><h2>' + title + '</h2>' +
  (description ? '<p class="muted">' + description + '</p>' : '') + '</div>' + link + '</div>';
const statusLine = '<p class="status" id="status" role="status"></p>';
const scanPath = (id) => "/scans/" + encodeURIComponent(id);
const scanLink = (scan) => '<a href="#scan/' + encodeURIComponent(scan.id) + '">' + h(scan.package || scan.filename) + '</a>';

async function request(path, options = {}) {
  const headers = {"X-Sentinel-Request":"1", ...options.headers};
  const config = {...options, headers, credentials:"same-origin"};
  if (options.body && typeof options.body !== "string") {
    headers["Content-Type"] = "application/json";
    config.body = JSON.stringify(options.body);
  }
  const response = await fetch(apiBase + path, config);
  if (response.status === 204) return null;
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof result.detail === "string" ? result.detail :
      response.status === 422 ? "Check the supplied fields and try again." : "Request failed (" + response.status + ").";
    if (response.status === 401 && state.user) {
      state.user = null;
      render();
    }
    throw Error(message);
  }
  return result;
}

function setStatus(message, error = false) {
  const status = $("#status");
  if (status) {
    status.textContent = message;
    status.classList.toggle("error", error);
  }
}

function mount(html, generation) {
  if (generation !== state.generation) return false;
  content.innerHTML = html;
  return true;
}

function go(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}

function auth(generation) {
  const capability = (symbol, title, description) => '<div class="capability">' + icon(symbol) +
    '<div><h2>' + title + '</h2><p class="muted">' + description + '</p></div></div>';
  mount('<div class="welcome-grid"><section class="welcome-intro"><h1>Know what’s inside an Android app.</h1>' +
    '<p class="welcome-lede">Inspect APK signatures, publisher records, and permission requests before you install or distribute an app.</p></section>' +
    '<section class="panel welcome-card" aria-labelledby="auth-title">' +
    '<h2 id="auth-title">Sign in</h2><p class="muted auth-subtitle" id="auth-subtitle">Access your private scans and reports.</p>' +
    '<form id="auth"><label>Email<input required type="email" name="email" autocomplete="username" maxlength="254" autocapitalize="none" spellcheck="false"></label>' +
    '<label>Password<input required type="password" name="password" minlength="12" maxlength="128" autocomplete="current-password"></label>' +
    '<button class="btn" type="submit" id="auth-submit">Sign in</button>' + statusLine + '</form>' +
    '<div class="auth-footer"><span id="auth-prompt">New to this workspace?</span> <button class="text-button" type="button" id="auth-mode">Create an account</button></div>' +
    '</section><section class="capabilities" aria-label="Checks and privacy">' +
    capability("badge-check", "Signature verification", "Compare verified signers with trusted publisher records.") +
    capability("file-search", "Static analysis", "Inspect permissions and code indicators without running the app.") +
    capability("lock-keyhole", "Private reports", "Uploads are deleted after analysis. Reports stay with your account.") +
    '</section></div>', generation);
  let register = false;
  $("#auth-mode").addEventListener("click", () => {
    register = !register;
    $("#auth-title").textContent = $("#auth-submit").textContent = register ? "Create account" : "Sign in";
    $("#auth-subtitle").textContent = register ? "Use a password with at least 12 characters." : "Access your private scans and reports.";
    $("#auth-prompt").textContent = register ? "Already registered?" : "New to this workspace?";
    $("#auth-mode").textContent = register ? "Use an existing account" : "Create an account";
    $("#auth input[type=password]").autocomplete = register ? "new-password" : "current-password";
    setStatus("");
    $("#auth input[type=email]").focus();
  });
  $("#auth").addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(event.currentTarget));
    const button = $("#auth-submit");
    button.disabled = true;
    try {
      if (register) await request("/auth/register", {method:"POST", body});
      state.user = await request("/auth/login", {method:"POST", body});
      go(location.hash || "#dashboard");
    } catch (error) {
      setStatus(error.message, true);
    } finally {
      button.disabled = false;
    }
  });
}

function table(items, exports = false) {
  if (!items.length) return '<p class="muted">No scans match this view.</p>';
  return '<div class="table-wrap"><table><thead><tr><th scope="col">APK</th><th scope="col">Submitted</th><th scope="col">Status</th><th scope="col">Risk</th>' +
    (exports ? '<th scope="col">Export</th>' : '') + '</tr></thead><tbody>' + items.map((scan) =>
    '<tr><td>' + scanLink(scan) + '</td><td>' + h(date(scan.created)) + '</td><td>' + badge(scan.status) +
    '</td><td>' + (scan.risk ? badge(scan.risk) : "—") + '</td>' + (exports ? '<td>' + downloads(scan.id) + '</td>' : "") + '</tr>'
  ).join("") + '</tbody></table></div>';
}

async function dashboard(generation) {
  const data = await request("/dashboard");
  const counts = data.counts;
  const risks = data.risks;
  const hasAssessments = Object.values(risks).some((count) => count > 0);
  const max = Math.max(1, ...Object.values(risks));
  const distribution = ["low_observed", "moderate", "high", "critical", "inconclusive"].map((name) =>
    '<div class="bar" data-risk="' + name + '"><span>' + h(human(name)) + '</span><div class="meter"><progress aria-label="' + h(human(name)) + '" max="' + max +
    '" value="' + (risks[name] || 0) + '"></progress></div><strong>' + (risks[name] || 0) + '</strong></div>').join("");
  const metric = (label, count) => '<div class="metric-card"><dt class="metric-label">' + label +
    '</dt><dd class="metric">' + count + '</dd></div>';
  mount(heading("Scan overview", "Review your Android APK assessments and the evidence behind each result.",
    action("#upload", icon("scan-line") + "Scan an APK", "btn")) +
    '<dl class="panel metric-grid">' + metric("Total scans", data.total) + metric("Completed", counts.completed || 0) +
    metric("Queued or running", (counts.queued || 0) + (counts.running || 0)) +
    metric("Failed or inconclusive", (counts.failed || 0) + (risks.inconclusive || 0)) + '</dl>' +
    '<div class="split"><section class="panel">' + panelTitle("Risk distribution", "Completed scans by assessment.") +
    (hasAssessments ? '<div class="histogram">' + distribution + '</div>' :
      '<p class="muted">Risk levels appear after a scan completes.</p>') +
    '</section><section class="panel">' + panelTitle("Recent findings") +
    (data.findings.length ? '<ul class="finding-list">' + data.findings.map((item) => '<li><a href="#scan/' + encodeURIComponent(item.id) + '">' + h(item.title) +
    '</a>' + badge(item.severity) + '</li>').join("") + '</ul>' : '<div class="empty-state">' + iconBox("file-search") +
    '<p class="muted">Findings appear after completed scans.</p></div>') + '</section></div>' +
    '<section class="panel">' + panelTitle("Recent activity", "", action("#history", "View history")) +
    table(data.items) + '</section>', generation);
}

function upload(generation) {
  mount(heading("New APK scan", "Submit one Android APK to inspect its metadata, signing, permissions, and static indicators.") +
    '<div class="split intake"><section class="panel"><h2>APK file</h2><form id="upload"><div class="drop" id="drop">' +
    iconBox("cloud-upload") + '<strong>Drag and drop an APK</strong><p class="muted" id="file-name" role="status">No file selected</p>' +
    '<input id="apk" type="file" accept=".apk,application/vnd.android.package-archive" hidden>' +
    '<button class="quiet" id="choose-apk" type="button">Browse files</button></div>' +
    '<progress aria-label="Upload progress" id="progress" max="100" value="0" hidden></progress>' +
    '<div><button class="btn" id="submit-apk" type="submit">' + icon("scan-line") + 'Upload and scan</button></div></form>' +
    statusLine + '</section><section class="panel"><h2>What Sentinel checks</h2><ul class="intake-list"><li>' +
    icon("badge-check") + 'APK signature and publisher reference matches</li><li>' +
    icon("file-search") + 'Manifest, permissions, and code indicators</li><li>' +
    icon("lock-keyhole") + 'Private report with the evidence and limits of each check</li></ul>' +
    '<p class="muted">Upload files you are authorized to inspect. This server removes the APK after the scan.</p></section></div>', generation);
  const drop = $("#drop");
  const picker = $("#apk");
  const choose = $("#choose-apk");
  const submit = $("#submit-apk");
  let selectedFile = null;
  function fileSelected(file) {
    selectedFile = file || null;
    $("#file-name").textContent = file ? file.name + " · " + (file.size / 1024).toLocaleString(undefined, {maximumFractionDigits:1}) + " KB" : "No file selected";
    setStatus("");
  }
  choose.addEventListener("click", () => picker.click());
  picker.addEventListener("change", () => fileSelected(picker.files[0]));
  drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("drag");
    if (submit.disabled) return;
    if (event.dataTransfer.files.length !== 1) return setStatus("Choose one APK.", true);
    picker.value = "";
    fileSelected(event.dataTransfer.files[0]);
  });
  $("#upload").addEventListener("submit", (event) => {
    event.preventDefault();
    const file = selectedFile;
    if (!file || !file.name.toLowerCase().endsWith(".apk") || !file.size) return setStatus("Choose a nonempty APK file.", true);
    const progress = $("#progress");
    const xhr = new XMLHttpRequest();
    submit.disabled = true;
    choose.disabled = true;
    progress.hidden = false;
    progress.value = 0;
    setStatus("Uploading " + file.name);
    xhr.open("POST", apiBase + "/scans");
    xhr.responseType = "json";
    xhr.timeout = 180000;
    xhr.setRequestHeader("Content-Type", "application/vnd.android.package-archive");
    xhr.setRequestHeader("X-Sentinel-Request", "1");
    xhr.setRequestHeader("X-APK-Filename", encodeURIComponent(file.name));
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) progress.value = e.loaded * 100 / e.total; };
    xhr.onload = () => {
      if (generation !== state.generation) return;
      submit.disabled = false;
      choose.disabled = false;
      if (xhr.status === 202) go("#scan/" + encodeURIComponent(xhr.response.id));
      else setStatus(xhr.response?.detail || "Upload failed (" + xhr.status + ").", true);
    };
    xhr.onerror = xhr.ontimeout = () => {
      if (generation !== state.generation) return;
      submit.disabled = false;
      choose.disabled = false;
      setStatus("The upload connection was interrupted.", true);
    };
    xhr.send(file);
  });
}

function downloads(id) {
  const path = apiBase + scanPath(id) + "/report.";
  return '<div class="row">' + action(path + "pdf", icon("file-down") + "PDF") + action(path + "json", "JSON") + '</div>';
}

function definitions(fields) {
  return "<dl>" + Object.entries(fields).map(([name, value]) => "<dt>" + h(name) + "</dt><dd>" + h(value) + "</dd>").join("") + "</dl>";
}

function findings(items) {
  return items.length ? items.map((item) =>
    '<article class="finding"><div class="row"><h3>' + h(item.title) + '</h3>' + badge(item.severity) +
    '</div><p>' + h(item.description) + '</p><p><strong>Action</strong> ' + h(item.action) + '</p><details><summary>Evidence and limitations</summary>' +
    list(item.evidence) + '<p class="muted">' + h(item.source) + ' · ' + h(item.id) + ' · ' + h(item.limitation) +
    '</p><a href="' + h(item.reference) + '" rel="noreferrer">Reference</a></details></article>'
  ).join("") : '<p class="muted">No rule findings for the checks that ran.</p>';
}

function displayReport(report) {
  const m = report.metadata;
  return '<div class="split"><section class="panel report-summary" data-risk="' + h(report.assessment.level) +
    '"><h2>Risk assessment</h2>' + badge(report.assessment.level) +
    list(report.assessment.reasons) + '<h3>Malware model</h3><p>' + h(report.model.reason) + '</p>' +
    (report.model.status === "experimental" ? pretty(report.model) : '') + '</section>' +
    '<section class="panel identity-summary"><h2>Publisher authenticity</h2>' + badge(report.identity.verdict) + '<p>' + h(report.identity.reason) +
    '</p><details><summary>Identity evidence</summary>' + pretty(report.identity) + '</details></section></div>' +
    '<section class="panel">' + panelTitle("Security findings", "Review the evidence and suggested action for each finding.") + findings(report.findings) +
    (report.threat_indicators ? '<p class="muted">' + h(report.threat_indicators.reason) + '</p>' : '') +
    '<details><summary>DEX indicators and embedded hosts</summary>' + pretty(report.code) + '</details></section>' +
    '<section class="panel"><h2>APK metadata</h2>' + definitions({"Package":m.package,"Label":m.label,"Version":(m.version_name || "Unavailable") + " (" + (m.version_code || "Unavailable") + ")",
      "Minimum SDK":m.min_sdk,"Target SDK":m.target_sdk,"SHA-256":report.sha256,"Size":report.bytes.toLocaleString() + " bytes",
      "Scanned at":new Date(report.scanned_at).toLocaleString()}) +
    '<details><summary>Manifest and archive inventory</summary>' + pretty(m) + '</details></section>' +
    '<div class="split"><section class="panel"><h2>Signing verification</h2>' + badge(report.signing.status) +
    (report.signing.reason ? '<p>' + h(report.signing.reason) + '</p>' : list(report.signing.sha256)) +
    '<details><summary>Signing details</summary>' + pretty(report.signing) + '</details></section>' +
    '<section class="panel"><h2>Requested permissions</h2>' + list(m.permissions) + '</section></div>' +
    '<section class="panel"><h2>Coverage and limitations</h2>' + list(report.limitations) +
    list(report.missing.map((item) => item.field + " · " + item.reason)) + '<details><summary>Tool and rule versions</summary>' +
    pretty({...report.tools, rules:report.rule_version, schema:report.schema_version}) + '</details></section>';
}

async function scan(id, generation, previousStatus) {
  const data = await request(scanPath(id));
  if (generation !== state.generation) return;
  const active = ["running", "queued"].includes(data.status);
  if (active) timer = setTimeout(() => scan(id, generation, data.status).catch((error) => errorPage(error, generation)), 1500);
  if (data.status === previousStatus) return;
  const html = heading(h(data.filename), data.report ? "Static analysis report" : "Scan status", data.report ? downloads(id) : "") +
    '<section class="panel scan-state"><div class="row scan-state-row"><div class="row" aria-live="polite">' + badge(data.status) +
    '<span class="muted">' + h(date(data.created)) + '</span></div>' +
    (data.status === "queued" ? '<button class="quiet" id="cancel">Cancel scan</button>' : '') +
    (data.status !== "running" ? '<button class="quiet danger" id="remove">Delete scan</button>' : '') +
    '</div>' +
    (data.error ? '<p class="status error">' + h(data.error) + '</p>' : '') +
    (active ? '<p class="status">' + (data.status === "queued" ? "Waiting for a scanner worker." : "The worker is inspecting the APK.") + '</p>' : '') +
    statusLine + '</section>' + (data.report ? displayReport(data.report) : "");
  if (!mount(html, generation)) return;
  if ($("#cancel")) $("#cancel").onclick = async () => {
    try { await request(scanPath(id) + "/cancel", {method:"POST"}); render(); }
    catch(error) { setStatus(error.message, true); }
  };
  if ($("#remove")) $("#remove").onclick = async () => {
    if (!window.confirm("Permanently remove this scan and its report?")) return;
    try { await request(scanPath(id), {method:"DELETE"}); go("#history"); }
    catch(error) { setStatus(error.message, true); }
  };
}

async function history(generation, reports = false) {
  const query = new URLSearchParams({...state.history, limit:20});
  if (reports) query.set("status", "completed");
  const data = await request("/scans?" + query);
  const filters = ['queued', 'running', 'completed', 'failed', 'cancelled'];
  const is = (value, current) => value === current ? " selected" : "";
  if (!mount(heading(reports ? "Reports" : "Scan history", reports ? "Download completed security assessments." : "Find and review your private APK scans.",
    action("#upload", "New scan", "btn")) + '<section class="panel"><form id="filters" class="row"><label>Search APK<input name="q" value="' +
    h(state.history.q) + '" maxlength="180" placeholder="File, package, or hash"></label>' +
    (reports ? "" : '<label>Status<select name="status"><option value="">All states</option>' +
      filters.map((item) => '<option value="' + item + '"' + is(item, state.history.status) + '>' + human(item) + '</option>').join("") + '</select></label>') +
    '<label>Sort<select name="sort"><option value="newest">Newest first</option><option value="oldest"' + is("oldest", state.history.sort) +
    '>Oldest first</option></select></label><button class="quiet">Apply filters</button></form></section>' +
    '<section class="panel">' + table(data.items, reports) + '<div class="actions"><button class="quiet" id="prev"' +
    (state.history.offset ? "" : " disabled") + '>Previous</button><button class="quiet" id="next"' +
    (state.history.offset + 20 < data.total ? "" : " disabled") + '>Next</button><span class="muted">' +
    (data.total ? (state.history.offset + 1) + "–" + (state.history.offset + data.items.length) + " of " + data.total : "0 results") +
    '</span></div></section>', generation)) return;
  $("#filters").onsubmit = (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    state.history = {...state.history, ...values, offset:0};
    render();
  };
  $("#prev").onclick = () => { state.history.offset -= 20; render(); };
  $("#next").onclick = () => { state.history.offset += 20; render(); };
}

async function compare(generation) {
  const data = await request("/scans?status=completed&limit=100");
  const options = '<option value="">Choose a scan</option>' + data.items.map((item) =>
    '<option value="' + h(item.id) + '">' + h(item.filename + " · " + date(item.created)) + '</option>').join("");
  if (!mount(heading("Compare scans", "Review changes between two completed APK assessments.") +
    '<section class="panel"><form id="comparison"><div class="grid"><label>Earlier scan<select name="left" required>' +
    options + '</select></label><label>Later scan<select name="right" required>' + options +
    '</select></label></div><div><button class="btn">Compare</button></div></form>' + statusLine + '</section><div id="comparison-result"></div>', generation)) return;
  if (data.items.length < 2) setStatus("Complete two scans to compare them.");
  $("#comparison").onsubmit = async (event) => {
    event.preventDefault();
    const query = new URLSearchParams(new FormData(event.currentTarget));
    if (query.get("left") === query.get("right")) return setStatus("Choose two different scans.", true);
    try {
      const result = await request("/scans/compare?" + query);
      if (generation !== state.generation) return;
      const summary = (report) => definitions({"Package":report.metadata.package, "Version":report.metadata.version_name,
        "SHA-256":report.sha256,"Signers":report.signing.sha256.join(", ") || "Unavailable",
        "Risk":human(report.assessment.level),"Identity":human(report.identity.verdict)}) + list(report.findings.map((f) => f.title));
      $("#comparison-result").innerHTML = '<div class="split"><section class="panel"><h2>Earlier scan</h2>' + summary(result.before) +
        '</section><section class="panel"><h2>Later scan</h2>' + summary(result.after) +
        '</section></div><section class="panel"><h2>Permission changes</h2><h3>Added</h3>' + list(result.permissions_added) +
        '<h3>Removed</h3>' + list(result.permissions_removed) + '</section>';
      setStatus("");
    } catch (error) { setStatus(error.message, true); }
  };
}

async function catalog(generation, offset = 0) {
  const data = await request("/catalog?offset=" + offset);
  const isAdmin = state.user.role === "admin";
  const records = data.items.map((item, index) => '<article class="finding"><h3>' + h(item.label) + '</h3>' +
    '<p class="muted">' + h(item.package + " · " + item.publisher + " · " + item.status) +
    '</p><details><summary>Verification evidence</summary>' + pretty(item) + '</details>' +
    (isAdmin ? '<button class="quiet actions edit-record" data-index="' + index + '">Edit record</button>' : "") + '</article>').join("");
  if (!mount(heading("Publisher catalog", "Publisher and signer records maintained by workspace administrators.") +
    '<section class="panel"><h2>Reference records</h2>' + (records || '<p class="muted">No reference records on this page.</p>') +
    '<div class="actions">' + (offset ? '<button class="quiet" id="catalog-prev">Previous</button>' : "") +
    (data.next != null ? '<button class="quiet" id="catalog-next">Next</button>' : "") + '</div></section>' +
    (isAdmin ? '<section class="panel"><h2>Add or update a reference</h2><form id="catalog-form"><div class="grid">' +
      '<label>Package<input name="package" required></label><label>Publisher<input name="publisher" required></label><label>App label<input name="label" required></label>' +
      '<label>Verification source URL<input name="source" type="url" required></label><label>Verified on<input name="verified_on" type="date" required></label>' +
      '<label>Status<select name="status"><option>active</option><option>revoked</option></select></label>' +
      '<label>Icon hash (optional)<input name="icon_hash" maxlength="16"></label></div><label>Evidence<textarea name="evidence" required minlength="12"></textarea></label>' +
      '<label>Approved SHA-256 signer sets<textarea name="signers" required placeholder="One set per line, multiple signers in a set separated by commas"></textarea></label>' +
      '<div><button class="btn">Save reference</button></div></form>' + statusLine + '</section>' : ""), generation)) return;
  if ($("#catalog-prev")) $("#catalog-prev").onclick = () => catalog(generation, Math.max(0, offset - 100));
  if ($("#catalog-next")) $("#catalog-next").onclick = () => catalog(generation, data.next);
  if (!isAdmin) return;
  const form = $("#catalog-form");
  content.querySelectorAll(".edit-record").forEach((button) => button.onclick = () => {
    const item = data.items[Number(button.dataset.index)];
    for (const field of form.elements) {
      if (field.name in item) field.value = item[field.name] ?? "";
    }
    form.elements.signers.value = item.signer_sets.map((set) => set.join(", ")).join("\n");
    form.elements.package.focus();
  });
  form.onsubmit = async (event) => {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    body.signer_sets = body.signers.trim().split(/\n/).map((line) => line.split(",").map((value) => value.trim().toLowerCase()));
    delete body.signers;
    body.icon_hash = body.icon_hash || null;
    try {
      await request("/catalog/" + encodeURIComponent(body.package), {method:"PUT", body});
      await catalog(generation, offset);
      setStatus("Reference saved.");
    } catch (error) { setStatus(error.message, true); }
  };
}

async function operations(generation) {
  const data = await request("/operations");
  mount(heading("Operations", "Monitor scan processing and catalog revisions.") +
    '<div class="grid"><section class="panel"><h2>Worker</h2><p>' + h(human(data.worker)) +
    '</p></section><section class="panel"><h2>Analysis versions</h2>' + definitions({"Rules":data.rule_version,"Model":data.model}) +
    '</section><section class="panel"><h2>Job totals</h2>' + (Object.keys(data.counts).length ? definitions(data.counts) : '<p class="muted">No jobs submitted.</p>') +
    '</section></div><section class="panel"><h2>Recent audit events</h2>' + (data.audit.length ? pretty(data.audit) : '<p class="muted">No events recorded.</p>') +
    '</section>', generation);
}

function settings(generation) {
  mount(heading("Settings", "Account details and scan data controls.") + '<section class="panel"><h2>Profile</h2>' +
    definitions({"Email":state.user.email,"Access":human(state.user.role)}) + '</section><section class="panel"><h2>Privacy</h2>' +
    '<p>APK files are removed after processing. Reports expire after ' + h(state.user.retention_days || "the configured number of") +
    ' days. You can delete individual reports from their scan page. Contact your workspace operator for account recovery.</p>' +
    action("#history", "Manage scans") + '</section>', generation);
}

function business(generation) {
  const fields = {
    active:"Monthly active users", paid:"Paying customers", arpu:"Monthly revenue per paying customer",
    scans:"Monthly scans", cpu:"Compute cost per scan", storage:"Monthly storage cost", overhead:"Monthly infrastructure cost",
    support:"Monthly support cost", fee:"Payment processing fee (%)", perCharge:"Fixed fee per payment",
    acquisition:"Acquisition cost per customer", newPaid:"New paying customers per month",
  };
  mount(heading("Business calculator", "Model monthly costs and revenue. All inputs are scenario assumptions in USD.") +
    '<section class="panel"><h2>Scenario assumptions</h2><form id="business"><div class="grid">' +
    Object.entries(fields).map(([key, label]) => '<label>' + label + '<input type="number" min="0" max="' +
      (key === "fee" ? "100" : "1000000000") + '" step="' + (["active","paid","scans","newPaid"].includes(key) ? "1" : "0.0001") +
      '" name="' + key + '" value="0"></label>').join("") + '</div></form>' +
    '<p class="muted">Break-even holds scan volume, acquisition spend and fixed costs constant. The estimate assumes one payment per customer per month.</p></section>' +
    '<section class="panel" aria-live="polite"><h2>Monthly projection</h2><div id="projection"></div>' + statusLine + '</section>', generation);
  const form = $("#business");
  const currency = new Intl.NumberFormat("en-US", {style:"currency", currency:"USD"});
  const calculate = () => {
    if (!form.checkValidity()) return setStatus("Enter valid nonnegative assumptions.", true);
    const inputs = Object.fromEntries([...new FormData(form)].map(([key, value]) => [key, Number(value)]));
    if (inputs.paid > inputs.active || inputs.newPaid > inputs.paid) {
      $("#projection").textContent = "";
      return setStatus("Paying customers must fit within active users. New paying customers must fit within paying customers.", true);
    }
    setStatus("");
    const revenue = inputs.paid * inputs.arpu;
    const fee = inputs.arpu * inputs.fee / 100 + inputs.perCharge;
    const compute = inputs.scans * inputs.cpu;
    const processing = inputs.paid * fee;
    const delivery = compute + processing + inputs.storage + inputs.overhead + inputs.support;
    const acquisition = inputs.acquisition * inputs.newPaid;
    const contribution = inputs.arpu - fee;
    const breakEven = contribution > 0 ? Math.ceil((delivery + acquisition - processing) / contribution) : "Unavailable";
    $("#projection").innerHTML = definitions({
      "Revenue":currency.format(revenue), "Compute":currency.format(compute), "Payment processing":currency.format(processing),
      "Acquisition spend":currency.format(acquisition), "Gross margin":revenue ? ((revenue-delivery)*100/revenue).toFixed(1) + "%" : "Unavailable",
      "Operating profit or loss":currency.format(revenue - delivery - acquisition), "Break-even customers":breakEven,
    });
  };
  form.oninput = calculate;
  form.onsubmit = (event) => event.preventDefault();
  calculate();
}

function errorPage(error, generation) {
  mount(heading("Unable to load this view", h(error.message)) + action("#dashboard", "Overview"), generation);
}

function setMenu(open) {
  document.body.dataset.menuOpen = String(open);
  navToggle.setAttribute("aria-expanded", String(open));
}

async function render() {
  clearTimeout(timer);
  const generation = ++state.generation;
  const route = location.hash.slice(1) || "dashboard";
  document.body.dataset.view = state.user ? "workspace" : "welcome";
  sidebar.hidden = !state.user;
  logoutButton.hidden = !state.user;
  document.getElementById("admin-link").hidden = state.user?.role !== "admin";
  document.getElementById("profile-email").textContent = state.user?.email || "";
  document.getElementById("profile-initial").textContent = (state.user?.email || "").slice(0, 1).toUpperCase();
  const navRoute = route.startsWith("scan/") ? "history" : route;
  const pageName = route.startsWith("scan/") ? "Scan details" : (Object.hasOwn(routeNames, route) ? routeNames[route] : "Overview");
  document.getElementById("breadcrumb").innerHTML = '<span>Workspace / </span><strong>' + pageName + '</strong>';
  document.title = state.user ? pageName + " | AppTrust Sentinel" : "AppTrust Sentinel";
  navigation.querySelectorAll("a").forEach((a) => {
    if (a.hash === "#" + navRoute) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  if (!state.user) {
    setMenu(false);
    return auth(generation);
  }
  if (state.route !== route && (route === "history" || route === "reports")) state.history.offset = 0;
  state.route = route;
  mount('<p class="status" role="status">Loading…</p>', generation);
  try {
    if (route.startsWith("scan/")) return await scan(route.slice(5), generation);
    const pages = {dashboard, upload, history, compare, reports:(g) => history(g,true), catalog, settings, business, operations};
    const page = Object.hasOwn(pages, route) ? pages[route] : dashboard;
    await page(generation);
  } catch (error) { errorPage(error, generation); }
}

async function workerHealth() {
  const response = await fetch(apiBase + "/ready").catch(() => null);
  const online = Boolean(response?.ok);
  document.getElementById("worker-dot").dataset.online = online;
  document.getElementById("worker-status").textContent = online ? "Scanner online" : "Scanner unavailable";
}

logoutButton.onclick = async () => {
  try {
    await request("/auth/logout", {method:"POST"});
    state.user = null;
    go("#dashboard");
  } catch(error) { errorPage(error, state.generation); }
};
document.querySelector(".skip").onclick = (event) => { event.preventDefault(); content.focus(); };
navToggle.onclick = () => setMenu(navToggle.getAttribute("aria-expanded") !== "true");
sidebar.addEventListener("click", (event) => {
  if (event.target.closest("a")) setMenu(false);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && navToggle.offsetWidth && navToggle.getAttribute("aria-expanded") === "true") {
    setMenu(false);
    navToggle.focus();
  }
});
window.addEventListener("hashchange", () => { setMenu(false); render(); content.focus(); });
workerHealth();
setInterval(workerHealth, 15000);
request("/auth/me").then((user) => { state.user = user; }).catch(() => {}).finally(render);
