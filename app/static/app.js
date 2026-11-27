"use strict";
const $ = (s) => document.querySelector(s);
const show = (el, on = true) => el.classList.toggle("hidden", !on);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));

function signals() {
  return [...document.querySelectorAll("#demoPanel input:checked")].map((i) => i.value).join(",");
}

async function api(path, body, method) {
  const opts = {method: method || (body === undefined ? "GET" : "POST"), credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-Demo-Signals": signals()}};
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : `Error ${r.status}`);
  }
  return data;
}

function msg(el, text, kind = "error") { el.textContent = text; el.className = "msg " + kind; }

// ---------- WebAuthn helpers (base64url <-> ArrayBuffer)
const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0)).buffer;
const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function creationOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  return {...o, challenge: b64uToBuf(o.challenge), user: {...o.user, id: b64uToBuf(o.user.id)},
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({...c, id: b64uToBuf(c.id)}))};
}
function requestOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  return {...o, challenge: b64uToBuf(o.challenge), allowCredentials: (o.allowCredentials || []).map((c) => ({...c, id: b64uToBuf(c.id)}))};
}
function credJSON(c) {
  if (typeof c.toJSON === "function") return c.toJSON();
  const r = c.response, out = {id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
    clientExtensionResults: c.getClientExtensionResults(), authenticatorAttachment: c.authenticatorAttachment, response: {clientDataJSON: bufToB64u(r.clientDataJSON)}};
  if (r.attestationObject) { out.response.attestationObject = bufToB64u(r.attestationObject); if (r.getTransports) out.response.transports = r.getTransports(); }
  if (r.authenticatorData) { out.response.authenticatorData = bufToB64u(r.authenticatorData); out.response.signature = bufToB64u(r.signature);
    if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle); }
  return out;
}
async function passkeyAssert(optionsPath, verifyPath) {
  if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
  const options = await api(optionsPath, {});
  const cred = await navigator.credentials.get({publicKey: requestOptions(options)});
  return api(verifyPath, {credential: credJSON(cred)});
}

// ---------- rendering
function bars() { document.querySelectorAll(".bar span[data-pct]").forEach((el) => { el.style.width = el.dataset.pct + "%"; }); }
function riskHtml(r) {
  if (!r) return "";
  const pct = Math.round(r.score * 100);
  const reasons = r.reasons && r.reasons.length ? r.reasons.map(esc).join(", ") : "nothing unusual";
  return `<div class="risk ${r.level}"><div class="bar"><span data-pct="${Math.max(pct, 2)}"></span></div>
    <b>Risk ${pct}% (${r.level})</b> · signals: ${reasons}</div>`;
}
const FACTOR_NAMES = {totp: "authenticator code", passkey: "fingerprint / face (passkey)"};

async function refresh() {
  let me;
  try { me = await api("/api/me"); } catch { me = null; }
  show($("#demoPanel"), true);
  if (!me || me.state !== "active") {
    show($("#authCard"), !me || me.state !== "pending"); show($("#app"), false); show($("#logoutBtn"), !!me);
    if (me && me.state === "pending") showStep(me.pending, me.login_risk);
    return;
  }
  show($("#authCard"), false); show($("#stepCard"), false); show($("#intro"), false);
  show($("#app"), true); show($("#logoutBtn"), true);
  $("#hello").textContent = `Hello, ${me.name}`;
  $("#loginRisk").innerHTML = "Signed in with: " + me.session_factors.map(esc).join(" + ") +
    (me.login_risk ? riskHtml(me.login_risk) : "");
  bars();
  const f = me.factors;
  $("#fTotp").innerHTML = f.totp ? `<span class="ok">✔</span> <b>Authenticator app</b> <span class="muted">time-based codes (RFC 6238)</span>`
    : `<span class="no">✖</span> <b>Authenticator app</b> <button id="totpBtn" class="small">Set up</button>`;
  $("#fPasskey").innerHTML = f.passkey ? `<span class="ok">✔</span> <b>Passkey</b> <span class="muted">${f.passkeys} registered · fingerprint/face required</span> <button id="pkBtn" class="small ghost">Add another</button>`
    : `<span class="no">✖</span> <b>Passkey</b> (fingerprint / face) <button id="pkBtn" class="small">Add</button>`;
  if ($("#totpBtn")) $("#totpBtn").onclick = setupTotp;
  $("#pkBtn").onclick = addPasskey;
  loadTables();
}

function showStep(required, risk) {
  show($("#authCard"), false); show($("#stepCard"), true);
  $("#stepRisk").innerHTML = riskHtml(risk) + `<p>Still needed: <b>${required.map((r) => FACTOR_NAMES[r] || r).join(" + ")}</b></p>`;
  bars();
  show($("#stepTotp"), required.includes("totp"));
  show($("#stepPasskey"), !required.includes("totp") && required.includes("passkey"));
}

async function loadTables() {
  const [p, a] = await Promise.all([api("/api/payments"), api("/api/activity")]);
  $("#payments tbody").innerHTML = p.payments.map((x) => `<tr><td>${esc(x.created.replace("T", " ").slice(0, 16))}</td><td>${esc(x.payee)}</td>
    <td>${esc(x.currency)} ${x.amount.toFixed(2)}</td><td>${Math.round(x.risk.score * 100)}%</td><td class="st ${esc(x.status)}">${esc(x.status.replace("_", " "))}</td></tr>`).join("")
    || `<tr><td colspan="5" class="muted">No payments yet</td></tr>`;
  $("#activity tbody").innerHTML = a.events.map((e) => `<tr><td>${esc(e.time.replace("T", " "))}</td><td>${esc(e.type.replace(/_/g, " "))}</td>
    <td>${esc(e.network)}</td><td class="muted">${esc(Object.entries(e.detail).filter(([, v]) => v !== null && !(Array.isArray(v) && !v.length)).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join("+") : v}`).join(" · "))}</td></tr>`).join("");
}

// ---------- actions
async function setupTotp() {
  try {
    const s = await api("/api/totp/setup", {});
    $("#totpQr").src = s.qr_svg_data_url; $("#totpSecret").textContent = s.secret.match(/.{1,4}/g).join(" ");
    show($("#totpSetup"), true);
  } catch (e) { msg($("#factorMsg"), e.message); }
}

async function addPasskey() {
  try {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
    const options = await api("/api/passkey/register/options", {});
    const cred = await navigator.credentials.create({publicKey: creationOptions(options)});
    await api("/api/passkey/register/verify", {credential: credJSON(cred), label: navigator.platform || "Passkey"});
    msg($("#factorMsg"), "Passkey added. High-value payments will ask for your fingerprint or face.", "ok");
    refresh();
  } catch (e) { msg($("#factorMsg"), e.name === "NotAllowedError" ? "Passkey set-up was cancelled." : e.message); }
}

function renderPayment(p) {
  const box = $("#payResult");
  let html = `<div class="pay ${esc(p.status)}"><h3>${esc(p.currency)} ${p.amount.toFixed(2)} to ${esc(p.payee)}: ${esc(p.status.replace("_", " "))}</h3>
    ${riskHtml(p.risk)}<p>${esc(p.reason)}</p>`;
  if (p.status === "step_up") {
    if (p.required.includes("totp")) html += `<form id="payTotp" class="row"><label>Authenticator code<input name="code" inputmode="numeric" maxlength="6" required autocomplete="one-time-code"></label><button>Confirm payment</button></form>`;
    else if (p.required.includes("passkey")) html += `<button id="payPk">Confirm ${esc(p.currency)} ${p.amount.toFixed(2)} with fingerprint / face</button>
      <p class="muted">Your passkey signs a challenge derived from this amount and payee (PSD2 dynamic linking).</p>`;
  }
  box.innerHTML = html + `<div id="payMsg" class="msg"></div></div>`;
  bars();
  if ($("#payTotp")) $("#payTotp").onsubmit = async (ev) => {
    ev.preventDefault();
    try { renderPayment(await api(`/api/payments/${p.id}/totp`, {code: ev.target.code.value})); loadTables(); }
    catch (e) { msg($("#payMsg"), e.message); }
  };
  if ($("#payPk")) $("#payPk").onclick = async () => {
    try { renderPayment(await passkeyAssert(`/api/payments/${p.id}/passkey/options`, `/api/payments/${p.id}/passkey/verify`)); loadTables(); }
    catch (e) { msg($("#payMsg"), e.name === "NotAllowedError" ? "Cancelled." : e.message); }
  };
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tab").forEach((t) => t.onclick = () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
    show($("#loginForm"), t.dataset.tab === "loginForm"); show($("#registerForm"), t.dataset.tab === "registerForm");
    msg($("#authMsg"), "", "");
  });
  $("#loginForm").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try {
      const r = await api("/api/login", {email: f.email.value, password: f.password.value});
      f.password.value = "";
      if (r.state === "active") refresh(); else showStep(r.required, r.risk);
    } catch (e) { msg($("#authMsg"), e.message); }
  };
  $("#registerForm").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try { await api("/api/register", {name: f.name.value, email: f.email.value, password: f.password.value}); refresh(); }
    catch (e) { msg($("#authMsg"), e.message); }
  };
  $("#stepTotp").onsubmit = async (ev) => {
    ev.preventDefault();
    try {
      const r = await api("/api/login/totp", {code: ev.target.code.value});
      if (r.state === "active") refresh(); else showStep(r.required);
    } catch (e) { msg($("#stepMsg"), e.message); }
  };
  $("#stepPasskeyBtn").onclick = async () => {
    try {
      const r = await passkeyAssert("/api/login/passkey/options", "/api/login/passkey/verify");
      if (r.state === "active") refresh(); else showStep(r.required);
    } catch (e) { msg($("#stepMsg"), e.name === "NotAllowedError" ? "Cancelled." : e.message); }
  };
  $("#totpConfirm").onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api("/api/totp/confirm", {code: ev.target.code.value}); show($("#totpSetup"), false);
      msg($("#factorMsg"), "Authenticator app set up.", "ok"); refresh(); }
    catch (e) { msg($("#factorMsg"), e.message); }
  };
  $("#payForm").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try { renderPayment(await api("/api/payments", {payee: f.payee.value, amount: parseFloat(f.amount.value), currency: f.currency.value})); loadTables(); }
    catch (e) { $("#payResult").innerHTML = `<div class="msg error">${esc(e.message)}</div>`; }
  };
  $("#logoutBtn").onclick = async () => { await api("/api/logout", {}); location.reload(); };
  refresh();
});
