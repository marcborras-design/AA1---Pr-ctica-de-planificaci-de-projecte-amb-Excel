// pagina.hpp - La interfície HTML, embeguda dins del programa C++.
// Per canviar l'aspecte, edita només el contingut entre R"HTML( i )HTML".
// Idiomes: ca, es, en, no (objecte T al principi del <script>).
#pragma once

static const char* PAGINA_HTML = R"HTML(<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Vault</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f4f5f7; --card: #ffffff; --text: #1c1e21; --muted: #6b7280; --border: #d9dce1;
    --accent: #2f5bea; --accent-text: #ffffff; --hover: #eef1f6;
    --ok: #1b6e2d; --ok-bg: #e6f4ea; --err: #b00020; --err-bg: #fdecee;
    --info: #1d4ed8; --info-bg: #e8efff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14161a; --card: #1e2127; --text: #e6e8eb; --muted: #9aa1ab; --border: #343a43;
      --accent: #6c8cff; --accent-text: #0b1020; --hover: #2a2f38;
      --ok: #7bd88f; --ok-bg: #16301d; --err: #ff8a98; --err-bg: #3a1a1f;
      --info: #9db4ff; --info-bg: #1c2540;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .app { max-width: 780px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
  header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.2rem; }
  h1 { font-size: 1.4rem; margin: 0; }
  h2 { font-size: 1rem; margin: 0 0 .6rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.2rem; }
  label { display: block; margin: .8rem 0 .25rem; font-size: .88rem; color: var(--muted); }
  input, textarea, select { width: 100%; font: inherit; color: var(--text); background: var(--card);
         border: 1px solid var(--border); border-radius: 8px; padding: .55rem .7rem; }
  select { width: auto; }
  input:focus, textarea:focus, select:focus, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  textarea { min-height: 10rem; resize: vertical; }
  button { font: inherit; border-radius: 8px; border: 1px solid var(--border); background: var(--card);
           color: var(--text); padding: .5rem .9rem; cursor: pointer; }
  button:hover:not(:disabled) { background: var(--hover); }
  button:disabled { opacity: .55; cursor: progress; }
  button.primari { background: var(--accent); color: var(--accent-text); border-color: var(--accent); font-weight: 600; }
  button.primari:hover:not(:disabled) { filter: brightness(1.08); background: var(--accent); }
  .fila-botons { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: 1rem; }
  .pestanyes { display: flex; gap: .4rem; border-bottom: 1px solid var(--border); margin: -.2rem 0 .6rem; }
  .pestanyes button { border: none; border-bottom: 3px solid transparent; border-radius: 0; background: none; padding: .6rem 1rem; }
  .pestanyes button[aria-selected="true"] { border-bottom-color: var(--accent); font-weight: 600; }
  .camp-pw { display: flex; gap: .4rem; }
  .camp-pw input { flex: 1; }
  .regles { list-style: none; margin: .6rem 0 0; padding: 0; font-size: .85rem; color: var(--muted); }
  .regles-titol { margin: .8rem 0 0; font-size: .85rem; color: var(--muted); }
  .regles li::before { content: "\25CB\00a0"; }
  .regles li.ok { color: var(--ok); }
  .regles li.ok::before { content: "\2713\00a0"; }
  .estat { margin-top: 1rem; padding: .6rem .8rem; border-radius: 8px; font-size: .92rem; }
  .estat.ok { background: var(--ok-bg); color: var(--ok); }
  .estat.error { background: var(--err-bg); color: var(--err); }
  .estat.info { background: var(--info-bg); color: var(--info); }
  .barra-sessio { display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }
  .cos { display: grid; grid-template-columns: 1fr 2fr; gap: 1.2rem; }
  @media (max-width: 640px) { .cos { grid-template-columns: 1fr; } }
  ul.llista { list-style: none; margin: 0; padding: 0; max-height: 22rem; overflow: auto; }
  ul.llista button { width: 100%; text-align: left; border: 1px solid transparent; background: none; margin-bottom: .2rem; }
  ul.llista button[aria-current="true"] { border-color: var(--accent); background: var(--hover); font-weight: 600; }
  .nota { font-size: .8rem; color: var(--muted); margin-top: 1rem; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
<div class="app">

  <header>
    <h1>Secure Vault</h1>
    <select id="idioma" aria-label="Idioma / Language">
      <option value="ca">Català</option>
      <option value="es">Castellano</option>
      <option value="en">English</option>
      <option value="no">Norsk</option>
    </select>
  </header>

  <!-- Pantalla 1: login / crear usuari -->
  <section id="auth" class="card">
    <div class="pestanyes" role="tablist">
      <button type="button" id="tabLogin" role="tab" aria-selected="true" data-i18n="tab_login"></button>
      <button type="button" id="tabReg" role="tab" aria-selected="false" data-i18n="tab_reg"></button>
    </div>

    <form id="formAuth" autocomplete="on">
      <label for="usuari" data-i18n="usuari"></label>
      <input id="usuari" name="username" autocomplete="username" maxlength="64" required>

      <label for="pw" data-i18n="pw"></label>
      <div class="camp-pw">
        <input id="pw" name="password" type="password" autocomplete="current-password" required>
        <button type="button" id="bMostra" aria-pressed="false"></button>
      </div>

      <div id="campPw2" hidden>
        <label for="pw2" data-i18n="pw2"></label>
        <input id="pw2" type="password" autocomplete="new-password">
      </div>

      <div id="regles" hidden>
        <p class="regles-titol" data-i18n="regles"></p>
        <ul class="regles">
          <li data-r="len" data-i18n="r_len"></li>
          <li data-r="maj" data-i18n="r_maj"></li>
          <li data-r="min" data-i18n="r_min"></li>
          <li data-r="num" data-i18n="r_num"></li>
          <li data-r="esp" data-i18n="r_esp"></li>
        </ul>
      </div>

      <div class="fila-botons">
        <button type="submit" id="bSubmit" class="primari"></button>
      </div>
    </form>
  </section>

  <!-- Pantalla 2: sessió -->
  <section id="sessio" hidden>
    <div class="barra-sessio">
      <span><span data-i18n="sessio_de"></span> <strong id="nomUsuari"></strong></span>
      <button type="button" id="bSortir" data-i18n="tancar"></button>
    </div>

    <div class="cos">
      <div class="card">
        <h2 data-i18n="secrets"></h2>
        <ul id="llista" class="llista"></ul>
        <p id="buit" class="nota" data-i18n="buit"></p>
      </div>

      <div class="card">
        <label for="nomSecret" data-i18n="nom_secret"></label>
        <input id="nomSecret" maxlength="128">

        <label for="text" data-i18n="text"></label>
        <textarea id="text" data-i18n-ph="ph_text"></textarea>

        <div class="fila-botons">
          <button type="button" id="bDesar" class="primari" data-i18n="desar"></button>
          <button type="button" id="bLlegir" data-i18n="desxifrar"></button>
          <button type="button" id="bCopiar" data-i18n="copiar"></button>
          <button type="button" id="bNeteja" data-i18n="netejar"></button>
        </div>
        <p class="nota" data-i18n="caduca_nota"></p>
      </div>
    </div>
  </section>

  <div id="estat" class="estat" role="status" aria-live="polite" hidden></div>
</div>

<script>
// ===================== Traduccions =====================
// Les claus "err_*" corresponen als codis d'error que envia el servidor C++.
const T = {
  ca: {
    tab_login: "Iniciar sessió", tab_reg: "Crear usuari",
    usuari: "Usuari", pw: "Contrasenya", pw2: "Repeteix la contrasenya",
    mostra: "Mostrar", amaga: "Amagar",
    regles: "La contrasenya ha de tenir:",
    r_len: "Mínim 8 caràcters", r_maj: "Una majúscula", r_min: "Una minúscula",
    r_num: "Un número", r_esp: "Un símbol",
    btn_login: "Entrar", btn_reg: "Crear compte",
    sessio_de: "Sessió de", tancar: "Tancar sessió",
    secrets: "Els meus secrets", buit: "Encara no tens cap secret.",
    nom_secret: "Nom del secret", text: "Contingut", ph_text: "Escriu aquí el text a xifrar...",
    desar: "Xifrar i desar", desxifrar: "Desxifrar", copiar: "Copiar", netejar: "Netejar",
    caduca_nota: "La sessió caduca als 15 minuts d'inactivitat.",
    w_login: "Verificant...", w_reg: "Creant usuari...", w_desar: "Xifrant...",
    w_llegir: "Desxifrant...", w_sortir: "Tancant sessió...",
    ok_reg: "Usuari creat. Ja pots iniciar sessió.", ok_desar: "Secret xifrat i desat.",
    ok_llegir: "Secret desxifrat.", ok_sortir: "Sessió tancada.", ok_copiat: "Copiat al porta-retalls.",
    err_copiar: "No s'ha pogut copiar.", err_connexio: "No s'ha pogut connectar amb el programa.",
    err_usuari_invalid: "El nom d'usuari ha de tenir entre 1 i 64 caràcters.",
    err_pw_curta: "La contrasenya ha de tenir com a mínim 8 caràcters.",
    err_pw_complexitat: "La contrasenya ha d'incloure majúscules, minúscules, números i símbols.",
    err_pw_llarga: "Contrasenya massa llarga.",
    err_pw_no_coincideix: "Les contrasenyes no coincideixen.",
    err_usuari_existeix: "Aquest nom d'usuari ja existeix.",
    err_credencials: "Usuari o contrasenya incorrectes.",
    err_sessio_caducada: "La sessió ha caducat. Torna a iniciar-la.",
    err_nom_secret_invalid: "El nom del secret ha de tenir entre 1 i 128 caràcters.",
    err_text_gran: "Text massa gran (màxim 1 MiB).",
    err_desar_error: "No s'ha pogut desar (potser el nom ja existeix).",
    err_secret_no_trobat: "Secret no trobat.",
    err_dades_alterades: "Contrasenya incorrecta o dades alterades.",
    err_error_intern: "Error intern del servidor."
  },
  es: {
    tab_login: "Iniciar sesión", tab_reg: "Crear usuario",
    usuari: "Usuario", pw: "Contraseña", pw2: "Repite la contraseña",
    mostra: "Mostrar", amaga: "Ocultar",
    regles: "La contraseña debe tener:",
    r_len: "Mínimo 8 caracteres", r_maj: "Una mayúscula", r_min: "Una minúscula",
    r_num: "Un número", r_esp: "Un símbolo",
    btn_login: "Entrar", btn_reg: "Crear cuenta",
    sessio_de: "Sesión de", tancar: "Cerrar sesión",
    secrets: "Mis secretos", buit: "Todavía no tienes ningún secreto.",
    nom_secret: "Nombre del secreto", text: "Contenido", ph_text: "Escribe aquí el texto a cifrar...",
    desar: "Cifrar y guardar", desxifrar: "Descifrar", copiar: "Copiar", netejar: "Limpiar",
    caduca_nota: "La sesión caduca tras 15 minutos de inactividad.",
    w_login: "Verificando...", w_reg: "Creando usuario...", w_desar: "Cifrando...",
    w_llegir: "Descifrando...", w_sortir: "Cerrando sesión...",
    ok_reg: "Usuario creado. Ya puedes iniciar sesión.", ok_desar: "Secreto cifrado y guardado.",
    ok_llegir: "Secreto descifrado.", ok_sortir: "Sesión cerrada.", ok_copiat: "Copiado al portapapeles.",
    err_copiar: "No se ha podido copiar.", err_connexio: "No se ha podido conectar con el programa.",
    err_usuari_invalid: "El nombre de usuario debe tener entre 1 y 64 caracteres.",
    err_pw_curta: "La contraseña debe tener al menos 8 caracteres.",
    err_pw_complexitat: "La contraseña debe incluir mayúsculas, minúsculas, números y símbolos.",
    err_pw_llarga: "Contraseña demasiado larga.",
    err_pw_no_coincideix: "Las contraseñas no coinciden.",
    err_usuari_existeix: "Este nombre de usuario ya existe.",
    err_credencials: "Usuario o contraseña incorrectos.",
    err_sessio_caducada: "La sesión ha caducado. Vuelve a iniciarla.",
    err_nom_secret_invalid: "El nombre del secreto debe tener entre 1 y 128 caracteres.",
    err_text_gran: "Texto demasiado grande (máximo 1 MiB).",
    err_desar_error: "No se ha podido guardar (quizá el nombre ya existe).",
    err_secret_no_trobat: "Secreto no encontrado.",
    err_dades_alterades: "Contraseña incorrecta o datos alterados.",
    err_error_intern: "Error interno del servidor."
  },
  en: {
    tab_login: "Log in", tab_reg: "Create user",
    usuari: "Username", pw: "Password", pw2: "Repeat the password",
    mostra: "Show", amaga: "Hide",
    regles: "The password must have:",
    r_len: "At least 8 characters", r_maj: "An uppercase letter", r_min: "A lowercase letter",
    r_num: "A number", r_esp: "A symbol",
    btn_login: "Enter", btn_reg: "Create account",
    sessio_de: "Signed in as", tancar: "Log out",
    secrets: "My secrets", buit: "You don't have any secrets yet.",
    nom_secret: "Secret name", text: "Content", ph_text: "Type the text to encrypt here...",
    desar: "Encrypt and save", desxifrar: "Decrypt", copiar: "Copy", netejar: "Clear",
    caduca_nota: "The session expires after 15 minutes of inactivity.",
    w_login: "Verifying...", w_reg: "Creating user...", w_desar: "Encrypting...",
    w_llegir: "Decrypting...", w_sortir: "Logging out...",
    ok_reg: "User created. You can now log in.", ok_desar: "Secret encrypted and saved.",
    ok_llegir: "Secret decrypted.", ok_sortir: "Logged out.", ok_copiat: "Copied to the clipboard.",
    err_copiar: "Could not copy.", err_connexio: "Could not connect to the program.",
    err_usuari_invalid: "The username must be between 1 and 64 characters.",
    err_pw_curta: "The password must have at least 8 characters.",
    err_pw_complexitat: "The password must include uppercase, lowercase, numbers and symbols.",
    err_pw_llarga: "Password too long.",
    err_pw_no_coincideix: "The passwords do not match.",
    err_usuari_existeix: "This username already exists.",
    err_credencials: "Wrong username or password.",
    err_sessio_caducada: "The session has expired. Please log in again.",
    err_nom_secret_invalid: "The secret name must be between 1 and 128 characters.",
    err_text_gran: "Text too large (maximum 1 MiB).",
    err_desar_error: "Could not save (the name may already exist).",
    err_secret_no_trobat: "Secret not found.",
    err_dades_alterades: "Wrong password or the data has been altered.",
    err_error_intern: "Internal server error."
  },
  no: {
    tab_login: "Logg inn", tab_reg: "Opprett bruker",
    usuari: "Brukernavn", pw: "Passord", pw2: "Gjenta passordet",
    mostra: "Vis", amaga: "Skjul",
    regles: "Passordet må ha:",
    r_len: "Minst 8 tegn", r_maj: "En stor bokstav", r_min: "En liten bokstav",
    r_num: "Et tall", r_esp: "Et spesialtegn",
    btn_login: "Logg inn", btn_reg: "Opprett konto",
    sessio_de: "Innlogget som", tancar: "Logg ut",
    secrets: "Mine hemmeligheter", buit: "Du har ingen hemmeligheter ennå.",
    nom_secret: "Navn på hemmeligheten", text: "Innhold", ph_text: "Skriv teksten som skal krypteres her...",
    desar: "Krypter og lagre", desxifrar: "Dekrypter", copiar: "Kopier", netejar: "Tøm",
    caduca_nota: "Økten utløper etter 15 minutter uten aktivitet.",
    w_login: "Verifiserer...", w_reg: "Oppretter bruker...", w_desar: "Krypterer...",
    w_llegir: "Dekrypterer...", w_sortir: "Logger ut...",
    ok_reg: "Bruker opprettet. Du kan nå logge inn.", ok_desar: "Hemmeligheten er kryptert og lagret.",
    ok_llegir: "Hemmeligheten er dekryptert.", ok_sortir: "Du er logget ut.", ok_copiat: "Kopiert til utklippstavlen.",
    err_copiar: "Kunne ikke kopiere.", err_connexio: "Kunne ikke koble til programmet.",
    err_usuari_invalid: "Brukernavnet må være mellom 1 og 64 tegn.",
    err_pw_curta: "Passordet må ha minst 8 tegn.",
    err_pw_complexitat: "Passordet må inneholde store og små bokstaver, tall og spesialtegn.",
    err_pw_llarga: "Passordet er for langt.",
    err_pw_no_coincideix: "Passordene er ikke like.",
    err_usuari_existeix: "Dette brukernavnet finnes allerede.",
    err_credencials: "Feil brukernavn eller passord.",
    err_sessio_caducada: "Økten har utløpt. Logg inn på nytt.",
    err_nom_secret_invalid: "Navnet på hemmeligheten må være mellom 1 og 128 tegn.",
    err_text_gran: "Teksten er for stor (maks 1 MiB).",
    err_desar_error: "Kunne ikke lagre (navnet finnes kanskje allerede).",
    err_secret_no_trobat: "Hemmeligheten ble ikke funnet.",
    err_dades_alterades: "Feil passord, eller dataene er endret.",
    err_error_intern: "Intern serverfeil."
  }
};

// ===================== Estat de la pàgina =====================
let idioma = "ca";
let mode = "login";        // "login" o "reg"
let token = "";            // només en memòria (mai a localStorage)
let ultimEstat = null;     // {clau, tipus}: es guarda la clau per poder retraduir-lo
let pwVisible = false;

const $ = id => document.getElementById(id);
const t = k => (T[idioma] && T[idioma][k]) || T.ca[k] || k;

// ===================== Idioma =====================
function idiomaInicial() {
  try {
    const guardat = localStorage.getItem("idioma");
    if (guardat && T[guardat]) return guardat;
  } catch (e) { /* localStorage pot no estar disponible */ }
  const nav = (navigator.language || "ca").slice(0, 2).toLowerCase();
  if (nav === "nb" || nav === "nn") return "no";
  return T[nav] ? nav : "ca";
}

function aplicaIdioma(l) {
  idioma = T[l] ? l : "ca";
  try { localStorage.setItem("idioma", idioma); } catch (e) {}
  document.documentElement.lang = idioma === "no" ? "nb" : idioma;
  $("idioma").value = idioma;

  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-ph]").forEach(el => { el.placeholder = t(el.dataset.i18nPh); });

  $("bSubmit").textContent = t(mode === "login" ? "btn_login" : "btn_reg");
  pintaMostra();
  pintaEstat();
}

// ===================== Missatges d'estat =====================
function estat(clau, tipus) { ultimEstat = clau ? { clau: clau, tipus: tipus } : null; pintaEstat(); }

function pintaEstat() {
  const e = $("estat");
  if (!ultimEstat) { e.hidden = true; e.textContent = ""; return; }
  e.hidden = false;
  e.textContent = t(ultimEstat.clau);     // textContent: mai innerHTML (evita XSS)
  e.className = "estat " + ultimEstat.tipus;
}

function claveError(codi) {
  const k = "err_" + codi;
  return T.ca[k] ? k : "err_error_intern";
}

// ===================== Comunicació amb el servidor C++ =====================
async function api(cami, dades) {
  const r = await fetch(cami, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Token": token },
    body: new URLSearchParams(dades || {})
  });
  return r.json();
}

// Bloqueja la pàgina mentre el servidor treballa (Argon2id és lent a propòsit)
async function feina(clauTreball, f) {
  const controls = document.querySelectorAll("button, select");
  controls.forEach(c => { c.disabled = true; });
  estat(clauTreball, "info");
  try { await f(); }
  catch (e) { estat("err_connexio", "error"); }
  finally { controls.forEach(c => { c.disabled = false; }); }
}

// ===================== Pantalla d'accés =====================
function setMode(m) {
  mode = m;
  $("tabLogin").setAttribute("aria-selected", String(m === "login"));
  $("tabReg").setAttribute("aria-selected", String(m === "reg"));
  $("campPw2").hidden = (m === "login");
  $("regles").hidden = (m === "login");
  $("pw2").required = (m === "reg");
  $("pw").autocomplete = (m === "login") ? "current-password" : "new-password";
  $("bSubmit").textContent = t(m === "login" ? "btn_login" : "btn_reg");
  estat(null);
  pintaRegles();
}

function reglesPw(p) {
  return {
    len: new TextEncoder().encode(p).length >= 8,   // bytes, igual que el servidor
    maj: /[A-Z]/.test(p),
    min: /[a-z]/.test(p),
    num: /[0-9]/.test(p),
    esp: /[^A-Za-z0-9]/.test(p)
  };
}

function pintaRegles() {
  const r = reglesPw($("pw").value);
  document.querySelectorAll("#regles li").forEach(li => li.classList.toggle("ok", !!r[li.dataset.r]));
}

function pintaMostra() {
  $("bMostra").textContent = t(pwVisible ? "amaga" : "mostra");
  $("bMostra").setAttribute("aria-pressed", String(pwVisible));
  $("pw").type = pwVisible ? "text" : "password";
  $("pw2").type = pwVisible ? "text" : "password";
}

const entrar = () => feina("w_login", async () => {
  const r = await api("/api/login", { usuari: $("usuari").value, contrasenya: $("pw").value });
  if (!r.ok) return estat(claveError(r.error), "error");
  token = r.token;
  $("nomUsuari").textContent = r.usuari;
  $("pw").value = "";
  $("pw2").value = "";
  pwVisible = false;
  pintaMostra();
  pintaRegles();
  ompleLlista(r.secrets);
  mostraSessio(true);
  estat(null);
});

const crear = () => {
  const p = $("pw").value;
  if (p !== $("pw2").value) return estat("err_pw_no_coincideix", "error");
  const r = reglesPw(p);
  if (!r.len) return estat("err_pw_curta", "error");
  if (!(r.maj && r.min && r.num && r.esp)) return estat("err_pw_complexitat", "error");

  return feina("w_reg", async () => {
    const resp = await api("/api/registre", {
      usuari: $("usuari").value, contrasenya: p, repeteix: $("pw2").value
    });
    if (!resp.ok) return estat(claveError(resp.error), "error");
    $("pw2").value = "";
    setMode("login");
    estat("ok_reg", "ok");
  });
};

// ===================== Pantalla de sessió =====================
function mostraSessio(on) { $("auth").hidden = on; $("sessio").hidden = !on; }

function marcaActiu() {
  const nom = $("nomSecret").value;
  document.querySelectorAll("#llista button").forEach(b => {
    b.setAttribute("aria-current", String(b.textContent === nom));
  });
}

function ompleLlista(noms) {
  const ul = $("llista");
  ul.textContent = "";
  noms.forEach(n => {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = n;
    b.onclick = () => { $("nomSecret").value = n; marcaActiu(); };
    li.appendChild(b);
    ul.appendChild(li);
  });
  $("buit").hidden = noms.length > 0;
  marcaActiu();
}

function tancaLocal() {
  token = "";
  $("text").value = "";
  $("nomSecret").value = "";
  ompleLlista([]);
  mostraSessio(false);
}

function caducada(r) {
  if (!r.caducada) return false;
  tancaLocal();
  estat("err_sessio_caducada", "error");
  return true;
}

$("bDesar").onclick = () => feina("w_desar", async () => {
  const r = await api("/api/desar", { nom: $("nomSecret").value, text: $("text").value });
  if (caducada(r)) return;
  if (!r.ok) return estat(claveError(r.error), "error");
  ompleLlista(r.secrets);
  $("text").value = "";
  estat("ok_desar", "ok");
});

$("bLlegir").onclick = () => feina("w_llegir", async () => {
  const r = await api("/api/llegir", { nom: $("nomSecret").value });
  if (caducada(r)) return;
  if (!r.ok) return estat(claveError(r.error), "error");
  $("text").value = r.text;
  estat("ok_llegir", "ok");
});

$("bCopiar").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("text").value);
    estat("ok_copiat", "ok");
  } catch (e) {
    estat("err_copiar", "error");
  }
};

$("bNeteja").onclick = () => { $("text").value = ""; };

$("bSortir").onclick = () => feina("w_sortir", async () => {
  await api("/api/logout");
  tancaLocal();
  estat("ok_sortir", "ok");
});

// ===================== Esdeveniments =====================
$("idioma").onchange = e => aplicaIdioma(e.target.value);
$("tabLogin").onclick = () => setMode("login");
$("tabReg").onclick = () => setMode("reg");
$("bMostra").onclick = () => { pwVisible = !pwVisible; pintaMostra(); };
$("pw").addEventListener("input", pintaRegles);
$("nomSecret").addEventListener("input", marcaActiu);
$("formAuth").addEventListener("submit", e => {
  e.preventDefault();
  if (mode === "login") entrar(); else crear();
});

// ===================== Inici =====================
aplicaIdioma(idiomaInicial());
setMode("login");
</script>
</body>
</html>
)HTML";
