/* DarkChecker — lógica do frontend (sem dependências externas). */

const API = {
  email: "/api/check/email",
  password: "/api/check/password",
};

// ---------------------------------------------------------------------------
// Navegação por abas
// ---------------------------------------------------------------------------
function activateTab(name) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.tab === name)
  );
  document.querySelectorAll(".panel").forEach((p) => {
    const isTarget = p.id === `panel-${name}`;
    p.classList.toggle("active", isTarget);
    p.hidden = !isTarget;
  });
  if (name === "learn") renderLearn();
}

document.querySelectorAll(".tab").forEach((tab) =>
  tab.addEventListener("click", () => activateTab(tab.dataset.tab))
);
document.querySelectorAll("[data-goto]").forEach((el) =>
  el.addEventListener("click", (e) => {
    e.preventDefault();
    activateTab(el.dataset.goto);
  })
);

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------
function esc(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function fmtNumber(n) {
  if (n == null) return "?";
  return Number(n).toLocaleString("pt-BR");
}

const RISK_LABEL = {
  none: "sem risco",
  low: "risco baixo",
  medium: "risco médio",
  high: "risco alto",
};

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    let detail = `Erro ${resp.status}`;
    try {
      const j = await resp.json();
      if (j.detail) detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch (_) {}
    throw new Error(detail);
  }
  return resp.json();
}

// ---------------------------------------------------------------------------
// Verificação de e-mail
// ---------------------------------------------------------------------------
const emailForm = document.getElementById("email-form");
const emailResult = document.getElementById("email-result");

emailForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("email-input").value.trim();
  const btn = emailForm.querySelector("button[type=submit]");
  btn.disabled = true;
  emailResult.innerHTML = `<p><span class="spinner"></span>Consultando fontes de vazamento…</p>`;
  try {
    const data = await postJSON(API.email, { email });
    emailResult.innerHTML = renderEmailResult(data);
  } catch (err) {
    emailResult.innerHTML = `<p class="error">⚠ ${esc(err.message)}</p>`;
  } finally {
    btn.disabled = false;
  }
});

function renderEmailResult(d) {
  const demo = d.is_demo
    ? `<span class="demo-flag">⚠ DADOS FICTÍCIOS (modo demonstração)</span>`
    : "";

  const header = d.breached
    ? `<div class="status-card breached">
         ${demo}
         <h2>E-mail comprometido</h2>
         <div class="big">${d.breach_count} vazamento${d.breach_count > 1 ? "s" : ""}
           <span class="risk-pill risk-${esc(d.risk_level)}">${RISK_LABEL[d.risk_level] || d.risk_level}</span>
         </div>
         <p>${esc(d.email)} apareceu em vazamentos de dados conhecidos.</p>
         ${renderExposed(d.exposed_data)}
       </div>`
    : `<div class="status-card safe">
         ${demo}
         <h2>Nenhum vazamento encontrado ✓</h2>
         <div class="big">Limpo</div>
         <p>${esc(d.email)} não foi encontrado nas fontes consultadas
            (${esc((d.sources_queried || []).join(", ") || "nenhuma")}).</p>
       </div>`;

  const breaches = (d.breaches || []).map(renderBreach).join("");
  const notes = (d.notes || []).length
    ? `<ul class="notes">${d.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`
    : "";

  return header + breaches + notes;
}

function renderExposed(list) {
  if (!list || !list.length) return "";
  return `<div class="exposed-tags">${list
    .map((x) => `<span>${esc(x)}</span>`)
    .join("")}</div>`;
}

function renderBreach(b) {
  const meta = [
    b.breach_date ? `📅 ${esc(b.breach_date)}` : null,
    b.pwn_count != null ? `👤 ${fmtNumber(b.pwn_count)} contas` : null,
    b.domain ? `🌐 ${esc(b.domain)}` : null,
    b.is_verified === false ? `⚠ não verificado` : null,
  ]
    .filter(Boolean)
    .join(" ");

  const dataClasses = (b.data_classes || []).length
    ? `<div class="exposed-tags">${b.data_classes
        .map((x) => `<span>${esc(x)}</span>`)
        .join("")}</div>`
    : "";

  return `<div class="breach">
    <h3>${esc(b.title || b.name)} <span class="source-tag">${esc(b.source)}</span></h3>
    <div class="meta">${meta}</div>
    ${b.description ? `<p>${esc(b.description)}</p>` : ""}
    ${dataClasses}
  </div>`;
}

// ---------------------------------------------------------------------------
// Verificação de senha
// ---------------------------------------------------------------------------
const passForm = document.getElementById("password-form");
const passResult = document.getElementById("password-result");
const passInput = document.getElementById("password-input");

document.getElementById("toggle-pass").addEventListener("click", () => {
  passInput.type = passInput.type === "password" ? "text" : "password";
});

passForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const password = passInput.value;
  const btn = passForm.querySelector("button[type=submit]");
  btn.disabled = true;
  passResult.innerHTML = `<p><span class="spinner"></span>Verificando via k-anonimato…</p>`;
  try {
    const data = await postJSON(API.password, { password });
    passResult.innerHTML = renderPasswordResult(data);
  } catch (err) {
    passResult.innerHTML = `<p class="error">⚠ ${esc(err.message)}</p>`;
  } finally {
    btn.disabled = false;
  }
});

function renderPasswordResult(d) {
  const demo = d.is_demo
    ? `<span class="demo-flag">⚠ MODO DEMONSTRAÇÃO</span>`
    : "";
  const cls = d.pwned ? "breached" : "safe";
  const head = d.pwned
    ? `<h2>Senha comprometida</h2>
       <div class="big">${fmtNumber(d.count)}×</div>
       <p>Esta senha apareceu <strong>${fmtNumber(d.count)}</strong> vezes em vazamentos conhecidos.</p>`
    : `<h2>Senha não encontrada ✓</h2>
       <div class="big">0×</div>
       <p>Esta senha não consta nos vazamentos indexados.</p>`;

  return `<div class="status-card ${cls}">
    ${demo}
    ${head}
    <p class="privacy-note">
      🔒 Apenas o prefixo <code>${esc(d.prefix_sent)}</code> do hash SHA-1 foi
      enviado à API (${esc(d.method)}). A senha em si nunca saiu do servidor.
    </p>
    <ul class="notes"><li>${esc(d.advice)}</li></ul>
  </div>`;
}

// ---------------------------------------------------------------------------
// Conteúdo educacional (renderizado sob demanda)
// ---------------------------------------------------------------------------
let learnRendered = false;
function renderLearn() {
  if (learnRendered) return;
  document.getElementById("learn-content").innerHTML = LEARN_HTML;
  learnRendered = true;
}

// O conteúdo abaixo é preenchido a partir da pesquisa acadêmica do projeto.
// Ver docs/METHODOLOGY.md para as fontes completas.
const LEARN_HTML = `
  <h2>Como esta aplicação funciona</h2>
  <p class="lead">
    O DarkChecker não invade nem raspa a dark web. Ele consulta serviços de
    segurança que já <strong>indexaram vazamentos publicamente conhecidos</strong>
    de forma ética e legal. Abaixo, a metodologia e o contexto acadêmico.
  </p>

  <h3>1. Verificação de e-mail</h3>
  <p>
    Enviamos o e-mail a APIs legítimas (XposedOrNot, gratuita; e opcionalmente
    o Have I Been Pwned) que respondem <em>apenas os metadados</em> dos
    vazamentos em que ele aparece: nome do serviço, data e quais
    <em>categorias</em> de dado foram expostas. Essas APIs <strong>não</strong>
    devolvem senhas nem dados pessoais — é essa abstração que as torna
    ferramentas defensivas e legais.
  </p>

  <h3>2. Verificação de senha por k-anonimato</h3>
  <p>
    Para checar uma senha sem nunca enviá-la, usamos a técnica de
    <strong>k-anonimato</strong> do <code>Pwned Passwords</code>:
  </p>
  <ol>
    <li>Calculamos o hash <code>SHA-1</code> da senha.</li>
    <li>Enviamos à API <strong>somente os 5 primeiros caracteres</strong> do hash.</li>
    <li>A API devolve <em>todos</em> os sufixos que começam com esse prefixo (centenas).</li>
    <li>A comparação final é feita localmente. A API nunca sabe qual senha você testou.</li>
  </ol>
  <blockquote>
    Endpoint gratuito: <code>https://api.pwnedpasswords.com/range/{prefixo}</code>
  </blockquote>

  <h2>Do vazamento à dark web: o ciclo de vida do dado</h2>
  <div class="flow-diagram">
    <div class="flow-step"><span class="icon">💥</span>Vazamento na empresa</div>
    <span class="flow-arrow">→</span>
    <div class="flow-step"><span class="icon">📦</span>Dump / combolist</div>
    <span class="flow-arrow">→</span>
    <div class="flow-step"><span class="icon">🏴‍☠️</span>Venda em fóruns / Telegram</div>
    <span class="flow-arrow">→</span>
    <div class="flow-step"><span class="icon">🔁</span>Credential stuffing</div>
    <span class="flow-arrow">→</span>
    <div class="flow-step"><span class="icon">🛡️</span>Agregação ética (HIBP)</div>
  </div>
  <p>
    Quando uma empresa é comprometida, os dados viram <strong>dumps</strong> que
    são combinados em <strong>combolists</strong> (listas de e-mail:senha).
    Essas listas são vendidas ou trocadas em fóruns da dark web e canais de
    Telegram, e usadas em ataques de <strong>credential stuffing</strong> —
    testar automaticamente as mesmas credenciais em vários serviços, explorando
    a reutilização de senhas.
  </p>
  <p>
    Serviços legítimos de segurança monitoram esses mesmos vazamentos de forma
    ética (recebendo submissões de pesquisadores, feeds de threat intelligence e
    dados já tornados públicos) para <strong>avisar as vítimas</strong> — sem
    redistribuir o conteúdo roubado.
  </p>

  <h2>A linha ética e legal</h2>
  <blockquote>
    <strong>Por que não raspar a dark web?</strong> Acessar e baixar dumps de
    dados roubados configura acesso não autorizado e manuseio de dados obtidos
    ilicitamente — crime na maioria das jurisdições, inclusive no Brasil
    (Lei 12.737/2012 e Lei 14.155/2021), independentemente da intenção acadêmica.
  </blockquote>
  <p>
    A pesquisa de segurança fica do lado certo da lei ao trabalhar com os
    <em>metadados</em> e <em>indicadores</em> dos vazamentos — não com os dados
    roubados em si — e ao ter como objetivo <strong>proteger</strong> as vítimas.
    É exatamente essa a abordagem deste projeto: demonstrar a exposição sem
    reproduzir o crime.
  </p>

  <h2>Por que isso importa</h2>
  <p>
    O objetivo acadêmico deste trabalho é evidenciar que, uma vez que um dado
    circula, ele escapa ao nosso controle — a dark web é, de fato, um ambiente
    onde a lei tem alcance limitado. A defesa realista não é "sumir da internet",
    mas sim: <strong>senhas únicas por serviço, gerenciador de senhas e
    autenticação em dois fatores (2FA)</strong>, que quebram a cadeia do
    credential stuffing.
  </p>

  <p class="muted">
    As estatísticas e referências completas estão em
    <code>docs/METHODOLOGY.md</code> no repositório do projeto.
  </p>
`;

// Carrega estado da API (habilita mensagens sobre HIBP se configurado).
fetch("/api/health")
  .then((r) => r.json())
  .then((h) => {
    if (h.hibp_email_enabled) {
      console.info("HIBP habilitado — usando fonte paga além da gratuita.");
    }
  })
  .catch(() => {});
