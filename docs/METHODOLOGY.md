# Metodologia e Fundamentação Acadêmica

> Este documento reúne a metodologia técnica e o embasamento teórico do
> **DarkChecker**. Ele foi elaborado a partir de pesquisa em fontes primárias
> (documentação oficial de APIs, relatórios de segurança e material acadêmico)
> e serve de base para a redação da monografia/relatório do projeto.
>
> ⚠️ **Nota de verificação:** vários números e endpoints abaixo foram
> confirmados por fontes secundárias e trechos de busca, pois algumas páginas
> primárias bloquearam a coleta automatizada. Antes da citação final na
> monografia, **abra cada URL primária e confirme o dado no texto original** —
> especialmente preços, limites de taxa e as estatísticas de vazamentos, que
> mudam com frequência.

---

## 1. Como funciona a verificação (metodologia técnica)

O projeto combina duas capacidades técnicas distintas, que **não devem ser
confundidas**: a verificação de **e-mail** em vazamentos nomeados e a
verificação de **senha** por k-anonimato.

### 1.1. Verificação de e-mail (breaches)

O objetivo é responder: *"em quais vazamentos conhecidos este e-mail
apareceu?"*. As APIs consultadas devolvem **apenas metadados** — nome do
vazamento, data, e quais *categorias* de dado foram expostas — e **nunca**
senhas ou dados pessoais. É essa abstração que as torna ferramentas defensivas
e legais.

**Have I Been Pwned (HIBP) — endpoint pago:**

```
GET https://haveibeenpwned.com/api/v3/breachedaccount/{account}
```

- `{account}` é o e-mail **URL-encoded**.
- **Requer chave de API paga** (`hibp-api-key`) e um cabeçalho `user-agent`
  identificando a aplicação. `user-agent` ausente → HTTP 403; chave inválida →
  HTTP 401.
- Parâmetro `truncateResponse=false` retorna os objetos completos (por padrão,
  `true`, retorna só o `Name`).
- Códigos: `200` = vazamentos encontrados (array JSON); `404` = **nenhum
  vazamento** (tratar como "limpo", não como erro); `429` = limite de taxa
  (respeitar `Retry-After`).
- Campos do modelo *Breach*: `Name`, `Title`, `Domain`, `BreachDate`
  (`YYYY-MM-DD`), `PwnCount`, `Description` (HTML), `DataClasses` (array),
  `IsVerified`, `IsFabricated`, `IsSensitive`, entre outros.

**XposedOrNot — endpoint gratuito, sem chave** (fonte padrão do projeto):

```
GET https://api.xposedornot.com/v1/check-email/{email}          (resumo)
GET https://api.xposedornot.com/v1/breach-analytics?email={email} (detalhado)
```

Devolve os vazamentos em que o e-mail aparece com metadados (nome, ano, domínio,
categorias expostas, contagem de registros), sem expor credenciais.

### 1.2. Verificação de senha por k-anonimato (gratuita)

Para checar uma senha **sem nunca transmiti-la**, o projeto usa a API gratuita
**Pwned Passwords** do HIBP (host distinto, sem chave):

```
GET https://api.pwnedpasswords.com/range/{prefixo}
```

O mecanismo de **k-anonimato**:

1. Calcula-se localmente o **hash SHA-1** da senha (40 caracteres hex,
   maiúsculos).
2. Envia-se ao servidor **apenas os 5 primeiros caracteres** do hash (o
   *prefixo*).
3. O servidor devolve, em texto puro, **todos** os sufixos (35 caracteres
   restantes) que começam com aquele prefixo, no formato `SUFIXO:CONTAGEM`.
4. A comparação final é feita **localmente**: procuramos nosso próprio sufixo na
   lista. A senha e o hash completo **nunca saem** da aplicação.

O prefixo de 5 caracteres é compartilhado por centenas de hashes diferentes (o
"conjunto de anonimato"), então o servidor não consegue saber qual senha foi
consultada.

- **Padding:** o cabeçalho `Add-Padding: true` preenche a resposta com sufixos
  falsos de `CONTAGEM=0`, ocultando o tamanho real do resultado de um observador
  de rede. Ocorrências reais têm sempre `CONTAGEM >= 1`. *(A aplicação envia esse
  cabeçalho por padrão.)*

### 1.3. Gratuito vs. pago (resumo de endpoints)

| Serviço | URL | Gratuito? | Autenticação |
|---|---|---|---|
| Pwned Passwords (senha) | `https://api.pwnedpasswords.com/range/{prefixo}` | Sim | Nenhuma (user-agent recomendado) |
| XposedOrNot (e-mail) | `https://api.xposedornot.com/v1/check-email/{email}` | Sim | Nenhuma |
| HIBP breachedaccount (e-mail) | `https://haveibeenpwned.com/api/v3/breachedaccount/{account}` | **Não** | `hibp-api-key` + `user-agent` |

---

## 2. Fontes de dados legítimas (APIs que a aplicação pode usar)

A arquitetura recomendada consome APIs que retornam **apenas metadados**, de
modo que a aplicação **nunca manipula credenciais roubadas diretamente**.

| Serviço | Gratuito? | Auth? | Notas |
|---|---|---|---|
| **XposedOrNot** | Sim | Não | Open-source, REST/JSON. Só metadados. Limites relatados ~2 req/s e 100 req/dia por IP. **Usado por padrão neste projeto.** |
| **LeakCheck Public** | Sim | Não | `GET https://leakcheck.io/api/public?check={email}`. Devolve `sources` e `fields` (tipos expostos) sem a senha. |
| **HIBP Pwned Passwords** | Sim | Não | Verificação de senha por k-anonimato. **Usado por padrão neste projeto.** |
| **HIBP breachedaccount** | Não | Sim (chave paga) | Verificação de e-mail. Opcional; habilitado se houver `HIBP_API_KEY`. |
| **Mozilla Monitor** | Sim (site) | — | Serviço ao consumidor; **não** oferece API pública de terceiros. Usa dados do HIBP. |
| **Intelligence X** | Freemium | Sim | Motor OSINT que **expõe o conteúdo vazado real** → maior risco legal. **Não** recomendado para este projeto. |
| **DeHashed** | Não (pago) | Sim | Retorna registros vazados reais (incl. senhas). Listado só por completude. |
| **Google Dark Web Report** | — | — | **Descontinuado** (scanning parou em 2026-01-15; recurso removido em 2026-02-16). |
| **Google Password Checkup** | Sim | — | Verifica senhas **salvas** no Chrome/Google; **não** é API pública para e-mail arbitrário. |

> **Cautela:** endpoints, parâmetros e limites do XposedOrNot e do LeakCheck
> foram confirmados via READMEs no GitHub e trechos de busca (as docs oficiais
> retornaram 403 ao coletor automatizado). Verifique em
> `https://api.xposedornot.com/openapi.json` e
> `https://wiki.leakcheck.io/en/api/public` antes de finalizar.

---

## 3. Do vazamento à dark web: o ciclo de vida do dado

*(Descrição acadêmica do pipeline; não fornece instruções operacionais de
acesso a fóruns, mercados ou dumps.)*

**Estágio 1 — a violação.** O dado se origina de um comprometimento (SQL
injection, roubo de credenciais, malware *infostealer*, bancos mal
configurados, phishing, comprometimento de terceiros) ou de scraping massivo. O
conjunto exfiltrado é um **dump** (exportação bruta de banco) com e-mails,
senhas (hash ou texto puro), nomes e PII. Malware *infostealer* (ex.: família
Emotet) é um alimentador moderno importante.

**Estágio 2 — empacotamento em combolists.** Dumps brutos são limpos,
deduplicados e crackeados, e reempacotados em **combolists** — grandes arquivos
de pares `email:senha` agregados de muitos vazamentos. A **Collection #1**
(~773 milhões de e-mails / ~2,7 bilhões de linhas, catalogada pelo HIBP em 2019)
ilustra como muitos vazamentos são fundidos em um único produto otimizado para
credential stuffing.

**Estágio 3 — venda/distribuição.** Dados agregados são vendidos, trocados ou
despejados em fóruns e marketplaces. Segundo o DOJ, o **RaidForums** (2015)
vendeu acesso a mais de 10 bilhões de registros antes da apreensão em abril de
2022; o **BreachForums** surgiu como sucessor. Canais de **Telegram** são uma
camada paralela de distribuição.

**Estágio 4 — agregação (nos dois lados da linha).** Criminalmente, os dados
viram combolists cada vez maiores. **Legitimamente**, serviços de notificação e
firmas de threat intelligence indexam os mesmos dados para **avisar as
vítimas** — o espelho ético da agregação criminosa.

### Credential stuffing

Segundo a **OWASP**, credential stuffing é "a injeção automatizada de pares
roubados de usuário e senha em formulários de login, a fim de obter acesso
fraudulento a contas". É catalogado como ameaça automatizada **OAT-008** e
explora especificamente a **reutilização de senhas** entre serviços. As
**combolists** são a forma-commodity do dado de vazamento — a ponte entre o dump
bruto e o ataque automatizado. A orientação **NIST SP 800-63B** (limitar
tentativas, checar senhas contra corpora de vazamentos, favorecer senhas longas)
e o uso de **MFA/2FA** são as defesas padrão.

---

## 4. A linha ética e legal

### Por que rastrear (crawl) dumps da dark web é ilegal

Baixar, possuir ou redistribuir dumps de credenciais roubadas pode configurar
**acesso não autorizado** e **manuseio de dados obtidos ilicitamente**,
**independentemente** da intenção acadêmica, e perpetua o dano às vítimas.

- **EUA:** a *Computer Fraud and Abuse Act* (CFAA, 18 U.S.C. §1030) criminaliza
  o acesso "sem autorização"; o tráfico de dados roubados implica fraude de
  dispositivo de acesso e roubo de identidade (as acusações contra o
  administrador do RaidForums).
- **Brasil:** a **Lei 12.737/2012** ("Lei Carolina Dieckmann") tipificou a
  invasão de dispositivo informático, e a **Lei 14.155/2021** ampliou as penas.
  A **LGPD (Lei 13.709/2018)** impõe deveres sobre o tratamento de dados
  pessoais, inclusive os de origem ilícita.

Usar conjuntos de "origem ilícita" também levanta exposição de proteção de
dados, direitos autorais e violação contratual.

### Como pesquisadores e serviços permanecem legais

- **Firmas de threat intelligence** (Recorded Future, Flashpoint, DarkOwl,
  Searchlight) indexam serviços/fóruns **publicamente acessíveis** e vendem
  **feeds licenciados** — os clientes recebem alertas sobre suas próprias
  credenciais sem tocar em dados roubados.
- **Pesquisadores** ficam legais via (a) **divulgação coordenada (CVD)**;
  (b) **honeypots** (sistemas-isca que eles mesmos possuem); (c) análise de
  dados **legalmente fornecidos** ou já públicos; e (d) submissão de descobertas
  a agregadores em vez de redistribuir dumps.
- **O HIBP** não exige que ninguém rastreie a dark web: centraliza e normaliza
  os dados atrás de um serviço pesquisável, obtidos de organizações violadas, de
  submissões de pesquisadores e de forças da lei (o FBI e o NHTCU holandês
  forneceram ao HIBP dados do malware Emotet em abril de 2021).

### Aplicação a este projeto

Por consumir apenas APIs que retornam **metadados** (XposedOrNot, HIBP) e por
verificar senhas via **k-anonimato** (o segredo nunca sai do cliente), a
aplicação **nunca manipula, armazena nem redistribui credenciais roubadas** —
mantendo-se do lado legal e ético da linha. Demonstra-se a exposição **sem
reproduzir o crime**.

> **Escopo jurisdicional:** esta análise cita CFAA (EUA) e a legislação
> brasileira. Um tratamento acadêmico deve declarar seu escopo e citar o
> estatuto relevante do país em questão. Este material **não é aconselhamento
> jurídico**.

---

## 5. Números e fontes citáveis (para a monografia)

> Verifique cada número na URL primária antes da citação final; edições mais
> recentes (IBM 2025, DBIR 2026) podem substituir os valores abaixo.

- **Collection #1 (jan. 2019):** 772.904.991 e-mails únicos e 21 milhões de
  senhas únicas em texto puro (~2,7 bi de pares, ~87 GB), agregados de 2.000+
  vazamentos. — Troy Hunt, 2019.
- **Mother of All Breaches / MOAB (jan. 2024):** 26 bilhões de registros
  (~12 TB); majoritariamente compilação de vazamentos anteriores. — Cybernews,
  2024.
- **RockYou2024 (jul. 2024):** 9.948.575.739 senhas únicas em texto puro (maior
  compilação de senhas até a data). — Cybernews, 2024.
- **Custo médio global de um vazamento:** US$ 4,88 milhões em 2024 (+~10% a/a).
  — IBM *Cost of a Data Breach Report*, 2024.
- **Credenciais roubadas** foram o vetor de acesso inicial mais comum (~16% dos
  vazamentos) e levaram ~292 dias para conter. — IBM, 2024.
- **Uso de credenciais roubadas em vazamentos:** ~31–38% em 2024 (varia com a
  metodologia). — Verizon DBIR, 2024/2025.
- **Reúso de senhas:** no caso mediano, apenas ~49% das senhas de um usuário
  entre serviços eram distintas (≈51% de reúso). — Verizon DBIR, 2025.
- **Credential stuffing:** mediana de ~19% de todas as tentativas diárias de
  autenticação em provedores SSO; taxa de sucesso baixa (0,2%–2%), mas custo tão
  baixo que compensa. — Verizon DBIR, 2025.
- **Economia dos dados roubados:** cartão de crédito ~US$ 17–120/item; logins
  bancários ~US$ 65–150; "kit" completo de roubo de identidade ~US$ 1.000
  (preços anunciados, não garantidos). — Privacy Affairs, *Dark Web Price Index
  2023*.
- **Escala do HIBP:** indexa bilhões de contas de centenas de vazamentos
  (fundado em dez. 2013). O total **não é estável** — cite a figura ao vivo na
  homepage na data de acesso.

---

## Referências

- [Have I Been Pwned: API Documentation (v3)](https://haveibeenpwned.com/api/v3)
- [Have I Been Pwned — homepage](https://haveibeenpwned.com/)
- [Have I Been Pwned: FAQs](https://haveibeenpwned.com/FAQs)
- [HIBP: Subscription / API Key](https://haveibeenpwned.com/API/Key)
- [Troy Hunt: Understanding HIBP's Use of SHA-1 and k-Anonymity](https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/)
- [Troy Hunt: The 773 Million Record "Collection #1" Data Breach](https://www.troyhunt.com/the-773-million-record-collection-1-data-reach/)
- [Pwned Passwords Padding (Lava Lamps and Workers) — Cloudflare Blog](https://blog.cloudflare.com/pwned-passwords-padding-ft-lava-lamps-and-workers/)
- [Scanning for breached accounts with k-Anonymity — Mozilla Security Blog](https://blog.mozilla.org/security/2018/06/25/scanning-breached-accounts-k-anonymity/)
- [XposedOrNot API Documentation](https://xposedornot.com/api_doc)
- [XposedOrNot-API (GitHub)](https://github.com/XposedOrNot/XposedOrNot-API)
- [LeakCheck Public API documentation](https://wiki.leakcheck.io/en/api/public)
- [Mozilla Monitor FAQ](https://support.mozilla.org/en-US/kb/mozilla-monitor-faq)
- [Credential stuffing | OWASP Foundation](https://owasp.org/www-community/attacks/Credential_stuffing)
- [OAT-008 Credential Stuffing | OWASP Automated Threats](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-008_Credential_Stuffing)
- [United States Leads Dismantlement of RaidForums — U.S. DOJ](https://www.justice.gov/opa/pr/united-states-leads-dismantlement-one-worlds-largest-hacker-forums)
- [RaidForums Gets Raided, Alleged Admin Arrested — Krebs on Security](https://krebsonsecurity.com/2022/04/raidforums-get-raided-alleged-admin-arrested/)
- [BreachForums (Wikipedia)](https://en.wikipedia.org/wiki/BreachForums)
- [Computer Fraud and Abuse Act (Wikipedia)](https://en.wikipedia.org/wiki/Computer_Fraud_and_Abuse_Act)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Collection No. 1 (Wikipedia)](https://en.wikipedia.org/wiki/Collection_No._1)
- [Cybernews — Mother of All Breaches: 26 Billion Records](https://cybernews.com/security/billions-passwords-credentials-leaked-mother-of-all-breaches/)
- [Cybernews — RockYou2024: 10 billion passwords leaked](https://cybernews.com/security/rockyou2024-largest-password-compilation-leak/)
- [Privacy Affairs — Dark Web Price Index 2023](https://www.privacyaffairs.com/dark-web-price-index-2023/)
- [IBM — Cost of a Data Breach Report](https://www.ibm.com/reports/data-breach)
- [Verizon — 2024 DBIR (PDF)](https://www.verizon.com/business/resources/reports/2024-dbir-data-breach-investigations-report.pdf)
- [Verizon — 2025 DBIR (PDF)](https://www.verizon.com/business/resources/reports/2025-dbir-data-breach-investigations-report.pdf)

### Legislação brasileira citada

- Lei nº 12.737/2012 (Lei Carolina Dieckmann) — invasão de dispositivo informático.
- Lei nº 14.155/2021 — amplia penas para crimes cibernéticos.
- Lei nº 13.709/2018 (LGPD) — proteção de dados pessoais.
