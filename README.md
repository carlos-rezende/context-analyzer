# Context Analyzer

[![Version](https://img.shields.io/badge/version-0.6.1-blue)](CHANGELOG.md)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-green)](https://developer.chrome.com/docs/extensions/mv3/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Build](https://img.shields.io/badge/build-Vite-purple)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-Vitest-yellow)](https://vitest.dev/)
[![Passive](https://img.shields.io/badge/analysis-passive-success)](https://developer.chrome.com/docs/extensions/mv3/)
[![Chrome](https://img.shields.io/badge/Chrome-supported-brightgreen)](https://www.google.com/chrome/)
[![Edge](https://img.shields.io/badge/Edge-supported-brightgreen)](https://www.microsoft.com/edge)

**Versão atual: 0.6.1** — ver [CHANGELOG.md](CHANGELOG.md).

Extensão Chrome/Edge para **análise passiva** de contexto e heurísticas de segurança: DOM, endpoints, cabeçalhos de resposta (somente leitura) e cookies `Set-Cookie` observados.

- **Non-intrusive:** só observação passiva; **não gera pedidos HTTP automatizados** (nem fuzz, nem crawler, nem replay automático).  
  *Non-intrusive passive analysis only. No automated requests are generated.*
- **Manifest V3 compliant** — [Manifest V3](https://developer.chrome.com/docs/extensions/mv3/).
- **Privacidade:** por defeito, **nenhum dado sai do browser**. Só se ativar a IA opcional e definir um endpoint HTTPS é que metadados (sem credenciais) são enviados ao servidor que configurar.  
  *No data leaves the browser unless optional AI endpoint is configured.*

---

## Funcionalidades

- Análise passiva do DOM (formulários, inputs, pistas IDOR, endpoints em HTML/JS, `import()` dinâmico)
- Endpoints e pedidos observados (DOM + rede)
- Headers de segurança, CSP avançado, cookies `Set-Cookie`
- Deteção JWT (metadados em storage), indícios GraphQL
- Pontuação de severidade (0–100), referências **CWE** / **OWASP**
- Exportação: JSON, HAR, JSON estilo Burp, esqueleto YAML Nuclei
- Sugestões XSS para **teste manual** (a extensão não envia payloads)
- IA opcional (HTTPS seu)
- Badge no ícone por separador

---

## Segurança

| Princípio | Detalhe |
|-----------|---------|
| Modo | Análise **passiva** — não altera pedidos nem executa payloads automaticamente |
| Dados | Por defeito não envia dados para servidores externos |
| IA | Opt-in; só metadados (caminhos, parâmetros, nomes de headers, resumos de achados) |
| Loja | Compatível com políticas típicas da Chrome Web Store |

A IA **nunca** envia: cookies, tokens, HTML completo nem corpo de pedidos.

---

## Arquitetura

```
src/
├── background/   # service worker, webRequest, agregação
├── content/      # leitura DOM (debounce)
├── core/         # heurísticas (IDOR, endpoints, headers, CSP, GraphQL, JWT, scoring)
├── integration/  # payloads a partir de webRequest
├── sidepanel/    # UI
├── ai/           # cliente opcional
├── data/         # definições (chrome.storage.local)
└── shared/       # tipos, sanitização, export HAR/Burp/Nuclei, hints XSS
```

---

## Desenvolvimento

### Gestor de pacotes

Utilize **[pnpm](https://pnpm.io/)** (`corepack enable` e `corepack prepare pnpm@9.15.4 --activate`, ou instalação global). Lockfile: `pnpm-lock.yaml`.

Após substituir `public/icons/context-analyzer.png` por um ficheiro muito grande, comprimir antes do build:

```bash
pnpm run optimize:icon
```

### Build

```bash
pnpm install
pnpm run build
```

Carregar a pasta **`dist`** em `chrome://extensions` → **Modo de programador** → **Carregar sem compactação**.

### Publicação (Chrome Web Store)

1. `pnpm run pack` — faz build e cria na raiz **`context-analyzer-vX.Y.Z.zip`** (conteúdo de `dist/`, pronto para upload).
2. [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole) → item da extensão → **Package** → carregar o ZIP.
3. Garantir que a **versão** no painel coincide com `manifest.json` / `package.json` (a loja exige incremento em cada envio).
4. Preencher **Privacy practices** com o mesmo texto da secção *Privacidade* deste README (dados locais; IA opcional com HTTPS configurado pelo utilizador).
5. Screenshots: tipicamente **1280×800** ou **640×400** px; ícone **128×128** já em `public/icons/`.

### Testes

```bash
pnpm test
```

**Vitest** em Node, com `happy-dom` — sem browser real, sem rede de testes automatizados de intrusão.

### Permissões

| Permissão | Uso |
|-----------|-----|
| `storage` | Definições (IA opcional, preferências) |
| `activeTab` | Contexto do separador quando relevante |
| `scripting` | Content scripts conforme manifest |
| `sidePanel` | Painel lateral |
| `webRequest` | Observação **somente leitura** de cabeçalhos de resposta |
| `tabs` | Associar achados ao separador ativo |
| `<all_urls>` | Analisar páginas visitadas (avaliar `optional_host_permissions` em ambientes restritos) |

### IA opcional

Configure um **endpoint HTTPS** nas definições do painel. O servidor deve responder JSON com `suggestion` ou `message`.

---

## Build (stack)

- TypeScript  
- Vite + `@crxjs/vite-plugin`  
- Manifest V3  
- pnpm  

---

## Licença

[MIT](LICENSE) — ver o ficheiro `LICENSE` na raiz do repositório.
