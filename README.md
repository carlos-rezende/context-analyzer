# Context Analyzer

**Versão atual: 0.6.0** — ver [CHANGELOG.md](CHANGELOG.md).

Extensão Chrome/Edge (Manifest V3) para **análise passiva** e heurística de segurança: DOM, endpoints, cabeçalhos de resposta (somente leitura) e cookies `Set-Cookie` observados. **Não** altera pedidos nem executa payloads automaticamente.

### Gestor de pacotes

[pnpm](https://pnpm.io/)\*\* (`corepack enable` e `corepack prepare pnpm@9.15.4 --activate`, ou instalação global do pnpm). O lockfile é `pnpm-lock.yaml`.

## Funcionalidades (v0.6)

| Área                       | Descrição                                                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Análise DOM**            | Formulários, inputs suspeitos, pistas IDOR na URL, endpoints em links/scripts.                                                             |
| **Rede (somente leitura)** | Cabeçalhos de resposta do documento principal, `Set-Cookie`, heurísticas de segurança.                                                     |
| **Pedidos XHR**            | Últimos pedidos `xmlhttprequest` / `other` por separador; **replay manual** — botões _Copiar fetch_ e _Copiar cURL_ (corpo não observado). |
| **GraphQL**                | Indícios em URL, `Content-Type`, scripts e caminho da página.                                                                              |
| **JWT**                    | Padrão JWT-like em `localStorage` / `sessionStorage` (metadados apenas; token completo não é exportado).                                   |
| **CSP**                    | Parser de diretivas além das ausências básicas (unsafe-inline/eval, frame-ancestors, object-src, etc.).                                    |
| **Pontuação**              | `severityScore` 0–100 no painel, derivado das severidades dos achados.                                                                     |
| **Exportação**             | Botão **Exportar JSON** com o agregado atual do separador.                                                                                 |
| **Badge**                  | Contador no ícone da extensão por separador (número de achados, máx. 99).                                                                  |
| **Definições**             | IA opcional (HTTPS seu), nível de detalhe compacto/normal.                                                                                 |

## Melhorias futuras (opcional)

- `optional_host_permissions` em vez de `<all_urls>` fixo em ambientes restritos.
- Testes do service worker / content / painel; ícones próprios em resolução real (substituir placeholders em `public/icons/`).

## Desenvolvimento

```bash
pnpm install
pnpm run build
```

Carregue a pasta `dist` em `chrome://extensions` → **Modo de programador** → **Carregar sem compactação**.

## Testes automatizados

```bash
pnpm test
```

Os testes usam **Vitest** em Node: apenas funções puras e DOM simulado (`happy-dom`), **sem** rede, **sem** browser real, **sem** Playwright/Puppeteer e **sem** binários de teste de intrusão — perfil pensado para reduzir ruído em antivírus e heurísticas de segurança do SO.

## Permissões (justificativa resumida)

| Permissão    | Uso                                                                                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `storage`    | Definições (IA opcional, preferências).                                                                                               |
| `activeTab`  | Contexto do separador quando relevante.                                                                                               |
| `scripting`  | Compatível com injeção controlada pelo manifest.                                                                                      |
| `sidePanel`  | Painel lateral da UI.                                                                                                                 |
| `webRequest` | Observação **somente leitura** de cabeçalhos de resposta (`responseHeaders`).                                                         |
| `tabs`       | Associar achados ao separador ativo e atualizar ao mudar de separador.                                                                |
| `<all_urls>` | Analisar pedidos e conteúdo em páginas visitadas (escopo amplo; avalie reduzir a `optional_host_permissions` em ambientes restritos). |

## IA opcional

Ative nas definições do painel e configure um **endpoint HTTPS seu**. O cliente envia apenas metadados (caminhos de URL, nomes de parâmetros, resumos de achados, nomes de cabeçalhos observados). **Não** envia cookies, tokens, HTML completo nem corpo de pedidos.

O servidor deve responder JSON com `suggestion` ou `message` (texto da sugestão).

## Estrutura

- `src/background` — service worker, `webRequest`, buffer de pedidos, badge, agregação e mensagens.
- `src/content` — leitura DOM com debounce e `requestIdleCallback` quando disponível.
- `src/core` — heurísticas (IDOR, endpoints, headers, cookies, inputs, GraphQL, JWT, CSP avançado, pontuação).
- `src/integration` — conversão de eventos `webRequest` para payloads de análise.
- `src/sidepanel` — UI (achados, endpoints, rede, export, definições).
- `src/ai` — cliente opcional e construção de contexto permitido.
- `src/data` — `chrome.storage.local` para definições.
- `src/shared` — tipos, contratos de mensagem, snippets de replay.
