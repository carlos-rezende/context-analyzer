# Changelog

Todas as alterações notáveis deste projeto serão documentadas aqui.

O formato segue o espírito de [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/), e o versionamento segue [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [0.6.1] — 2026-03-31

### Adicionado

- Referências **CWE** / **OWASP** nos achados; catálogo em `shared/weakness`.
- Exportação **HAR**, JSON estilo **Burp** e esqueleto **YAML Nuclei** (`shared/export-tools`).
- Sugestões **XSS** para teste manual (`shared/xss-hints`); deteção de `import()` dinâmico em endpoints.
- Testes unitários: scoring, CSP avançado, GraphQL, JWT.
- `LICENSE` MIT; `author` e licença em `package.json`.
- Script `pnpm run pack`: gera `context-analyzer-vX.Y.Z.zip` (versão do `package.json`) a partir de `dist/` (Chrome Web Store).

### Alterado

- README e `manifest.json`: texto non-intrusive, privacidade e MV3 alinhados à loja.

## [0.6.0] — 2026-03-31

### Adicionado

- Extensão MV3 **Context Analyzer**: análise passiva (DOM, cabeçalhos, cookies observados).
- Heurísticas: IDOR, endpoints, inputs, headers de segurança, cookies `Set-Cookie`.
- GraphQL (URL, `Content-Type`, scripts), JWT-like em `localStorage`/`sessionStorage` (sem exportar tokens).
- CSP com parser de diretivas além das verificações básicas.
- Pontuação de severidade (0–100), export JSON dos achados, badge no ícone por separador.
- Pedidos XHR observados com cópia **fetch** / **cURL** para replay manual.
- Painel lateral, IA opcional (endpoint HTTPS configurável), nível de detalhe compacto/normal.
- Ícone da extensão em `public/icons/context-analyzer.png`; build com Vite + `@crxjs/vite-plugin`.
- Dependências com **pnpm** (`pnpm-lock.yaml`).

### Notas

- Não altera pedidos nem executa payloads automaticamente.
