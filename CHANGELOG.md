# Changelog

Todas as alterações notáveis deste projeto serão documentadas aqui.

O formato segue o espírito de [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/), e o versionamento segue [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [0.6.0] — 2026-03-31

### Adicionado

- Extensão MV3 **Context Analyzer**: análise passiva (DOM, cabeçalhos, cookies observados).
- Heurísticas: IDOR, endpoints, inputs, headers de segurança, cookies `Set-Cookie`.
- GraphQL (URL, `Content-Type`, scripts), JWT-like em `localStorage`/`sessionStorage` (sem exportar tokens).
- CSP com parser de diretivas além das verificações básicas.
- Pontuação de severidade (0–100), export JSON dos achados, badge no ícone por separador.
- Pedidos XHR observados com cópia **fetch** / **cURL** para replay manual.
- Painel lateral, IA opcional (endpoint HTTPS configurável), nível de detalhe compacto/normal.
- Ícones de extensão (placeholders), build com Vite + `@crxjs/vite-plugin`.
- Gestão de dependências com **pnpm** (`pnpm-lock.yaml`); documentação sem `npm`.

### Notas

- Não altera pedidos nem executa payloads automaticamente.
