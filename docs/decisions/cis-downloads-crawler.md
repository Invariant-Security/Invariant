# Crawler do catálogo público CIS Downloads

## Contexto

O fluxo inicial de `fetch` usava uma tabela de versões e labels criada para a quickdemo. Isso impedia detectar automaticamente novas publicações — por exemplo, Debian Linux 13 v1.1.0 apareceu no catálogo em 2026-08-27 enquanto a tabela ainda apontava para v1.0.0.

A página `https://downloads.cisecurity.org/#/` oferece downloads anônimos, mas seu catálogo JSON exige a sessão Laravel e o token CSRF criados pelo próprio frontend. Requisições HTTP isoladas aos endpoints retornam 401.

## Decisão

- Usar uma única sessão Chromium headless para abrir a página e executar os mesmos GETs same-origin usados por ela.
- Limitar a descoberta, por enquanto, aos produtos `Debian Linux` e `Ubuntu Linux`.
- Converter cada PDF anunciado em metadados explícitos: família, documento estável, versão do publisher, ID do documento, nome do arquivo, data de publicação e caminho Pardot.
- Fazer o download em seguida com `httpx`, usando o GET anônimo e o cookie `documentId` que o frontend usa. Playwright não transporta os bytes dos PDFs.
- Aceitar o artefato somente quando o servidor responder como PDF e o conteúdo começar com `%PDF`.
- Preservar cada resultado pelo SHA-256 já implementado no collector. O catálogo escolhe candidatos; o hash identifica o conteúdo real.

## Interface

- `invariant fetch cis`: baixa todos os PDFs Debian/Ubuntu exibidos no catálogo, incluindo versões diferentes ainda publicadas.
- `invariant fetch <documento>`: descobre o catálogo e baixa somente a maior versão semântica daquele documento.

`KNOWN_CIS_DOCUMENTS` continua temporariamente como registro de nomes aceitos por extract/import/assessment, mas sua versão não controla mais o download.

## Consequências

- Novas versões passam a ser encontradas sem alteração de código.
- Reexecuções são seguras: conteúdo idêntico resolve para o mesmo caminho content-addressed.
- O crawler depende da estrutura e dos endpoints internos do frontend público, que não são uma API contratada. O teste de integração de descoberta deve sinalizar mudanças nesse contrato.
- Chromium precisa estar instalado para descoberta; o download em si continua sendo HTTP comum.
- O uso e a distribuição dos PDFs devem respeitar os termos do CIS; o crawler não remove essa responsabilidade.
