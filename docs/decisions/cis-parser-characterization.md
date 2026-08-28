# Caracterização dos PDFs CIS Debian/Ubuntu (Fase 1 do plano de validação do parser)

## Contexto

Plano completo: ver o histórico do agent Codex que escreveu `codexplan.md` (não versionado
neste repo). Fase 1 pede um relatório reprodutível cobrindo todo PDF Debian/Ubuntu local
disponível, sem inferências silenciosas, para então decidir com evidência se a Fase 5
(perfis editoriais por formato) é necessária.

## Método

`scripts/characterize_cis_pdfs.py` -- somente leitura, nunca escreve no banco, nunca
modifica um PDF. Reaproveita `_pdf_lines()` / `_find_headers()` / `_split_sections()` do
extractor diretamente (mesmo padrão que `tests/extractor/test_header_parsing.py` já usa)
em vez de chamar `extract_all_recommendations()` e extrair o texto bruto de novo
separadamente -- extração de texto é a parte cara (~20-30s nos PDFs maiores), e fazer isso
duas vezes por documento estourou o orçamento de tempo do ambiente de execução em background
na primeira tentativa.

Também incluiu o Debian 13 v1.1.0, publicado por CIS em 2026-08-27 (descoberto rodando
`CIS().discover_benchmarks()` ao vivo) -- a versão local anterior era 1.0.0.

Rodar: `.venv/bin/python scripts/characterize_cis_pdfs.py`
Saída: `docs/cis_characterization_report.json` (18 documentos, versionado neste commit).

## Resultado

- **18/18 documentos processados sem erro.**
- **0 IDs duplicados** em qualquer documento.
- **0 campos obrigatórios vazios** (`external_id`/`title`/`description`/`audit`/`remediation`)
  em qualquer documento.
- `rationale` vazio em alguns itens de documentos mais novos (vocabulário
  Automated/Manual): debian_12 (1.2.1.3, 1.2.1.4), debian_13 v1.0.0 (1.2.1.3, 1.2.1.4),
  debian_13 v1.1.0 (1.2.1.4), ubuntu_22_04_stig (1.133), ubuntu_24_04 (1.2.1.3, 1.2.1.4),
  ubuntu_24_04_stig (1.150). Confirma a observação já registrada no plano ("alguns
  Rationale vazios") -- não é regressão, é o próprio documento fonte.
- Vocabulário de scoring: `Scored`/`Not Scored` nos documentos mais antigos (debian_10
  v1.0.0, debian_9, ubuntu_12_04, ubuntu_14_04), `Automated`/`Manual` nos mais novos;
  ubuntu_16_04 mistura os dois. O parser já trata ambos via `_SCORED_TERMS` -- nenhuma
  ação necessária.
- Debian 13 v1.1.0 processa sem erro: 350 recomendações, 1156 páginas, 23.3s.
- **Debian 11 STIG não é anormalmente lento por si só.** A extração completa (single-pass,
  sem instrumentação) leva ~30s, na mesma faixa dos outros documentos de tamanho
  parecido. O "custo significativamente maior" observado na validação exploratória
  anterior era o instrumento de medição, não o documento: a primeira versão deste script
  usava `tracemalloc` para medir pico de memória, que mediu 194s para este PDF contra 31s
  sem tracemalloc (6x de overhead, confirmado isolando a chamada). Trocado por
  `resource.getrusage().ru_maxrss` (custo ~zero, é só ler um contador do SO). Nenhum
  documento desta bateria excedeu ~31s de extração de ponta a ponta.
- Evidência independente de contagem:
  - A única contagem verificada por humano no repo (Debian 10 v1.0.0 = 235, de
    `tests/extractor/test_extractor.py`) bate exatamente.
  - Heurística "quantas vezes o rótulo `Description:` aparece no texto bruto" bate
    exatamente em 14/18 documentos; diverge por 1 em 3 (debian_11_stig, ubuntu_20_04,
    ubuntu_20_04_stig) e por 7 em ubuntu_12_04.
  - Investigado o caso ubuntu_12_04 (o maior desvio): o excesso vem de recomendações cujo
    corpo atravessa múltiplas páginas -- este PDF reimprime
    "Profile Applicability: / Description:" como cabeçalho de continuação em cada página
    subsequente da mesma recomendação, então a heurística (que só conta ocorrências do
    rótulo) conta o mesmo rótulo várias vezes por recomendação. Isso é uma limitação
    conhecida da heurística (já documentada como tal no próprio script) -- não é evidência
    de recomendações perdidas: `_find_headers` encontrou exatamente 180 cabeçalhos reais,
    0 duplicados, e a âncora `Profile Applicability:` continua sendo suficiente para
    distinguir um cabeçalho real de um cabeçalho de continuação de página.

## Achado colateral para a Fase 4 (não corrigido nesta etapa -- é robustez de parser, não caracterização)

`_split_sections()` guarda o conteúdo de cada rótulo em um dict, e o `finditer` sobre o
texto concatenado sobrescreve a entrada quando o mesmo rótulo aparece mais de uma vez no
corpo. O cabeçalho de continuação de página do caso ubuntu_12_04 mostra que isso acontece
de verdade neste formato. Nesta bateria nenhum campo ficou *vazio* por causa disso (então
não é um buraco visível), mas em tese o *conteúdo* poderia ficar errado se o cabeçalho de
continuação vier depois do conteúdo real na ordem do texto extraído. Vale uma fixture
mínima na Fase 4 para travar o comportamento correto (manter a primeira ocorrência, não a
última).

## Decisão da Fase 5 (perfis editoriais)

A matriz de caracterização **não mostra divergência de layout real** entre Debian/Ubuntu
normal e STIG: os 18 documentos (2 vocabulários de scoring, 153 a 1280 páginas, normal e
STIG, 6 famílias de versão) foram extraídos pelo mesmo parser genérico com 0 IDs
duplicados e 0 campos obrigatórios vazios. A única variação observada (`rationale`
ocasionalmente vazio) é um estado de **dado** legítimo do documento fonte, não uma
diferença de **formato** -- o parser já lida com isso corretamente (campo fica string
vazia, nada quebra).

**Decisão: não construir perfis editoriais (`legacy`/`modern`/`stig`) nesta etapa.** Não
há evidência que justifique a complexidade -- construir isso agora seria design para um
requisito hipotético, contrariando o princípio de arquitetura do próprio plano ("não criar
parsers por distribuição sem evidência de formatos diferentes").

Isso fica como **decisão em aberto**, não uma adivinhação: se um documento futuro (uma
família nova, ou uma versão STIG com estrutura visivelmente diferente -- por exemplo, se
Debian 11 STIG tivesse de fato se mostrado estruturalmente distinto, e não apenas com mais
páginas) mostrar divergência real, revisitar com uma fixture mínima provando a
necessidade, exatamente como a Fase 5 do plano exige.

## O que foi construído em cima dessa evidência (Fases 2, 3, 4 e 6)

Commits separados, um por fase, no mesmo branch:

- **Fase 2 (contrato fail-closed)**: `extractor.extract_and_validate()` recusa (nunca
  persiste parcialmente) um documento sem nenhuma recomendação, com IDs duplicados, ou
  com um campo obrigatório (`external_id`/`title`/`description`/`audit`/`remediation`)
  vazio -- todos com 0 ocorrências reais nos 18 documentos desta caracterização, então
  tratados como falha real, não normalização silenciosa. `rationale` vazio é aviso, não
  falha (ocorre de verdade, ver acima). `invariant.cli.extract` ganhou também uma
  verificação de regressão de contagem contra a `document_version` anterior do mesmo
  documento, e rollback explícito em qualquer falha.
- **Fase 3 (proveniência por página)**: `source_page_start`/`source_page_end` em cada
  `ExtractedRecommendation`, propagados para `extracted_items.raw_data`.
- **Fase 4 (robustez)**: achado real ao ligar os campos preservados (`Default
  Value`/`References`/`CIS Controls`/`Impact`) -- a última recomendação de um documento
  não tinha cabeçalho seguinte para limitar seu corpo, então absorvia o apêndice inteiro
  (confirmado: ~17KB do apêndice "Change History" dentro do campo CIS Controls da
  recomendação 6.2.20 do Debian 10 v1.0.0, e o intervalo de páginas dela ia até a última
  página do documento). Corrigido cortando o corpo antes de qualquer linha
  `Appendix: <nome>` -- confirmado em 3 documentos reais antes de virar a regra. Também
  adicionado orçamento de tempo (120s, 4x acima do medido) para a extração do Debian 11
  STIG na suíte de testes.
- **Fase 6 (integração)**: `invariant extract` aceita qualquer `document_slug` já
  baixado, não só chaves de `KNOWN_CIS_DOCUMENTS`; `document_versions.parser_version` é
  persistido (`extractor.PARSER_VERSION`), independente de `publisher_version`. Não há
  hoje nenhum "pular se já processado" em `invariant extract` para o item 3 do plano
  (reprocessar quando o parser mudar) precisar contornar -- todo `extract` já reprocessa
  por completo, então a mudança de parser já é capturada automaticamente na próxima
  execução, sem código adicional.

`pytest tests/extractor tests/cli/test_extract.py -q -m "not integration"`: 30 passed.
`pytest -m "not integration" -q`: 406 passed.
