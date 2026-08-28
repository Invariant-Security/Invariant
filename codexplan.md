# Plano Codex: collector e parser CIS

## Objetivo

Concluir uma vertical confiável de coleta e extração dos PDFs Debian Linux e Ubuntu Linux publicados em `downloads.cisecurity.org`, preservando a cadeia:

```text
Source -> Document -> Document Version -> Raw Artifact/hash/timestamp
       -> Extracted Item + páginas de origem
```

O collector dinâmico está implementado na branch `feat/cis-crawler`. Os passos abaixo tratam da validação e evolução do parser antes do merge/push final do conjunto collector + parser.

## Estado observado

O parser atual é genérico para o layout CIS e não contém branches específicas para Debian, Ubuntu ou STIG. Entretanto, ele assume:

- títulos com IDs numéricos de 2 a 5 segmentos;
- sufixos `Scored`, `Not Scored`, `Automated` ou `Manual`;
- seção `Profile Applicability` logo após o título;
- labels de seção fixos em inglês;
- no máximo três linhas adicionais em títulos quebrados;
- extração integral do PDF em memória;
- ausência de proveniência por página na saída.

A cobertura integral existente usa Debian 10 v1.0.0. Validações exploratórias também funcionaram para Debian 10 v2.0, Debian 11 v2.0, Ubuntu 24.04 v2.0 e Ubuntu 24.04 STIG v1.0, com alguns `Rationale` vazios. Debian 11 STIG apresentou custo de extração significativamente maior e precisa de investigação isolada.

## Princípio de arquitetura

Não criar parsers por distribuição sem evidência de formatos diferentes. Debian e Ubuntu normais já compartilham o mesmo layout. Usar um núcleo CIS comum e introduzir perfis somente quando a matriz comprovar diferenças editoriais:

```text
CISExtractor
├── detector de formato
├── leitura de páginas
├── parser comum de cabeçalhos e seções
├── perfil legacy
├── perfil modern
└── perfil STIG, se necessário
```

A seleção deve ocorrer por características do documento, não pelo nome da distro.

## Fase 1 — Matriz de caracterização

1. Catalogar todos os PDFs Debian/Ubuntu locais por:
   - documento e versão;
   - normal ou STIG;
   - quantidade de páginas;
   - vocabulário de scoring;
   - quantidade de recomendações extraídas;
   - IDs duplicados;
   - campos obrigatórios vazios;
   - tempo total e pico aproximado de memória.
2. Incluir a versão nova Debian 13 v1.1.0 descoberta pelo crawler.
3. Comparar a contagem extraída com uma evidência independente do próprio PDF, quando disponível.
4. Registrar diferenças reais de layout antes de criar qualquer perfil especializado.

Critério de conclusão: relatório reproduzível cobrindo todos os PDFs disponíveis, sem inferências silenciosas.

## Fase 2 — Contrato e validação fail-closed

1. Definir quais campos são obrigatórios por recomendação:
   - `external_id`;
   - `title`;
   - `profile_applicability`;
   - `description`;
   - `rationale` quando presente no formato;
   - `audit`;
   - `remediation`;
   - páginas de origem.
2. Representar avisos e erros de extração explicitamente.
3. Falhar o documento quando:
   - nenhuma recomendação for encontrada;
   - houver IDs duplicados;
   - seções obrigatórias desaparecerem acima do limite aceito;
   - a contagem cair de maneira incompatível com a versão anterior;
   - o formato não puder ser identificado com segurança.
4. Não normalizar nem persistir silenciosamente uma extração inválida.

Critério de conclusão: documentos incompatíveis produzem erro explicável, nunca sucesso parcial indistinguível.

## Fase 3 — Proveniência por página

1. Processar o PDF página a página, sem concatenar primeiro todo o documento.
2. Manter para cada recomendação:
   - `source_page_start`;
   - `source_page_end`;
   - opcionalmente trechos/hashes de evidência textual.
3. Garantir que recomendações quebradas entre páginas sejam reconstruídas sem perder a origem.
4. Propagar essa informação até `extracted_items.raw_data`.

Critério de conclusão: qualquer campo extraído pode ser revisado no intervalo exato de páginas do artefato identificado pelo SHA-256.

## Fase 4 — Robustez do parser comum

1. Separar leitura do PDF, detecção de cabeçalhos e divisão de seções.
2. Tornar limites de título e padrões de ID configuráveis por perfil, mantendo defaults restritivos.
3. Evitar que sumário, checklist e apêndices sejam classificados como recomendações.
4. Encerrar corretamente o corpo da última recomendação antes de apêndices.
5. Preservar também, sem normalizar:
   - `Default Value`;
   - `References`;
   - `CIS Controls`;
   - `Impact`.
6. Investigar o desempenho do Debian 11 STIG e adicionar orçamento de tempo ao teste.

Critério de conclusão: todos os documentos suportados passam com IDs únicos, proveniência e campos completos dentro das exceções documentadas.

## Fase 5 — Perfis editoriais, somente se comprovados

1. Agrupar documentos por características observadas, não por distro.
2. Implementar `legacy`, `modern` ou `stig` apenas para regras que realmente divergem.
3. Manter modelos de saída idênticos entre perfis.
4. Adicionar fixture mínima para cada diferença estrutural.

Critério de conclusão: nenhuma regra duplicada por Debian/Ubuntu e cada especialização possui um PDF/fixture que prova sua necessidade.

## Fase 6 — Integração da esteira

1. Fazer `extract` aceitar qualquer documento descoberto pelo catálogo, removendo a versão como autoridade de `KNOWN_CIS_DOCUMENTS`.
2. Persistir `parser_version` separadamente de `publisher_version` e `collector_version`.
3. Garantir reprocessamento quando o parser mudar mesmo que o PDF não mude.
4. Executar:

```bash
pytest tests/extractor tests/cli/test_extract.py -q
pytest -m "not integration" -q
```

5. Rodar a matriz real de PDFs em job de integração separado.
6. Atualizar README e decisão arquitetural com limitações conhecidas.

Critério de conclusão: collector e parser funcionam ponta a ponta para todos os PDFs Debian/Ubuntu suportados, com evidência reproduzível.

## Fora de escopo desta etapa

- Normalização semântica nova.
- Geração automática de checks a partir de comandos CIS em texto livre.
- Novas famílias além de Debian e Ubuntu.
- Diff semântico e notificações.
- Push/merge final antes da revisão dos resultados do parser.

## Ordem imediata de execução

1. Criar o comando/script de caracterização somente leitura.
2. Rodar a matriz sobre os PDFs locais e Debian 13 v1.1.0.
3. Corrigir primeiro proveniência e fail-closed.
4. Corrigir gaps comprovados pelo relatório.
5. Decidir, com evidência, se STIG exige perfil próprio.
6. Rodar testes completos e revisar o diff collector + parser.
7. Só então concluir a publicação/merge da branch.
