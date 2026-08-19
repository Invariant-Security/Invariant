# Invariant — BXSEC Demo & Outreach Plan

> Plano para preparar uma demo funcional do Invariant para a BXSEC sem alterar o escopo do PRD. A demo é uma vertical slice destinada a gerar oportunidades de **contratação**, **prestação de serviço** e **colaboração open source**.

## 1. Objetivo

A BXSEC não precisa provar que o Invariant está pronto. Precisa provar que:

- o projeto existe;
- existe um problema real;
- há direção técnica;
- já existe software funcionando;
- você entende o que está construindo;
- existe espaço para colaboração;
- existe potencial comercial.

A pergunta que a demo deve provocar é:

> **"Como eu posso me envolver com esse projeto ou com essa pessoa?"**

## 2. O que NÃO fazer

A demo não altera o PRD e não deve virar:

- scanner AWS completo;
- dashboard;
- Kubernetes;
- CVSS completo;
- integração com todas as fontes;
- Telegram;
- SaaS;
- arquitetura definitiva.

O PRD continua sendo o roadmap. A BXSEC recebe apenas uma demonstração prática de uma parte do sistema.

## 3. Estratégia da demo

Usar quatro ambientes Linux em Docker:

```text
                 INVARIANT
                    │
          Knowledge / Controls
                    │
                    ▼
              Linux targets
                    │
                    ▼
            Evidence Collector
                    │
                    ▼
              Assessment
                    │
                    ▼
                Findings
                    │
                    ▼
       Source / Control / Evidence
```

Isso deixa a demo local, rápida, repetível e independente de credenciais AWS.

## 4. Quatro targets

### Target 01 — Baseline

Ambiente relativamente correto.

Objetivo: mostrar que o Invariant também consegue produzir `PASS`.

### Target 02 — SSH

Uma ou duas configurações propositalmente inseguras relacionadas a SSH. A configuração exata deve ser escolhida de acordo com o controle/documentação realmente utilizado.

### Target 03 — Permissions

Permissões de arquivos/configurações propositalmente inadequadas.

Objetivo: demonstrar que o Invariant trabalha com **misconfigurations / control violations**, não apenas CVEs.

### Target 04 — Multiple Findings

Combinação dos problemas anteriores.

Objetivo: mostrar múltiplos findings em um único ambiente.

## 5. Resultado visual

Exemplo de formato, sem inventar números:

```text
$ invariant assess

Invariant Assessment
────────────────────────────────────────

Targets scanned: 4

container-01    ✓ 0 findings
container-02    ⚠ 2 findings
container-03    ⚠ 1 finding
container-04    ✗ 5 findings

────────────────────────────────────────
Total findings: 8
```

Os números acima são apenas ilustrativos; a implementação deve mostrar resultados reais.

## 6. O ponto mais importante

Não parar em:

```text
HIGH
SSH insecure
```

Mostrar a cadeia:

```text
Finding
   ↓
Control
   ↓
Source
   ↓
Document Version
   ↓
Evidence
```

Exemplo:

```text
Finding: INVARIANT-LNX-001

Status: FAIL

Control:
<controle real>

Severity:
<severity real da fonte, quando aplicável>

Evidence:
<evidência real>

Source:
<fonte real>

Document version:
<versão real>
```

Mensagem central:

> **O Invariant não quer apenas dizer que algo está errado. Quer mostrar por que acredita que está errado e de onde veio essa conclusão.**

## 7. Finding ≠ automaticamente vulnerabilidade

Preferir:

- finding;
- security finding;
- misconfiguration;
- control violation;
- assessment result.

Evitar chamar automaticamente todo resultado de "vulnerabilidade". Isso reforça **Evidence over assumptions**.

## 8. Demo em dois atos

### Ato 1 — Produto

```text
Docker
 ↓
4 Linux environments
 ↓
Invariant
 ↓
Assessment
 ↓
Findings
```

Tempo alvo: **2–4 minutos**.

### Ato 2 — Engenharia

Mostrar brevemente:

```text
collector
   ↓
evidence
   ↓
control
   ↓
assessment
   ↓
finding
```

Explicar uma ou duas decisões, sem tour pelo repositório inteiro.

Tempo alvo: **3–5 minutos**.

# 9. Pitch do Invariant

## Pitch de 30 segundos

> **"O Invariant é um projeto open source que estou construindo para transformar referências técnicas de segurança e infraestrutura em uma base de conhecimento versionada e, posteriormente, em assessments baseados em evidências. Comecei pela camada de conhecimento porque não quero fazer simplesmente outro scanner de AWS. Quero preservar a fonte, acompanhar mudanças entre versões e conseguir rastrear um finding até a evidência e até o controle que originou aquela conclusão."**

Depois:

> **"Para a BXSEC eu trouxe uma vertical slice disso funcionando em quatro ambientes Linux rodando em Docker."**

## Pitch de 1–2 minutos

> "Estou construindo o Invariant como um projeto open source focado em segurança, infraestrutura e confiabilidade.
>
> A ideia nasceu de uma pergunta simples: quando uma infraestrutura muda, o que deveria continuar sendo verdade?
>
> O projeto começa criando uma camada de conhecimento a partir de fontes como CIS e outras referências técnicas. Essas fontes são preservadas, versionadas e suas mudanças são acompanhadas.
>
> Depois, esse conhecimento pode alimentar assessments de ambientes reais.
>
> Para a BXSEC preparei uma demonstração pequena: quatro ambientes Linux em Docker, cada um com configurações diferentes. O Invariant coleta evidências, compara com controles e gera findings.
>
> O ponto não é apenas 'ele encontrou um problema'. Quero conseguir responder de onde veio aquele controle, qual versão da fonte estava vigente e qual evidência levou ao resultado.
>
> A filosofia do projeto é Human First: IA pode acelerar desenvolvimento, mas o humano precisa entender, questionar, testar e validar o resultado.
>
> O projeto é open source e estou procurando tanto feedback técnico quanto pessoas interessadas em colaborar. Também estou aberto a conversar sobre aplicações comerciais de assessment, hardening e implantação."

# 10. Pitch para contratação

> "Estou direcionando minha carreira para Platform Engineering, SRE, DevOps e segurança de infraestrutura. O Invariant é meu laboratório aberto para aplicar esse estudo em um projeto real. Estou trabalhando com Linux, Docker, automação, segurança, versionamento de conhecimento e, posteriormente, AWS e Kubernetes. Estou procurando uma oportunidade onde possa aplicar isso em produção e continuar crescendo tecnicamente."

Não apresentar a empresa como simples trampolim. Mostrar interesse em aprender o sistema, resolver problemas reais e evoluir para responsabilidades maiores.

# 11. Pitch para prestação de serviço

Não vender o Invariant como produto pronto.

> "O Invariant está sendo construído como uma base para assessments de infraestrutura. A ideia é transformar benchmarks e boas práticas em verificações reproduzíveis, gerar evidências e entregar um relatório rastreável. No futuro isso pode virar uma ferramenta para ajudar empresas a avaliar configurações de Linux, Docker, AWS e Kubernetes, identificar gaps e apoiar hardening."

Possível fluxo:

```text
Assessment
    ↓
Relatório
    ↓
Prioridades
    ↓
Hardening
    ↓
Reassessment
```

Não prometer funcionalidades que ainda não existem.

# 12. Pitch para colaboradores

> "O projeto é open source e está no começo. Eu não quero esperar ficar perfeito para abrir. A ideia é construir uma base de conhecimento e depois transformá-la em assessments de infraestrutura. Estou procurando gente interessada em segurança, Linux, Go, Python, Docker, cloud, documentação e arquitetura para ajudar a definir o projeto junto."

Possíveis áreas:

- Go;
- Python;
- Linux;
- Docker;
- segurança;
- parsers;
- documentação;
- benchmarks;
- testes;
- DevOps;
- AWS;
- Kubernetes;
- UX/dashboard futuramente.

# 13. Human First na apresentação

Se perguntarem sobre IA:

> "Eu uso IA como acelerador, mas estou tentando evitar o modelo de simplesmente gerar o projeto inteiro. Estou implementando em pequenos incrementos, entendendo e testando cada parte."

Não esconder o uso de IA. O diferencial é demonstrar entendimento.

# 14. PIT — Project Information / Technical Overview

**Nome:** Invariant

**Categoria:** Open source infrastructure security / reliability knowledge and assessment engine.

**Filosofia:** Human First.

**Princípios:**

```text
Build until you understand
AI is an accelerator, not an authority
Evidence over assumptions
Small increments
```

**Primeiro problema:** construir uma camada de conhecimento confiável a partir de fontes técnicas e benchmarks.

**Primeira fonte:** CIS AWS Foundations Benchmark.

**Primeira tecnologia:** Go, como experimento de aprendizado/produtividade. Python continua como fallback se Go virar um bloqueio desproporcional.

**Banco:** PostgreSQL.

**Direção:**

```text
Linux
 ↓
Docker
 ↓
AWS
 ↓
Kubernetes
 ↓
SRE / Platform
```

**Visão:**

```text
Sources
   ↓
Ingestion
   ↓
Raw Artifacts
   ↓
Extraction
   ↓
Normalization
   ↓
Versioned Knowledge
   ↓
Assessment
   ↓
Evidence
   ↓
Findings
```

**Posicionamento:** não tentar ser simplesmente "mais um scanner AWS". O diferencial pretendido é conhecimento versionado, proveniência, mudança entre versões, evidência, explicabilidade e Human First.

# 15. PIT — Demo

**Objetivo:** demonstrar que o conceito pode sair do papel.

**Ambiente:**

```text
Docker
 ├── target-01
 ├── target-02
 ├── target-03
 └── target-04
```

**Fluxo:**

```text
Docker Target
      ↓
Collector
      ↓
Evidence
      ↓
Control
      ↓
Assessment
      ↓
Finding
      ↓
Source / Version / Evidence
```

**Critério de sucesso:**

- iniciar de forma previsível;
- executar localmente;
- mostrar resultados reais;
- permitir explicar pelo menos um finding;
- permitir abrir o código;
- não depender de AWS;
- não depender de internet durante a apresentação, quando possível;
- reiniciar rapidamente.

# 16. Plano de execução

## Fase 1 — Hoje

Definir somente:

- 3–5 controles demonstráveis;
- evidência exigida por cada controle;
- configuração de cada container;
- formato do finding;
- fluxo mínimo do CLI.

Não adicionar funcionalidades por empolgação.

## Fase 2 — Implementação

```text
1. Docker environments
       ↓
2. Evidence collector
       ↓
3. Control representation
       ↓
4. Assessment
       ↓
5. Finding output
       ↓
6. Source/evidence metadata
```

Cada etapa deve funcionar antes da próxima.

## Fase 3 — V0 real

Em paralelo, manter o PRD:

```text
CIS
 ↓
Download
 ↓
Raw
 ↓
Hash
 ↓
Extraction
 ↓
PostgreSQL
```

A demo Linux não substitui o V0; ela fornece uma superfície demonstrável para o evento.

## Fase 4 — Ensaio

Executar do zero e cronometrar.

Meta: **menos de 10 minutos para chegar do ambiente inicial ao resultado**.

Testar também:

- computador sem internet;
- Docker parado;
- containers removidos;
- banco indisponível;
- execução repetida;
- output inesperado.

Preparar recovery.

# 17. Checklist

```text
[ ] GitHub público
[ ] README atualizado
[ ] Logo
[ ] Repositório funcionando
[ ] Docker funcionando
[ ] 4 targets
[ ] Findings reais
[ ] Fonte dos controles documentada
[ ] Demo testada do zero
[ ] Backup local
[ ] Página/slides de apoio
[ ] QR Code para GitHub
[ ] QR Code para contato
[ ] Instagram
[ ] LinkedIn
```

# 18. Página/QR Code

```text
INVARIANT

Open Source Infrastructure
Security & Reliability

Human First.

[ GitHub ]
[ Documentation ]
[ LinkedIn ]
[ Instagram ]
```

A demo deve funcionar localmente e não depender exclusivamente de Wi-Fi, GitHub, Docker Hub, APIs externas, AWS ou Telegram.

# 19. Conversas na BXSEC

Pessoas prioritárias:

- AppSec;
- Cloud Security;
- DevSecOps;
- DevOps;
- SRE;
- Platform Engineering;
- pentest;
- infraestrutura;
- consultoria;
- startups;
- open source.

Perguntas:

> "Você trabalha mais com cloud ou infraestrutura?"

> "Como vocês fazem assessment hoje?"

> "Usam algum benchmark como CIS no processo?"

> "Como vocês acompanham mudanças nos controles?"

> "O que essa ferramenta precisaria fazer para ser útil de verdade?"

> "Você teria interesse em contribuir com um projeto open source nessa área?"

Isso transforma a BXSEC em pesquisa de produto + networking + recrutamento.

# 20. Três públicos, três conversas

### Contratação

Falar de:

- você;
- engenharia;
- Linux;
- Docker;
- DevOps;
- SRE;
- troubleshooting;
- capacidade de aprender.

### Cliente

Falar de:

- assessment;
- evidência;
- relatório;
- hardening;
- reassessment;
- automação.

### Colaborador

Falar de:

- arquitetura;
- open source;
- problemas interessantes;
- roadmap;
- tecnologias;
- liberdade para contribuir.

# 21. Perguntas esperadas

### "Por que não Prowler?"

> "Prowler é uma referência muito forte em cloud security e eu não quero simplesmente competir com ele como scanner. O Invariant está explorando primeiro a camada de conhecimento, versionamento, proveniência e evidência."

### "Por que Go?"

> "Quero usar o V0 também como experimento de aprendizado. Go é uma oportunidade de construir uma aplicação de infraestrutura com uma linguagem diferente das que eu normalmente uso. Se a linguagem virar um bloqueio maior que o valor que entrega, Python continua sendo uma alternativa."

### "Por que CIS?"

> "Porque preciso de uma fonte estruturada e reconhecida para validar o pipeline de ingestão. O objetivo é depois abstrair a fonte."

### "Por que Docker?"

> "Para a primeira demo consigo criar ambientes reproduzíveis, isolados e controlados. Também me permite demonstrar Linux e segurança sem depender de uma conta cloud."

### "Isso já é um produto?"

> "Ainda não. É um projeto open source em fase inicial. A demo mostra uma vertical slice funcional e o projeto está sendo construído para validar o problema antes de tentar transformá-lo em produto."

### "Você usa IA?"

> "Sim, como acelerador. Mas uma das regras do projeto é Human First: código gerado precisa ser compreendido, revisado e testado antes de ser aceito."

# 22. O que não fingir

Se algo não estiver pronto:

> "Ainda não implementei."

Se algo for protótipo:

> "Isso é experimental."

Se não souber:

> "Não sei ainda; é justamente uma das coisas que quero investigar."

Se a IA ajudou:

> "Usei IA para acelerar essa parte, mas essa implementação foi revisada e testada por mim."

# 23. Métrica de sucesso

A BXSEC será considerada bem-sucedida se gerar pelo menos uma oportunidade concreta:

```text
1 conversa de contratação
        OU
1 potencial cliente
        OU
1 colaborador interessado
        OU
5+ contatos técnicos relevantes
        OU
feedback que altere uma decisão
```

Não medir sucesso por quantidade de pessoas que viram a demo.

Medir por:

> **"Quantas conversas relevantes a demo gerou?"**

# 24. Depois da BXSEC

Registrar:

```text
Pessoa
 ↓
Contexto
 ↓
Feedback
 ↓
Oportunidade
 ↓
Próximo passo
```

Categorias:

```text
HIRING
SERVICE
OPEN SOURCE
```

Registrar também decisões e feedback técnico que possam alimentar o projeto.

# 25. Regra final

A BXSEC não precisa ver o Invariant perfeito.

Precisa ver:

```text
IDEIA
  ↓
DECISÃO
  ↓
CÓDIGO
  ↓
EXECUÇÃO
  ↓
EVIDÊNCIA
  ↓
APRENDIZADO
```

> **Don't build to seem like you know.**
>
> **Build until you know.**
>
> **Human First.**
