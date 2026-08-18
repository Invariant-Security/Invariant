# invariant
Plataforma de ingestão, versionamento e rastreabilidade de diretrizes de segurança. Um laboratório de engenharia focado no pipeline de dados, unindo rigor técnico, aprendizado contínuo e a filosofia "Human First". Construído com Python, PostgreSQL e foco em evidências, entregando os dados via API REST para um frontend em React.

# Invariant 🛡️

![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-V0%20(WIP)-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

> Uma plataforma de ingestão de conhecimento de segurança, rastreabilidade e versionamento contínuo.

O **Invariant** não é apenas um scanner de segurança; é um pipeline de aquisição de dados focado em extrair, normalizar e versionar diretrizes de segurança (como CIS Benchmarks, CVSS, AWS Security Pillar) para garantir que o seu ambiente seja auditado contra uma "Fonte da Verdade" confiável e rastreável.

---

## 🧠 Filosofia e Princípios Essenciais

### A Filosofia Central: Human First
É a regra inegociável e a base de todo o projeto. A premissa é clara: **a IA pode propor e acelerar a implementação, mas o humano entende, questiona, decide, revisa, testa e documenta.**

### Core Principles
1. **Build until you understand:** *"Não construa para parecer que sabe. Construa até saber."*
2. **AI is an accelerator, not an authority:** A IA serve para *pair programming* e pesquisa, mas o código gerado deve ser compreendido pelo autor antes de ser aceito.
3. **Evidence over assumptions:** Não inventar vulnerabilidades, impactos de negócio ou fingir expertise sobre ferramentas que não rodam de verdade no ambiente.
4. **Small increments:** O desenvolvimento deve focar em resolver um problema por vez, gerando uma mudança focada e um resultado testável.

---

## 🛠️ Stack Tecnológico e Arquitetura

O projeto utiliza ferramentas robustas com foco em performance e aprendizado profundo de engenharia:
- **Linguagem:** Python
- **Banco de Dados:** PostgreSQL
- **Acesso a Dados:** SQL puro via psycopg (fugindo de ORMs para forçar o domínio de SQL real)
- **CLI Framework:** Typer (para comandos internos de pipeline como `fetch`, `diff`, etc.)
- **API:** REST API com FastAPI, responsável por entregar os dados ao frontend
- **Frontend:** React (SPA focado exclusivamente em web)

---

## 🗺️ Roadmap e Milestones

O desenvolvimento é incremental, garantindo a maturidade da camada de dados antes da construção do Assessment Engine (scanner):

* **V0 — Knowledge Ingestion Foundation:** Fundação da plataforma. Estabelecimento do pipeline básico de coleta, extração e normalização.
* **V0.1 — CIS:** Primeiro alvo do sistema, focado exclusivamente no *CIS AWS Foundations Benchmark*.
* **V0.2 — Versioning & Change Tracking:** Capacidade de preservar histórico, separando a versão do documento, do parser e da aplicação.
* **V0.3 — Notifications (Notificações):** Alertas (ex: Telegram) ao detectar alterações significativas na base de conhecimento.
* **V0.4 — Multiple Sources (Múltiplas Fontes):** Expansão do pipeline integrando FIRST/CVSS, AWS Security Pillar e relatórios OWASP.

---

## ⚙️ Pré-requisitos

Para rodar o Invariant localmente, você precisará de:
- [Python 3.11+](https://www.python.org/downloads/)
- [PostgreSQL](https://www.postgresql.org/download/) (Rodando localmente ou via Docker)
- [Node.js](https://nodejs.org/) (para o frontend em React, quando ele existir)
- *Recomendado: Make e Docker para facilitar o setup da infra.*

---

## 🚀 Quickstart

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/seu-usuario/invariant.git
   cd invariant
   ```

2. **Baixe as dependências:**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Configure o banco de dados:**
   *(Instruções para rodar as migrations do PostgreSQL entrarão aqui)*

4. **Execute o projeto:**
   ```bash
   python -m invariant.cli.main --help
   ```

---

## 💻 Como Usar (Usage)

*(Comandos disponíveis na V0.1)*

Para realizar a ingestão inicial do CIS AWS Foundations:
```bash
python -m invariant.cli.main fetch cis
```
*Este comando baixa o documento, salva o artefato bruto, calcula o hash SHA-256 e extrai os controles para o banco de dados.*

---

## 📂 Estrutura de Diretórios (Destaques)

```text
invariant/
├── src/invariant/      # Lógica de negócio, API REST (FastAPI) e CLI (Typer)
├── sql/                # Queries SQL brutas e schemas
├── frontend/           # SPA em React (a ser criado)
└── docs/
    └── study-notes/    # 🧪 Laboratório de estudos e notas de arquitetura. O código é produto do aprendizado documentado aqui.
```

---

## 🤝 Como Contribuir

Contribuições são bem-vindas, desde que respeitem a regra **Human First**. Pull Requests devem vir acompanhados de explicações claras sobre *por que* e *como* o código funciona. Códigos 100% gerados por IA sem curadoria humana não serão aceitos.

---

## 📄 Licença

Este projeto é licenciado sob a licença [MIT](LICENSE).