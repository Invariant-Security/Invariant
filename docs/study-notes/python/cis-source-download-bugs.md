# Study Note: bugs no `CISSource.download` / `publisher_version`

Continuação de [source_protocol.md](../architecture/source_protocol.md) — aquela nota
resolveu a forma (`Protocol` vs herança). Esta nota é sobre bugs de
comportamento que sobraram na implementação depois que a forma ficou certa.

Código revisado (estado em 2026-08-18):

```python
class CISSource:
    name = "cis"

    def download(self) -> tuple[bytes, str]:
        try:
            return httpx.get("https://www.cisecurity.org/cis-benchmarks/").content, "pdf"
        except httpx.HTTPError as e:
            print(f"Error downloading CIS document: {e}")
            raise

    def publisher_version(self) -> str:
        str: ...
```

## Erros reais encontrados hoje

### 1. URL errada + extensão hardcoded errada

`https://www.cisecurity.org/cis-benchmarks/` é a página de listagem em
**HTML**, não o PDF do benchmark. Retornar `"pdf"` fixo faz o `fetch.py`
salvar um arquivo HTML com nome/extensão de PDF — quebra a rastreabilidade
que o projeto promete (hash de um conteúdo mal identificado, PRD seção 47).

Além disso, o site da CIS normalmente exige preencher um formulário
(nome/e-mail) antes de liberar o PDF do benchmark — então nem está claro
ainda se dá pra automatizar esse download com um `GET` simples. Isso é uma
decisão em aberto, não só um bug de código.

**Correção mínima**: descobrir a URL real do artefato (ou documentar que
não existe download direto) antes de fixar a extensão.

### 2. `publisher_version` não retorna nada

```python
def publisher_version(self) -> str:
    str: ...
```

`str: ...` é uma anotação de variável solta (equivalente a escrever
`x: int` sem atribuir nada) — não é um `return`. A função sempre devolve
`None` implicitamente, apesar da assinatura prometer `-> str`. Isso viola
o contrato do `Protocol` `Source` em tempo de execução (o type checker
também não pega, porque `Protocol` só é checado estaticamente — ver
`source_config.md`, tabela de trade-off).

**Correção**: `return "unknown"` (ou o que fizer sentido enquanto a lógica
de extrair a versão do publisher não existe) — ou `raise
NotImplementedError` se for melhor deixar explícito que ainda não foi
implementado, em vez de mentir retornando `None`.

### 3. `httpx.get()` não levanta erro para status HTTP ruim

O `except httpx.HTTPError` só pega erro de rede/conexão (DNS falhou,
timeout, conexão recusada). Uma resposta `404` ou `500` chega normalmente
como `Response` válida — `.content` funciona, só que o conteúdo é uma
página de erro, não o documento esperado, e nenhuma exceção é disparada.

**Correção**: chamar `response.raise_for_status()` antes de usar
`.content`:

```python
response = httpx.get(url)
response.raise_for_status()   # levanta httpx.HTTPStatusError se 4xx/5xx
return response.content, "pdf"
```

### 4. (correção ao que eu disse antes) `httpx` já tem timeout por padrão

Na conversa eu falei "sem timeout explícito, pode travar pra sempre" —
isso é verdade pra `requests`, mas **não** pra `httpx`: o `httpx.get()``
já usa um timeout padrão de 5 segundos (diferente de `requests`, que não
tem timeout nenhum por padrão). Não é um bug real, mas vale deixar
explícito (`timeout=30`, por exemplo) pra documentar a intenção, já que 5s
pode ser curto pra um PDF grande.

### 5. `print()` dentro de código de biblioteca

`invariant.source` vai ser chamado tanto pela CLI quanto (futuramente)
pela API. `print()` manda direto pro stdout sem nível, sem estrutura, sem
como desligar. `logging.getLogger(__name__).error(...)` seria mais
idiomático — quem chama decide se/como exibir o log.

## Resumo (pra ler antes de corrigir)

| Ponto | Tipo de erro | Prioridade |
|---|---|---|
| Extensão `"pdf"` fixa pra uma URL que devolve HTML | bug de dados | alto — quebra rastreabilidade |
| URL não é o artefato real | decisão em aberto | alto — bloqueia o resto |
| `publisher_version` sempre retorna `None` | bug de lógica | médio |
| Sem `raise_for_status()` | erro engolido silenciosamente | médio |
| Sem `timeout` explícito | não é bug (httpx já tem default) | baixo |
| `print()` em vez de `logging` | estilo/idiomático | baixo |

## Referências

- [source_protocol.md](../architecture/source_protocol.md)
- [source_config.md](../architecture/source_config.md)
- https://www.python-httpx.org/quickstart/#timeouts
- https://www.python-httpx.org/quickstart/#errors
