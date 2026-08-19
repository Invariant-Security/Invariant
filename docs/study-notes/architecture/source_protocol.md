# Study Note: Source Protocol — por que a assinatura se repete

> Nome do arquivo ajustado para `source_protocol.md` (snake_case) para
> seguir a regra de PEP 8 que já está no README — o pedido original foi
> `sourceProtocol.md` (camelCase).

## A dúvida de hoje

Se `Source(Protocol)` já declara `download` e `publisher_version`, por que
`CISSource` precisa declarar tudo de novo, com a mesma assinatura?

## Resposta

`Protocol` **não usa herança**. Não existe relação "é um" entre `Source` e
`CISSource` — são duas classes sem parentesco nenhum do ponto de vista do
Python em tempo de execução. Sem herança, não há nada para herdar.

Os métodos dentro de um `Protocol` normalmente têm corpo vazio (`...`) —
eles não carregam lógica nenhuma, só descrevem a **forma**: nome do
método, tipos dos parâmetros, tipo de retorno.

```python
class Source(Protocol):
    def download(self) -> tuple[bytes, str]: ...   # sem corpo real
```

Quando `CISSource` não herda de `Source`, o Python não sabe que `Source`
existe. `CISSource` precisa escrever `download` com um corpo de verdade,
porque a versão dentro do `Protocol` nunca teve corpo nenhum para herdar
— e mesmo que tivesse, sem herança nada seria repassado.

## Comparando com Go (mesma ideia, outra linguagem)

Interfaces em Go funcionam igual: declarar
`type Source interface { Download() ([]byte, string) }` não dá código
nenhum de graça — todo `struct` que implementa a interface escreve a
função inteira do zero. `Protocol` em Python é o mesmo mecanismo.

## Se quisesse compartilhar código de verdade

Isso é o que `abc.ABC` resolveria (à custa de exigir herança): um método
concreto (com corpo real) na classe base é herdado por todo mundo sem
reescrever.

```python
from abc import ABC, abstractmethod

class Source(ABC):
    def log_download(self):        # método concreto, compartilhado
        print(f"downloading {self.name}")

    @abstractmethod
    def download(self) -> tuple[bytes, str]: ...

class CISSource(Source):
    name = "cis"
    def download(self):
        self.log_download()         # herdado de graça
        ...
```

Com `Protocol`, esse tipo de compartilhamento não existe via herança — só
via função utilitária externa (ver `source_config.md`).

## Erros reais cometidos hoje ao implementar isso (log de aprendizado)

1. `import Protocol` → errado, `Protocol` mora dentro de `typing`; correto
   é `from typing import Protocol`.
2. `class CISSource(Protocol)` → `CISSource` herdando de `Protocol` mistura
   o papel de "contrato" com o papel de "implementação". O certo é
   `class CISSource:` sem herdar nada.
3. `import requests` + chamada `httpx.get(...)` sem `import httpx` →
   `NameError` na hora de rodar. `requests` também não é dependência do
   projeto (`pyproject.toml` só declara `httpx`).
4. `params={"url": url, "output": "pdf"}` numa requisição que já ia direto
   pro PDF — parâmetro sem função aparente, provável cópia de outro
   contexto.
5. `httpx.get()` não segue redirect por padrão (diferente de `requests`) —
   precisa de `follow_redirects=True` se a URL for um link de redirect.
6. `AWSSource`, `FIRSTSource`, `OWASPSource` criados como `Protocol` antes
   da hora — essas fontes são V0.4 no roadmap (PRD seções 9-12), o V0.1 é
   só CIS. Regra de incrementos pequenos do CLAUDE.md.
7. Todas as classes (`CISSource`, `AWSSource`, ..., `Source`) acabaram
   herdando `Protocol`, virando 5 contratos soltos e desconectados, em vez
   de 1 contrato (`Source`) + N implementações concretas.

## Formato final que resolve os pontos acima

```python
class Source(Protocol):
    name: str
    def download(self) -> tuple[bytes, str]: ...
    def publisher_version(self) -> str: ...

class CISSource:                     # implementação concreta, sem herdar Protocol
    name = "cis"

    def download(self) -> tuple[bytes, str]:
        response = httpx.get(CIS_URL, follow_redirects=True)
        return response.content, "pdf"

    def publisher_version(self) -> str:
        ...
```

## Referências

- https://docs.python.org/3/library/typing.html#typing.Protocol
- https://docs.python.org/3/library/abc.html
- [source_config.md](source_config.md) — nota anterior, Protocol vs ABC
