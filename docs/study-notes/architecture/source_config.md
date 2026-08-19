# Study Note: Source Config (Protocol vs ABC)

## Contexto

O pipeline do Invariant precisa que `invariant.collector` saiba "baixar o
documento de uma fonte" sem saber qual fonte é (CIS, AWS, OWASP...). Isso
exige que toda fonte tenha a mesma forma — mesmos métodos, mesma
assinatura. Python não tem uma palavra reservada `interface` como
Java/C#/Go; existem duas ferramentas para simular isso: `abc.ABC` e
`typing.Protocol`.

## O problema que a interface resolve

```text
invariant.collector
        │
        │ não pode saber nada específico de CIS/AWS/OWASP
        ▼
     Source  ←── contrato comum que qualquer fonte precisa satisfazer
        │
   ┌────┴────┬─────────┐
   ▼         ▼         ▼
CISSource AWSSource OwaspSource
```

Sem esse contrato, `collector` teria que ter um `if source == "cis": ...`
para cada fonte — exatamente o que o PRD (seção 7) proíbe: "pensar em
Source/Document/Version/Artifact, não em CIS parser/AWS parser".

## Opção 1 — `abc.ABC` (contrato explícito, por herança)

```python
from abc import ABC, abstractmethod

class Source(ABC):
    @abstractmethod
    def download(self) -> tuple[bytes, str]:
        """Retorna (conteúdo bruto, extensão do arquivo)."""
        ...

class CISSource(Source):        # herda explicitamente
    def download(self) -> tuple[bytes, str]:
        ...  # implementação real
```

- É obrigatório herdar de `Source`.
- Se `CISSource` esquecer de implementar `download`, o Python recusa **em
  tempo de execução**, na hora de instanciar:
  ```text
  TypeError: Can't instantiate abstract class CISSource with abstract method download
  ```
- Uma `ABC` também pode ter métodos concretos (com implementação), que
  toda subclasse herda de graça — ou seja, `ABC` também permite reuso de
  código via herança, além de forçar o contrato.

## Opção 2 — `typing.Protocol` (contrato estrutural, "duck typing")

```python
from typing import Protocol

class Source(Protocol):
    def download(self) -> tuple[bytes, str]: ...

class CISSource:                # NÃO herda de nada
    def download(self) -> tuple[bytes, str]:
        ...
```

- `CISSource` nem precisa importar `Source`. Basta "ter a cara certa"
  (método com a assinatura certa).
- A checagem é feita por ferramentas de tipo estático (`mypy`/`pyright`),
  não em tempo de execução — o Python não impede rodar uma classe
  incompleta, só o type checker reclamaria antes, ao analisar o código.
- É o mesmo mecanismo das interfaces implícitas de Go (satisfazer uma
  interface só por ter os métodos certos, sem `implements` explícito).

## Reuso de código sem herança

Diferença real entre as duas opções não é "repetir código ou não" — é
"de onde vem o compartilhamento de código".

- Com `ABC`, o compartilhamento pode vir de métodos concretos herdados.
- Com `Protocol`, não existe herança, então o compartilhamento vem de
  **funções utilitárias comuns**, chamadas de dentro de cada classe:

```python
# invariant/source/_http.py
def download_bytes(url: str) -> bytes:
    ...  # lógica única de HTTP GET, compartilhada

# invariant/source/cis.py
class CISSource:
    name = "cis"
    def download(self) -> tuple[bytes, str]:
        content = download_bytes(CIS_URL)   # reuso via função, não herança
        return content, "pdf"
```

`Protocol` não elimina reuso de código, só muda onde ele mora (função
utilitária em vez de método herdado).

## Tabela de trade-off

| | `ABC` | `Protocol` |
|---|---|---|
| Precisa herdar? | Sim | Não |
| Travado em tempo de execução? | Sim (erro ao instanciar se faltar método) | Não (só o type checker acusa) |
| Acoplamento | `CISSource` depende de `invariant.source.Source` | `CISSource` não precisa saber que `Source` existe |
| Reuso de código | Via métodos concretos herdados | Via funções utilitárias separadas |
| Analogia | `implements`/`extends` de Java/C# | Interface implícita de Go |

## Por que `Protocol` foi escolhido para `Source`

- O `invariant.collector` só precisa de "algo com `download()`" — não há
  necessidade real de uma hierarquia de classes.
- O primeiro caso real (CIS AWS Foundations) parece ser um download direto
  via URL, sem login — pouca complexidade compartilhada que justificasse
  herança.
- Desacopla `invariant.collector` de uma cadeia de herança: testar com um
  fake/stub de `Source` não exige herdar nada, só implementar o método.
- Reuso de código continua possível via função utilitária (ex.:
  `download_bytes`), então a falta de herança não custa nada aqui.

## Referências

- https://docs.python.org/3/library/typing.html#typing.Protocol
- https://docs.python.org/3/library/abc.html
