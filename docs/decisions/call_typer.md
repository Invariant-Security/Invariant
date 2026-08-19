# Alternativas
1) cada modulo importa `app` do main.py e usa @app.command() direto.
2) Cada modulo expoe uma funcao pura, main.py centraliza (import invariant) e registra com app.command("fetch")(fetch.fetch)

# opcao 2 ganhou por facilidade

- Funcoes puras sao mais faceis de testar com pytest

- evita import circular entre main.py e os modulos de comando (claude ensinou sobre import circular e seus problemas de fagilidade na execucao)

- Typer fica centralizado no main.py

# lado ruim
muito texto dentro do main, verbosidade e repeticao consideravel de comando