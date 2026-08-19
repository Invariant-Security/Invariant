"""invariant CLI root."""

# TODO: define the Typer root app and register the fetch/extract/import/
# diff/check-updates/notify/source/document/control subcommands.

import typer
from invariant.cli import fetch, extract, diff, check_updates, notify, import_document

app = typer.Typer()

app.command("fetch")(fetch.fetch)
app.command("extract")(extract.extract)
app.command("diff")(diff.diff)
app.command("check_updates")(check_updates.check_updates)
app.command("notify")(notify.notify)
app.command("import_document")(import_document.import_document)


def main() -> None:
    # TODO: call the Typer app once it exists.
    app()

if __name__ == "__main__":
    main()
