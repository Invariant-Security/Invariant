"""create sources, documents, document_versions, extracted_items

Revision ID: a4aba57c258e
Revises: 
Create Date: 2026-08-19 16:09:47.181851

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a4aba57c258e'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Hand-written SQL (PRD sec. 20 -- no ORM), kept as its own file under
# sql/schema/ rather than inline here so it stays readable/reviewable on
# its own, separate from Alembic's bookkeeping.
_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00001_init.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        "DROP TABLE extracted_items, document_versions, documents, sources CASCADE;"
    )
