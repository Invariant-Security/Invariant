"""create controls table

Revision ID: 6f8ce5e7018a
Revises: a4aba57c258e
Create Date: 2026-08-19 17:36:47.475373

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6f8ce5e7018a'
down_revision: Union[str, Sequence[str], None] = 'a4aba57c258e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00002_controls.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE controls CASCADE;")
