"""add_type_field_in_sns

Revision ID: 1928da62cee6
Revises: 702f43f1b165
Create Date: 2024-01-06 23:11:28.458304

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "1928da62cee6"
down_revision: Union[str, None] = "702f43f1b165"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sns",
        sa.Column("type", sa.String(24), comment="종류"),
    )


def downgrade() -> None:
    op.drop_column("sns", "type")
