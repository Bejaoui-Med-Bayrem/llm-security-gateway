"""unique evaluation per campaign and normalize gateway actions

Revision ID: 95592ffb564b
Revises: 07029555e6ef
Create Date: 2026-10-02 17:52:54.045497

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '95592ffb564b'
down_revision: Union[str, Sequence[str], None] = '07029555e6ef'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # Rows created by hand before the Gateway owned these fields used
    # lowercase variants ("block", "blocked"). The API now only accepts
    # and returns "ALLOW" / "BLOCK".
    for table, column in (
        ("attack_executions", "gateway_action"),
        ("gateway_decisions", "action"),
    ):
        op.execute(
            f"UPDATE {table} SET {column} = 'BLOCK' "
            f"WHERE lower({column}) IN ('block', 'blocked')"
        )
        op.execute(
            f"UPDATE {table} SET {column} = 'ALLOW' "
            f"WHERE lower({column}) IN ('allow', 'allowed')"
        )

    # Name matches PostgreSQL's default for unique=True on the model.
    op.create_unique_constraint(
        "evaluations_campaign_id_key",
        "evaluations",
        ["campaign_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""

    # The action normalization is not reverted: the old values carried
    # no extra meaning.
    op.drop_constraint(
        "evaluations_campaign_id_key",
        "evaluations",
        type_="unique",
    )
