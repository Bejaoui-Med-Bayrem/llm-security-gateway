"""add cascade deletes to foreign keys

Revision ID: 07029555e6ef
Revises: e43895952bef
Create Date: 2026-10-02 17:27:19.786386

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '07029555e6ef'
down_revision: Union[str, Sequence[str], None] = 'e43895952bef'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (constraint name, source table, referenced table, column, ondelete)
#
# Ownership chain cascades:
#   application → campaigns → attacks → attack_executions → gateway_decisions
#                          └→ evaluations
#
# "created_by" references to users are RESTRICT: deleting a user who still
# owns data is refused so attack results are never lost silently.
FOREIGN_KEYS = (
    ("campaigns_application_id_fkey", "campaigns", "applications", "application_id", "CASCADE"),
    ("attacks_campaign_id_fkey", "attacks", "campaigns", "campaign_id", "CASCADE"),
    ("attack_executions_attack_id_fkey", "attack_executions", "attacks", "attack_id", "CASCADE"),
    ("gateway_decisions_execution_id_fkey", "gateway_decisions", "attack_executions", "execution_id", "CASCADE"),
    ("evaluations_campaign_id_fkey", "evaluations", "campaigns", "campaign_id", "CASCADE"),
    ("fk_applications_created_by_users", "applications", "users", "created_by", "RESTRICT"),
    ("campaigns_created_by_fkey", "campaigns", "users", "created_by", "RESTRICT"),
)


def _recreate_foreign_keys(ondelete_override: str | None) -> None:
    for name, source, referent, column, ondelete in FOREIGN_KEYS:
        op.drop_constraint(name, source, type_="foreignkey")
        op.create_foreign_key(
            name,
            source,
            referent,
            [column],
            ["id"],
            ondelete=ondelete_override or ondelete,
        )


def upgrade() -> None:
    """Upgrade schema."""
    _recreate_foreign_keys(None)


def downgrade() -> None:
    """Downgrade schema."""
    _recreate_foreign_keys("NO ACTION")
