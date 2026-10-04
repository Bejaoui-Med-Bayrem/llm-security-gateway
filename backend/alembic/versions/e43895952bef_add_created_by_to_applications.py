"""add created_by to applications

Revision ID: e43895952bef
Revises: 56cda9544611
Create Date: 2026-09-22 00:08:10.187074

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e43895952bef"
down_revision: Union[str, Sequence[str], None] = "56cda9544611"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # 1. Add the column temporarily as nullable
    op.add_column(
        "applications",
        sa.Column("created_by", sa.Uuid(), nullable=True),
    )

    # 2. Assign existing applications to an admin: admin@example.com
    #    if it exists, otherwise any admin.
    op.execute(
        sa.text(
            """
            UPDATE applications
            SET created_by = COALESCE(
                (SELECT id FROM users WHERE email = 'admin@example.com'),
                (SELECT id FROM users WHERE role = 'admin' ORDER BY email LIMIT 1)
            )
            WHERE created_by IS NULL
            """
        )
    )

    unowned = op.get_bind().execute(
        sa.text("SELECT count(*) FROM applications WHERE created_by IS NULL")
    ).scalar()

    if unowned:
        raise RuntimeError(
            f"{unowned} existing application(s) need an owner, but there is "
            "no admin user. Create one first (python -m app.cli create-admin "
            "--email ... --full-name ...), then rerun the migration."
        )

    # 3. Make the column mandatory
    op.alter_column(
        "applications",
        "created_by",
        existing_type=sa.Uuid(),
        nullable=False,
    )

    # 4. Add the foreign key
    op.create_foreign_key(
        "fk_applications_created_by_users",
        "applications",
        "users",
        ["created_by"],
        ["id"],
    )


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_constraint(
        "fk_applications_created_by_users",
        "applications",
        type_="foreignkey",
    )

    op.drop_column("applications", "created_by")