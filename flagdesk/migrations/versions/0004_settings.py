"""settings

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('settings',
    sa.Column('key', sa.String(length=40), nullable=False),
    sa.Column('value', sa.String(length=200), nullable=False),
    sa.PrimaryKeyConstraint('key'),
    schema='flagdesk'
    )


def downgrade() -> None:
    op.drop_table('settings', schema='flagdesk')
