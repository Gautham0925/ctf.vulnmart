"""sounds and announcement sound

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('announcements', sa.Column('sound', sa.String(length=40), nullable=False, server_default=''), schema='flagdesk')
    op.create_table('sounds',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=60), nullable=False),
    sa.Column('mime', sa.String(length=32), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    schema='flagdesk'
    )


def downgrade() -> None:
    op.drop_table('sounds', schema='flagdesk')
    op.drop_column('announcements', 'sound', schema='flagdesk')
