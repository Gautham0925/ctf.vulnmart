"""announcements and resources

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('announcements',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('title', sa.String(length=120), nullable=False),
    sa.Column('body', sa.String(length=1000), nullable=False),
    sa.Column('link', sa.String(length=500), nullable=False),
    sa.Column('challenge_id', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('created_by', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    schema='flagdesk'
    )
    op.create_index('ix_announcements_created', 'announcements', ['created_at'], unique=False, schema='flagdesk')
    op.create_table('resources',
    sa.Column('id', sa.String(length=48), nullable=False),
    sa.Column('title', sa.String(length=120), nullable=False),
    sa.Column('description', sa.String(length=300), nullable=False),
    sa.Column('filename', sa.String(length=80), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('labs', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('released_labs', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('released_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema='flagdesk'
    )


def downgrade() -> None:
    op.drop_table('resources', schema='flagdesk')
    op.drop_index('ix_announcements_created', table_name='announcements', schema='flagdesk')
    op.drop_table('announcements', schema='flagdesk')
