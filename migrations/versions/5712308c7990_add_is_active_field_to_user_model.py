"""Add is_active field to User model

Revision ID: 5712308c7990
Revises: 25a9fbda02c1
Create Date: 2025-04-27 01:52:09.945810

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5712308c7990'
down_revision = '25a9fbda02c1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_active', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_active')

    # ### end Alembic commands ###
