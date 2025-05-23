"""empty message

Revision ID: 959fa5c98050
Revises: 35b68c535f46
Create Date: 2019-02-27 10:36:20.679432

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '959fa5c98050'
down_revision = '35b68c535f46'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('gateways',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('gw_id', sa.String(), nullable=True),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('modified_on', sa.String(), nullable=True),
    sa.Column('modified_by', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['modified_by'], ['admin_users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('gw_id'),
    sa.UniqueConstraint('name')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('gateways')
    # ### end Alembic commands ###
