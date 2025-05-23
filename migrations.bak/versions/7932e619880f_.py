"""empty message

Revision ID: 7932e619880f
Revises: e07e277fdd41
Create Date: 2019-02-06 09:23:25.912607

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7932e619880f'
down_revision = 'e07e277fdd41'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('transactions', sa.Column('package', sa.String(), nullable=True))
    op.add_column('transactions', sa.Column('uname', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('transactions', 'uname')
    op.drop_column('transactions', 'package')
    # ### end Alembic commands ###
