import sqlalchemy
from data.db_session import SqlAlchemyBase
from flask_login import UserMixin


class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    username = sqlalchemy.Column(sqlalchemy.String, nullable=True, unique=True)
    password = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    reminds_names = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    reminds_opises = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    reminds_deadlines = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    reminds_statuses = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    photoprofile = sqlalchemy.Column(sqlalchemy.BLOB, nullable=True)
    role = sqlalchemy.Column(sqlalchemy.String, nullable=True, default='user')


class Admin(SqlAlchemyBase, UserMixin):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    username = sqlalchemy.Column(sqlalchemy.String, nullable=True, unique=True)
    password = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    reminds_names = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    reminds_opises = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    reminds_deadlines = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    reminds_statuses = sqlalchemy.Column(sqlalchemy.JSON, nullable=True)
    photoprofile = sqlalchemy.Column(sqlalchemy.BLOB, nullable=True)
    role = sqlalchemy.Column(sqlalchemy.String, nullable=True, default='user')