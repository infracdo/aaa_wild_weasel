from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class BaseModel(db.Model):
    """Base data model for all objects"""
    __abstract__ = True

    def __init__(self, *args):
        super().__init__(*args)

    def __repr__(self):
        """Define a base way to print models"""
        return '%s(%s)' % (self.__class__.__name__, {
            column: value
            for column, value in self._to_dict().items()
        })

    def json(self):
        """
                Define a base way to jsonify models, dealing with datetime objects
        """
        return {
            column: value if not isinstance(value, datetime.date) else value.strftime('%Y-%m-%d')
            for column, value in self._to_dict().items()
        }

class Transaction(BaseModel, db.Model):
    """Model for the transactions table"""
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key = True)
    uname = db.Column(db.String)
    gw_sn = db.Column(db.String)
    ip = db.Column(db.String)
    gw_address = db.Column(db.String)
    gw_port = db.Column(db.String)
    mac = db.Column(db.String)
    apmac = db.Column(db.String)
    ssid = db.Column(db.String)
    vlanid = db.Column(db.String)
    token = db.Column(db.String)
    stage = db.Column(db.String)
    package = db.Column(db.String)
    device = db.Column(db.String)
    date_modified = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.uname = kwargs.get('uname')
        self.gw_sn = kwargs.get('gw_sn')
        self.ip = kwargs.get('ip')
        self.gw_address = kwargs.get('gw_address')
        self.gw_port = kwargs.get('gw_port')
        self.mac = kwargs.get('mac')
        self.apmac = kwargs.get('apmac')
        self.ssid = kwargs.get('ssid')
        self.vlanid = kwargs.get('vlanid')
        self.token = kwargs.get('token')
        self.stage = kwargs.get('stage')
        self.package = kwargs.get('package')
        self.device = kwargs.get('device')
        self.date_modified = kwargs.get('date_modified')

class Devices(BaseModel, db.Model):
    """Model for the devices table"""
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key = True)
    mac = db.Column(db.String)
    free_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    free_limit = db.Column(db.Float)
    month_limit = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.mac = kwargs.get('mac')
        self.free_data = kwargs.get('free_data')
        self.month_data = kwargs.get('month_data')
        self.free_limit = kwargs.get('free_limit')
        self.month_limit = kwargs.get('month_limit')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')

class Registered_Users(BaseModel, db.Model):
    """Model for the users table"""
    __tablename__ = 'registered_users'

    id = db.Column(db.Integer, primary_key = True)
    uname = db.Column(db.String)
    registered_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    registered_limit = db.Column(db.Float)
    month_limit = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.uname = kwargs.get('uname')
        self.registered_data = kwargs.get('registered_data')
        self.month_data = kwargs.get('month_data')
        self.registered_limit = kwargs.get('registered_limit')
        self.month_limit = kwargs.get('month_limit')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')
