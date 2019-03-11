from flask_sqlalchemy import SQLAlchemy
import datetime
from flask_uploads import UploadSet, IMAGES

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

    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String)
    gw_sn = db.Column(db.String)
    gw_id = db.Column(db.String)
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
        self.gw_id = kwargs.get('gw_id')
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

    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String)
    free_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.mac = kwargs.get('mac')
        self.free_data = kwargs.get('free_data')
        self.month_data = kwargs.get('month_data')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')


class Registered_Users(BaseModel, db.Model):
    """Model for the users table"""
    __tablename__ = 'registered_users'

    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String)
    registered_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.uname = kwargs.get('uname')
        self.registered_data = kwargs.get('registered_data')
        self.month_data = kwargs.get('month_data')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')


class Admin_Users(db.Model):
    """Model for the admin users table"""
    __tablename__ = 'admin_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    gateways = db.relationship(
        "Gateways", backref="modified_by", lazy="dynamic")
    limits = db.relationship(
        "Data_Limits", backref="modified_by", lazy="dynamic")
    uptimes = db.relationship(
        "Uptimes", backref="modified_by", lazy="dynamic")
    announcements = db.relationship(
        "Announcements", backref="modified_by", lazy="dynamic")
    logos = db.relationship(
        "Logos", backref="modified_by", lazy="dynamic")

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.first_name = kwargs.get('first_name')
        self.last_name = kwargs.get('last_name')

    # Flask-Login integration
    # NOTE: is_authenticated, is_active, and is_anonymous
    # are methods in Flask-Login < 0.3.0
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.username

    def __repr__(self):
        return (self.first_name + " " + self.last_name).title()


class Gateways(db.Model):
    """Model for the admin users table"""
    __tablename__ = 'gateways'

    id = db.Column(db.Integer, primary_key=True)
    gw_id = db.Column(db.String, unique=True)
    name = db.Column(db.String, unique=True)
    status = db.Column(db.SmallInteger)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    modified_on = db.Column(
        db.String, onupdate=datetime.datetime.now)
    limits = db.relationship(
        "Data_Limits", backref="gateway_id", lazy="dynamic")
    uptimes = db.relationship(
        "Uptimes", backref="gateway_id", lazy="dynamic")
    announcements = db.relationship(
        "Announcements", backref="gateway_id", lazy="dynamic")
    logos = db.relationship(
        "Logos", backref="gateway_id", lazy="dynamic")

    def get_gw_id(self):
        return self.gw_id

    def __repr__(self):
        return self.name


class Data_Limits(db.Model):
    """Model for the data limits table"""
    __tablename__ = 'data_limits'

    id = db.Column(db.Integer, primary_key=True)
    access_type = db.Column(db.SmallInteger)
    limit_type = db.Column(db.String(2))
    gw_id = db.Column(db.String, db.ForeignKey('gateways.gw_id'))
    value = db.Column(db.Float)
    status = db.Column(db.SmallInteger)
    modified_by_id = db.Column(db.Integer, db.ForeignKey(
        'admin_users.id'))
    modified_on = db.Column(
        db.String, onupdate=datetime.datetime.now)

    # __table_args__ = (db.UniqueConstraint(
    #     'gw_id', 'access_type', 'limit_type'), )


class Uptimes(db.Model):
    """Model for the portal uptimes table"""
    __tablename__ = 'uptimes'

    id = db.Column(db.Integer, primary_key=True)
    gw_id = db.Column(db.String, db.ForeignKey('gateways.gw_id'), unique=True)
    start_time = db.Column(db.Time(timezone=False))
    end_time = db.Column(db.Time(timezone=False))
    status = db.Column(db.SmallInteger)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    modified_on = db.Column(
        db.String, onupdate=datetime.datetime.now)


images = UploadSet('images', IMAGES)


class Announcements(db.Model):
    """Model for the announcement images table"""
    __tablename__ = 'announcements'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    path = db.Column(db.Unicode(128))
    status = db.Column(db.SmallInteger)
    gw_id = db.Column(db.String, db.ForeignKey('gateways.gw_id'), unique=True)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    modified_on = db.Column(
        db.String, onupdate=datetime.datetime.now)

    def __unicode__(self):
        return self.name

    @property
    def url(self):
        return images.url(self.path)

    @property
    def filepath(self):
        if self.path is None:
            return
        return images.path(self.path)


class Logos(db.Model):
    """Model for the logo images table"""
    __tablename__ = 'logos'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    path = db.Column(db.Unicode(128))
    status = db.Column(db.SmallInteger)
    gw_id = db.Column(db.String, db.ForeignKey('gateways.gw_id'), unique=True)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    modified_on = db.Column(
        db.String, onupdate=datetime.datetime.now)

    def __unicode__(self):
        return self.name

    @property
    def url(self):
        return images.url(self.path)

    @property
    def filepath(self):
        if self.path is None:
            return
        return images.path(self.path)


class RegisterUser(db.Model):
    """Model for the free radius registered users table"""
    __tablename__ = 'radcheck'
    __bind_key__ = 'radius'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    attribute = db.Column(db.String, default='Cleartext-Password')
    op = db.Column(db.String, default=':=')
    value = db.Column(db.String)
    full_name = db.Column(db.String)
    address = db.Column(db.String)
    phone_no = db.Column(db.String)
    birthday = db.Column(db.String)
    gender = db.Column(db.String(2))
    id_type = db.Column(db.String(2))
    id_value = db.Column(db.String)
    status = db.Column(db.SmallInteger)
    token = db.Column(db.String)
