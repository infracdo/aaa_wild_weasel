from flask import Flask, flash, redirect, url_for, request, make_response, render_template, session, g, jsonify
from wtforms import form, fields, validators, SelectField, HiddenField, RadioField, PasswordField, StringField, TextAreaField
import flask_admin as admin
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_admin.contrib.sqla import ModelView
from flask_admin import helpers, expose
from flask_admin import form as admin_form
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event, func, desc, Sequence
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from pyrad.dictionary import Dictionary
from pyrad.client import Client
from pyrad.packet import Packet
from models import db, Transaction, AccessAuthLogs, Devices, Registered_Users, CertifiedDevices, Admin_Users, Gateways, Data_Limits, Uptimes, Announcements, Logos, RegisterUser, UserRoles, GatewayGroup, GatewayGroups, GroupAnnouncements, Accounting, PortalRedirectLinks, SessionId
from googletrans import Translator
import pyrad.packet
import datetime, socket, uuid, os, re, hashlib, json
from flask_uploads import UploadSet, IMAGES, configure_uploads, patch_request_class
#from jinja2 import Markup
from markupsafe import Markup #newly added
from tzlocal import get_localzone
from send_mail import send_mail         
from math import ceil
import csv
import io
import warnings
import sys
from googletrans import Translator #newly added
from tzlocal import get_localzone   #newly added

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = b'_5#y2L!.4Q8z\n\xec]/'

POSTGRES = {
    'user': 'wildweasel',
    'pw': 'ap0ll0ap0ll0',
    'db': 'wildweasel',
    'host': 'localhost',
    'port': '5432',
}

RADIUS = {
    'user': 'wildweasel',
    'pw': 'ap0ll0ap0ll0',
    'db': 'radius',
    'host': 'localhost',
    'port': '5432',
}

pyradServer = "192.168.90.73"
portal_url_root = "http://192.168.90.73:8080/"

#POSTGRES = {
#    'user': 'wildweasel',
#    'pw': 'ap0ll0',
#    'db': 'wildweasel',
#    'host': '192.168.88.145',
#    'port': '5432',
#}

#RADIUS = {
#    'user': 'radiator',
#    'pw': 'ap0ll0',
#    'db': 'radius',
#    'host': '192.168.88.145',
#    'port': '5432',
#}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_BINDS'] = {
    'radius': 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % RADIUS
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))   # refers to application_top
APP_STATIC = os.path.join(APP_ROOT, 'static')

def load_json_file(filename):
    with open(filename) as json_file:
        return json.load(json_file)


# @app.before_request
# def session_management():
#     # make the session last indefinitely until it is cleared
#     session.permanent = True

with warnings.catch_warnings():
    warnings.filterwarnings('ignore', 'Fields missing from ruleset', UserWarning)

@app.route('/')
def hello_world():
    return redirect(url_for('login'))


@app.route('/wifidog/ping', strict_slashes=False)
@app.route('/ping', strict_slashes=False)
def ping():
    return "Pong"

def encryptPass(userInput):
    salt = 'ap0ll0'
    db_password = userInput + salt
    return hashlib.md5(db_password.encode()).hexdigest()

@app.route('/authenticate', methods=['POST'])
def authenticate():
    password = request.form.get('password')
    if password and encryptPass(password) == 'ap0ll0': 
        return jsonify({'status': 'success'}), 200
    return jsonify({'status': 'failure'}), 401

# <------ GET DATA LIMIT SETTINGS | @getLimit ------>
def getLimit(gw_id, access_type, limit_type, default):
    _default = Data_Limits.query.filter_by(
        gw_id='DEFAULT', access_type=access_type, limit_type=limit_type,status=1).first()
    default = default if _default == None else _default.value
    limit = Data_Limits.query.filter_by(
        gw_id=gw_id, access_type=access_type, limit_type=limit_type,status=1).first()
    
    return default if limit == None else limit.value

# <------ CHECK IF TIME IN RANGE for uptime | @timeinRage ------>
def time_in_range(start, end, x):
    """Return true if x is in the range [start, end]"""
    if start <= end:
        return start <= x <= end
    else:
        return start <= x or x <= end

# @sessionID
def setSessionIdStart(mac):
    #last = Accounting.query.filter(Accounting.acctstatustype=='Start').order_by(desc(Accounting.time_stamp)).first()
    seq = Sequence('session_id_seq')
    next_id = db.session.execute(seq)
    acctsessionid = mac + "&" + str(next_id)

    last = SessionId.query.filter_by(mac=mac).first()
    if not last:
        new = SessionId(session_id=acctsessionid, mac=mac)
        db.session.add(new)
    else:
        last.session_id = acctsessionid
    db.session.commit()

    return acctsessionid

def setSessionIdAlive(mac):
    last_id = SessionId.query.filter_by(mac=mac).first().session_id
    return last_id

# <------ LOGIN ROUTE | @login ------>

@app.route('/wifidog/login/', methods=['GET', 'POST'], strict_slashes=False)
@app.route('/login/', methods=['GET', 'POST'], strict_slashes=False)
def login():

    if session.get('messages'):
        messages = session['messages']
    else:
        messages = load_json_file(os.path.join(APP_STATIC, 'lang/en.json'))
    
    session['title'] = messages['title']

    # LOGIN: POST request | @post
    if request.method == 'POST':
        srv = Client(server=pyradServer, secret=b"ap0ll0",
                     dict=Dictionary("dictionary"))
        uname = request.form['uname']
        pword = encryptPass(request.form['pword'])
        package = request.form['package']
        token = session['token']

        # <------ LOGIN, POST: FREE ACCESS | @loginFree ------>
        if package == "Free":
            # get dynamic limits, @hardcoded defaults
            daily_limit = getLimit(session['gw_id'], 1, 'dd', 50000000)
            month_limit = getLimit(session['gw_id'], 1, 'mm', 1000000000)
            session['type'] = 'One-Click Login'

            #check if device already exists in database
            trans = Transaction.query.filter_by(token=token).first()
            if Devices.query.filter_by(mac=trans.mac).count() > 0:
                device = Devices.query.filter_by(mac=trans.mac).first()
                try:
                    last_active_date = datetime.datetime.strptime(device.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
                except:
                    last_active_date = datetime.datetime.strptime(device.last_active, '%Y-%m-%d %H:%M:%S').date()
                if device.free_data >= daily_limit:
                    if last_active_date == datetime.date.today():
                        return render_template('logout.html', message=messages['day_limit_exceeded'], returnLink=url_for('access'), return_text=messages['return_text'])
                    else:
                        device.free_data = 0
                        db.session.commit()
                else:
                    if device.month_data >= month_limit:
                        if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                            return render_template('logout.html', message=messages['month_limit_exceeded'], returnLink=url_for('access'), return_text=messages['return_text'])
                        else:
                            device.month_data = 0
                            db.session.commit()
            else:
                # add to database if new device
                new_device = Devices(mac=trans.mac, free_data=0, month_data=0, last_active=str(datetime.datetime.now()), last_record=0)
                db.session.add(new_device)
                db.session.commit()

            # authenticate free access device   
            trans.stage = "authenticated"
            trans.package = "One-Click Login"
            trans.uname = trans.mac
            session["uname"] = trans.uname
            trans.date_modified = str(datetime.datetime.now())
            trans.last_active = get_localzone().localize(datetime.datetime.now())
            trans.start_time = get_localzone().localize(datetime.datetime.now())
            log = AccessAuthLogs(gw_id=session['gw_id'], stage="authenticated", mac=trans.mac, username=trans.uname)
            db.session.add(log)
            db.session.commit()
            acct_req = srv.CreateAcctPacket(User_Name=trans.mac)
            acct_req["NAS-Identifier"] = trans.gw_id
            acct_req["Framed-IP-Address"] = trans.ip
            acct_req["Callback-Id"] = setSessionIdStart(trans.mac)
            acct_req["Login-LAT-Service"] = trans.package
            acct_req["Login-LAT-Node"] = trans.mac
            acct_req["Connect-Info"] = trans.device
            acct_req["Acct-Status-Type"] = "Start"
            acct_req["Called-Station-Id"] = '0'
            acct_req["Calling-Station-Id"] = '0'

            try:
                reply = srv.SendPacket(acct_req)
            except pyrad.client.Timeout:
                message = "RADIUS server does not reply"
                
                return render_template("logout.html", message=message, hideReturnToHome=True)
            except socket.error as error:
                message = "Network error: " + error[1]
                
                return render_template("logout.html", message=message, hideReturnToHome=True)
            
            return redirect("http://" + trans.gw_address + ":" + trans.gw_port + "/wifidog/auth?token=" + trans.token, code=302, Response=None)
    else:
        # <------ LOGIN, GET: HOMEPAGE | @loginGet, @home ------>
        # retrieve arguments from access point and save to session
        # @tofollow

        if request.headers.get('isHTTPS') == "no":
            path = str(request.url).replace(str(request.url_root),portal_url_root,1)
            #print(path)
            return render_template('redirect.html', path=path)

        session['gw_id'] = request.args.get('gw_id', default='', type=str)
        session['gw_sn'] = request.args.get('gw_sn', default='', type=str)
        session['gw_address'] = request.args.get('gw_address', default='', type=str)
        session['gw_port'] = request.args.get('gw_port', default='', type=str)
        session['ip'] = request.args.get('ip', default='', type=str)
        session['mac'] = request.args.get('mac', default='', type=str)
        session['apmac'] = request.args.get('apmac', default='', type=str)
        session['ssid'] = request.args.get('ssid', default='', type=str)
        session['vlanid'] = request.args.get('vlanid', default='', type=str)
        session['token'] = request.cookies.get('token')
        session['device'] = request.headers.get('User-Agent')
        session['logged_in'] = True

        # print("NAS-Identifier")
        # print(session['gw_id'])
        # print("Framed-IP-Address")
        # print(session['gw_id'])
        # print("Callback-Id")
        # print("Login-LAT-Service")
        # print("Login-LAT-Node")
        # print("Connect-Info")
        # print("Acct-Status-Type")
        # print("Called-Station-Id")
        # print("Calling-Station-Id")

        # acct_req = srv.CreateAcctPacket(User_Name=trans.uname)
        #             acct_req["NAS-Identifier"] = trans.gw_id
        #             acct_req["Framed-IP-Address"] = trans.ip
        #             acct_req["Callback-Id"] = setSessionIdStart(trans.mac)
        #             acct_req["Login-LAT-Service"] = trans.package
        #             acct_req["Login-LAT-Node"] = trans.mac
        #             acct_req["Connect-Info"] = trans.device
        #             acct_req["Acct-Status-Type"] = "Start"
        #             acct_req["Called-Station-Id"] = '0'
        #             acct_req["Calling-Station-Id"] = '0'

        # catch errors: if no IP, if not accessed through wifi, redirect
        if session['ip'] == '' or session['ip'] == None:
            return render_template('logout.html', message=messages['connect'], hideReturnToHome=True)
        
        # if portal downtime, don't proceed
        today = datetime.date.today().strftime('%Y-%m-%d')
        uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
        if not uptime:
            uptime = Uptimes.query.filter_by(gw_id='DEFAULT',status=1).first()
        tz = get_localzone()
        if uptime:
            start = datetime.time(*map(int, str(uptime.start_time).split(':')))
            end = datetime.time(*map(int, str(uptime.end_time).split(':')))
            if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
                return render_template('logout.html', message=(messages['schedule'][0] + start.strftime("%-I:%M %p") + messages['schedule'][1] + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
        
        # if already accessed today, skip terms and language
        # @tofollow: fix this
        if Transaction.query.filter_by(mac=session['mac']).filter_by(device=session['device']).filter(Transaction.date_modified.like(today + '%')).filter_by(stage='authenticated').count() > 0:
            lang = request.cookies.get("lang")
            send_to_access = True
        else:
            lang = None
            send_to_access = False

        # check if device already saved in db   
        if Transaction.query.filter_by(mac=session['mac']).filter_by(device=session['device']).count() > 0:
            session['token'] = Transaction.query.filter_by(
                mac=session['mac']).filter_by(device=session['device']).first().token
        # if not, create new token
        if session['token'] == None:
            session['token'] = uuid.uuid4().hex
            while Transaction.query.filter_by(token=session['token']).count() > 0:
                session['token'] = uuid.uuid4().hex
            # create new transaction
            trans = Transaction(gw_sn=session['gw_sn'], gw_id=session['gw_id'], ip=session['ip'], gw_address=session['gw_address'], gw_port=session['gw_port'], mac=session['mac'], apmac=session['apmac'], ssid=session['ssid'], vlanid=session['vlanid'], token=session['token'], stage="capture", device=session['device'], date_modified=str(datetime.datetime.now()), last_active=get_localzone().localize(datetime.datetime.now()))
            db.session.add(trans)
            log = AccessAuthLogs(stage="capture", gw_id=session['gw_id'], mac=session['mac'])
            db.session.add(log)
            # create new log
            db.session.commit()
        else:
            # if already exists, update the transaction row in db
            trans = Transaction.query.filter_by(token=session['token']).first()
            trans.gw_sn = session['gw_sn']
            trans.gw_id = session['gw_id']
            trans.ip = session['ip']
            trans.gw_address = session['gw_address']
            trans.gw_port = session['gw_port']
            trans.mac = session['mac']
            trans.apmac = session['apmac']
            trans.ssid = session['ssid']
            trans.vlanid = session['vlanid']
            trans.stage = "capture"
            trans.device = session['device']
            trans.date_modified = str(datetime.datetime.now())
            trans.last_active = get_localzone().localize(datetime.datetime.now())
            trans.start_time = None
            trans.octets = None
            log = AccessAuthLogs(stage="capture", gw_id=session['gw_id'], mac=session['mac'])
            db.session.add(log)
            db.session.commit()
        # show homepage / index page
        
        return render_template('index.html', send_to_access=send_to_access, lang=lang)

# <------- GET LOGO SETTINGS | @getLogo ------>
def getLogo(gw_id):
    logo = Logos.query.filter_by(gw_id=gw_id, status=1).first()
    if logo:
        
        return 'uploads/' + logo.path
    else:
        default = Logos.query.filter_by(gw_id='DEFAULT', status=1).first()
        if default:
            
            return 'uploads/' + default.path
    
    return None


# <------ TYPES OF ACCESS PAGE ROUTE | @access ------>

@app.route('/access/')
@app.route('/access/<lang>')
def access(lang=None):
    #redirect if not accessed through wifi
 
    if session.get('lang'):
        lang = session['lang']
    if session.get('messages'):
        messages = session['messages']
    else:
        messages = load_json_file(os.path.join(APP_STATIC, 'lang/en.json'))

    session['title'] = messages['title']

    if not session.get('ip'):
        return render_template('logout.html', message=messages['connect'], hideReturnToHome=True) 
    
    #redirect if portal downtime
    uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
    if not uptime:
        uptime = Uptimes.query.filter_by(gw_id='DEFAULT',status=1).first()
    tz = get_localzone()
    if uptime:
        start = datetime.time(*map(int, str(uptime.start_time).split(':')))
        end = datetime.time(*map(int, str(uptime.end_time).split(':')))
        if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
            return render_template('logout.html', message=(messages['schedule'][0] + start.strftime("%-I:%M %p") + messages['schedule'][1] + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
    
    #get dynamic data limits, @hardcoded default values
    limit1 = getLimit(session['gw_id'], 1, 'dd', 50000000)/10000000000
    limit2 = getLimit(session['gw_id'], 2, 'dd', 100000000)/1000000000
    limit3 = getLimit(session['gw_id'], 3, 'dd', 300000000)/1000000000

    def format_limit(limit):
        if limit >= 1000000:
            return "{0:.0f} TB".format(limit/1000000)
        elif limit >= 1000:
            return "{0:.0f} GB".format(limit/1000)
        else:
            return "{0:.0f} MB".format(limit)
    
    return render_template('access.html', lang=lang, limit1=format_limit(limit1), limit2=format_limit(limit2), limit3=format_limit(limit3), logo_path=getLogo(session['gw_id']))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082)
