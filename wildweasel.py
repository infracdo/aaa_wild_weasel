from flask import Flask, flash, redirect, url_for, request, make_response, render_template, session
from wtforms import form, fields, validators, SelectField, HiddenField, RadioField, PasswordField, StringField, TextAreaField
import flask_admin as admin
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_admin.contrib.sqla import ModelView
from flask_admin import helpers, expose
from flask_admin import form as admin_form
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event, func
from werkzeug.security import generate_password_hash, check_password_hash
from pyrad.dictionary import Dictionary
from pyrad.client import Client
from pyrad.packet import Packet
from models import db, Transaction, Devices, Registered_Users, CertifiedDevices, Admin_Users, Gateways, Data_Limits, Uptimes, Announcements, Logos, RegisterUser, UserRoles, GatewayGroup, GatewayGroups, GroupAnnouncements
from googletrans import Translator
import pyrad.packet
import datetime, socket, uuid, os, re
from flask_uploads import UploadSet, IMAGES, configure_uploads, patch_request_class
from jinja2 import Markup
from tzlocal import get_localzone
from send_mail import send_mail
from math import ceil

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = b'_5#y2L!.4Q8z\n\xec]/'

# POSTGRES = {
#     'user': 'wildweasel',
#     'pw': 'ap0ll0',
#     'db': 'wildweasel',
#     'host': 'localhost',
#     'port': '5432',
# }

# RADIUS = {
#     'user': 'radius',
#     'pw': 'ap0ll0',
#     'db': 'radius',
#     'host': 'localhost',
#     'port': '5432',
# }

pyradServer = "192.168.88.146"

POSTGRES = {
    'user': 'wildweasel',
    'pw': 'ap0ll0',
    'db': 'wildweasel',
    'host': '192.168.88.145',
    'port': '5432',
}

RADIUS = {
    'user': 'freeradius',
    'pw': 'ap0ll0',
    'db': 'freeradius',
    'host': '192.168.88.145',
    'port': '5432',
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_BINDS'] = {
    'radius': 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % RADIUS
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


# @app.before_request
# def session_management():
#     # make the session last indefinitely until it is cleared
#     session.permanent = True


@app.route('/')
def hello_world():
    return redirect(url_for('login'))


@app.route('/ping/')
def ping():
    return "Pong"

# <------ GET DATA LIMIT SETTINGS | @getLimit ------>
def getLimit(gw_id, access_type, limit_type, default):
    _default = Data_Limits.query.filter_by(
        gw_id='default', access_type=access_type, limit_type=limit_type,status=1).first()
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


# <------ LOGIN ROUTE | @login ------>

@app.route('/login/', methods=['GET', 'POST'])
def login():

    # LOGIN: POST request | @post
    if request.method == 'POST':
        srv = Client(server=pyradServer, secret=b"ap0ll0",
                     dict=Dictionary("dictionary"))
        uname = request.form['uname']
        pword = request.form['pword']
        package = request.form['package']
        token = session['token']

        # <------ LOGIN, POST: FREE ACCESS | @loginFree ------>
        if package == "Free":
            # get dynamic limits, @hardcoded defaults
            daily_limit = getLimit(session['gw_id'], 1, 'dd', 50000000)
            month_limit = getLimit(session['gw_id'], 1, 'mm', 1000000000)
            session['type'] = 'One-Click'

            #check if device already exists in database
            trans = Transaction.query.filter_by(token=token).first()
            if Devices.query.filter_by(mac=trans.mac).count() > 0:
                device = Devices.query.filter_by(mac=trans.mac).first()
                last_active_date = datetime.datetime.strptime(
                    device.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
                if device.free_data >= daily_limit:
                    if last_active_date == datetime.date.today():
                        return render_template('logout.html', message="You have exceeded your data usage limit for today.", returnLink=url_for('access'))
                    else:
                        device.free_data = 0
                        db.session.commit()
                else:
                    if device.month_data >= month_limit:
                        if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                            return render_template('logout.html', message="You have exceeded your data usage limit for this month.", returnLink=url_for('access'))
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
            trans.package = "One-Click"
            trans.uname = trans.mac
            session["uname"] = trans.uname
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            acct_req = srv.CreateAcctPacket(User_Name=trans.mac)
            acct_req["NAS-Identifier"] = trans.gw_id
            acct_req["Framed-IP-Address"] = trans.ip
            acct_req["Acct-Session-Id"] = trans.mac
            acct_req["Acct-Status-Type"] = "Start"
            try:
                reply = srv.SendPacket(acct_req)
            except pyrad.client.Timeout:
                message = "RADIUS server does not reply"
            except socket.error as error:
                message = "Network error: " + error[1]
            return redirect("http://" + trans.gw_address + ":" + trans.gw_port + "/wifidog/auth?token=" + trans.token, code=302, Response=None)
        else:
            # <------ LOGIN, POST: REGISTERED ACCESS | @loginReg ------>
            if package == "Registered":
                # get dynamic limits, @hardcoded defaults
                daily_limit = getLimit(session['gw_id'], 2, 'dd', 100000000)
                month_limit = getLimit(session['gw_id'], 2, 'mm', 2000000000)
                session['type'] = 'Registered'

                # check status
                reguser = RegisterUser.query.filter_by(username=uname).first()
                if reguser:
                    if reguser.status == 0:
                        message = "Access denied! Your email address has not been verified."
                        resp = make_response(render_template('login.html', message=message))
                        resp.set_cookie('token', token)
                        return resp
                    if int(reguser.validated) == 0:
                        registered = datetime.datetime.strptime(reguser.registration_date, '%Y-%m-%d %H:%M:%S.%f')
                        elapsed_time = datetime.datetime.now() - registered
                        if elapsed_time > datetime.timedelta(days=30):
                            return render_template('logout.html', message="Your account has not been validated and your registration has expired. Please contact DICT.", returnLink=url_for('access'))
                # check login credentials
                # @tofollow: password encryption
                session['uname'] = uname
                req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=uname)
                req["User-Password"] = req.PwCrypt(pword)
                reply = srv.SendPacket(req)
                message = False
                reply = False
                try:
                    reply = srv.SendPacket(req)
                except pyrad.client.Timeout:
                    message = "RADIUS server does not reply"
                except socket.error as error:
                    message = "Network error: " + error[1]
                if reply.code == pyrad.packet.AccessAccept:
                    # if credentials accepted
                    # if user already exists in db
                    if Registered_Users.query.filter_by(uname=uname).count() > 0:
                        user = Registered_Users.query.filter_by(uname=uname).first()
                        last_active_date = datetime.datetime.strptime(user.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
                        if user.registered_data >= daily_limit:
                            if last_active_date == datetime.date.today():
                                return render_template('logout.html', message="You have exceeded your data usage limit for today.",returnLink=url_for('access'))
                            else:
                                user.registered_data = 0
                                db.session.commit()
                        else:
                            if user.month_data >= month_limit:
                                if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                                    return render_template('logout.html', message="You have exceeded your data usage limit for this month.", returnLink=url_for('access'))
                                else:
                                    user.month_data = 0
                                    db.session.commit()
                    else:
                        # if new user
                        new_user = Registered_Users(uname=uname, registered_data=0, month_data=0, last_active=str(datetime.datetime.now()), last_record=0)
                        db.session.add(new_user)
                        db.session.commit()

                    # update transaction table, authenticate user
                    trans = Transaction.query.filter_by(token=token).first()
                    trans.stage = "authenticated"
                    trans.package = "Registered"
                    trans.uname = uname
                    trans.date_modified = str(datetime.datetime.now())
                    db.session.commit()
                    acct_req = srv.CreateAcctPacket(User_Name=trans.uname)
                    acct_req["NAS-Identifier"] = trans.gw_id
                    acct_req["Framed-IP-Address"] = trans.ip
                    acct_req["Acct-Session-Id"] = trans.mac
                    acct_req["Acct-Status-Type"] = "Start"
                    try:
                        reply = srv.SendPacket(acct_req)
                    except pyrad.client.Timeout:
                        message = "RADIUS server does not reply"
                    except socket.error as error:
                        message = "Network error: " + error[1]
                    return redirect("http://" + trans.gw_address + ":" + trans.gw_port + "/wifidog/auth?token=" + trans.token, code=302, Response=None)
                else:
                    # if wrong credentials
                    message = "Access denied!"
                    resp = make_response(render_template('login.html', message=message))
                    resp.set_cookie('token', token)
                    return resp

    else:
        # <------ LOGIN, GET: HOMEPAGE | @loginGet, @home ------>
        # retrieve arguments from access point and save to session
        # @tofollow

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

        # catch errors: if no IP, if not accessed through wifi, redirect
        if session['ip'] == '' or session['ip'] == None:
            return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
        
        # if portal downtime, don't proceed
        today = datetime.date.today().strftime('%Y-%m-%d')
        uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
        tz = get_localzone()
        if uptime:
            start = datetime.time(*map(int, str(uptime.start_time).split(':')))
            end = datetime.time(*map(int, str(uptime.end_time).split(':')))
            if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
                return render_template('logout.html', message=("Sorry, Pipol Konek is only available from " + start.strftime("%-I:%M %p") + " to " + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
        
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
            trans = Transaction(gw_sn=session['gw_sn'], gw_id=session['gw_id'], ip=session['ip'], gw_address=session['gw_address'], gw_port=session['gw_port'], mac=session['mac'], apmac=session['apmac'], ssid=session['ssid'], vlanid=session['vlanid'], token=session['token'], stage="capture", device=session['device'], date_modified=str(datetime.datetime.now()))
            db.session.add(trans)
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
            db.session.commit()
        # show homepage / index page
        return render_template('index.html', send_to_access=send_to_access, lang=lang)


# <------ SELECT LANGUAGE PAGE ROUTE | @lang ------>

@app.route('/lang/', methods=['GET', 'POST'])
def lang():
    if not session.get('ip'):
        return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
    uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
    tz = get_localzone()
    if uptime:
        start = datetime.time(*map(int, str(uptime.start_time).split(':')))
        end = datetime.time(*map(int, str(uptime.end_time).split(':')))
        if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
            return render_template('logout.html', message=("Sorry, Pipol Konek is only available from " + start.strftime("%-I:%M %p") + " to " + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
    return render_template('lang.html')


# <------ TERMS & CONDITIONS PAGE ROUTE | @terms ----->

@app.route('/terms/<lang>', methods=['GET', 'POST'])
def terms(lang):
    if not session.get('ip'):
        return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
    uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
    tz = get_localzone()
    if uptime:
        start = datetime.time(*map(int, str(uptime.start_time).split(':')))
        end = datetime.time(*map(int, str(uptime.end_time).split(':')))
        if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
            return render_template('logout.html', message=("Sorry, Pipol Konek is only available from " + start.strftime("%-I:%M %p") + " to " + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
    if lang =="en":
        resp = make_response(render_template('terms.html'))
    else:
        if lang =="tl":
            resp = make_response(render_template('terms-tl.html'))
        else:
            resp = make_response(render_template('terms.html'))
    resp.set_cookie('lang', lang)
    return resp


# <------- GET LOGO SETTINGS | @getLogo ------>
def getLogo(gw_id):
    logo = Logos.query.filter_by(gw_id=gw_id, status=1).first()
    if logo:
        return 'uploads/' + logo.path
    else:
        default = Logos.query.filter_by(gw_id='default', status=1).first()
        if default:
            return 'uploads/' + default.path
    return None


# <------ TYPES OF ACCESS PAGE ROUTE | @access ------>

@app.route('/access/')
@app.route('/access/<lang>')
def access(lang=None):
    #redirect if not accessed through wifi
    if not session.get('ip'):
        return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
    
    #redirect if portal downtime
    uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
    tz = get_localzone()
    if uptime:
        start = datetime.time(*map(int, str(uptime.start_time).split(':')))
        end = datetime.time(*map(int, str(uptime.end_time).split(':')))
        if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
            return render_template('logout.html', message=("Sorry, Pipol Konek is only available from " + start.strftime("%-I:%M %p") + " to " + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
    
    #get dynamic data limits, @hardcoded default values
    limit1 = "{0:.0f}".format(getLimit(session['gw_id'], 1, 'dd', 50000000)/1000000)
    limit2 = "{0:.0f}".format(getLimit(session['gw_id'], 2, 'dd', 100000000)/1000000)
    limit3 = "{0:.0f}".format(getLimit(session['gw_id'], 3, 'dd', 300000000)/1000000)
    
    return render_template('access.html', lang=lang, limit1=limit1, limit2=limit2, limit3=limit3, logo_path=getLogo(session['gw_id']))


# <------ REGISTERED ACCESS LOGIN ROUTE | @signin @regLogin------>

@app.route('/login-reg/')
@app.route('/login-reg/<lang>')
def loginReg(lang=None):
    #redirect if not accessed through wifi
    if not session.get('ip'):
        return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
    
    #redirect if portal downtime
    uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
    tz = get_localzone()
    if uptime:
        start = datetime.time(*map(int, str(uptime.start_time).split(':')))
        end = datetime.time(*map(int, str(uptime.end_time).split(':')))
        if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
            return render_template('logout.html', message=("Sorry, Pipol Konek is only available from " + start.strftime("%-I:%M %p") + " to " + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
    
    return render_template('login.html', lang=lang, logo_path=getLogo(session['gw_id']))


# <------ AUTHENTICATION ROUTE | @auth ------->

@app.route('/auth/')
def auth():
    token_n = request.args.get('token', default='', type=str)
    stage_n = request.args.get('stage', default='', type=str)
    incoming_n = request.args.get('incoming', default='', type=int)
    outgoing_n = request.args.get('outgoing', default='', type=int)
    trans = Transaction.query.filter_by(token=token_n).first()
    srv = Client(server=pyradServer, secret=b"ap0ll0", dict=Dictionary("dictionary"))
    acct_req = srv.CreateAcctPacket(User_Name=trans.uname)
    acct_req["NAS-Identifier"] = trans.gw_id
    acct_req["Framed-IP-Address"] = trans.ip
    acct_req["Acct-Session-Id"] = trans.mac

    # Stop connection during logout stage and update database
    if stage_n == "logout":
        trans.stage = "logout"
        trans.date_modified = str(datetime.datetime.now())
        db.session.commit()
        return "Auth: 0"

    if trans.stage == "logout" or trans.stage == "end_email_validation" or trans.stage == "end_reset_password":
        return "Auth: 0"

    # <------ AUTHENTICATION FOR EMAIL VALIDATION | @authEmail ------>

    if trans.stage == "pending_confirmation" or trans.stage == "start_email_validation":
        # limit to 20 MB
        if incoming_n + outgoing_n > 20000000:
            trans.stage = "end_email_validation"
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            return "Auth: 0"
        # limit to 10 minutes
        last_modified = datetime.datetime.strptime(trans.date_modified, '%Y-%m-%d %H:%M:%S.%f')
        elapsed_time = datetime.datetime.now() - last_modified
        if elapsed_time <= datetime.timedelta(minutes=5):
            trans.stage = "start_email_validation"
            db.session.commit()
            return "Auth: 1"
        else:
            # end if exceeded
            trans.stage = "end_email_validation"
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            return "Auth: 0"
        return "Auth: 1"

        # <------ AUTHENTICATION FOR PASSWORD RESET | @authPass ------>

    if trans.stage == "reset_password":
        # limit to 20 MB
        if incoming_n + outgoing_n > 20000000:
            trans.stage = "end_reset_password"
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            return "Auth: 0"
        # limit to 10 minutes
        last_modified = datetime.datetime.strptime(trans.date_modified, '%Y-%m-%d %H:%M:%S.%f')
        elapsed_time = datetime.datetime.now() - last_modified
        if elapsed_time <= datetime.timedelta(minutes=5):
            trans.stage = "reset_password"
            db.session.commit()
            return "Auth: 1"
        else:
            # end if exceeded
            trans.stage = "end_reset_password"
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            return "Auth: 0"
        return "Auth: 1"

    # <------ AUTHENTICATION FOR REGISTERED ACCESS | @authReg ------>

    if trans.package == "Registered":
        daily_limit = getLimit(trans.gw_id, 2, 'dd', 100000000)
        month_limit = getLimit(trans.gw_id, 2, 'mm', 2000000000)
        user = Registered_Users.query.filter_by(uname=trans.uname).first()
        new_record = incoming_n + outgoing_n
        if new_record < user.last_record:
            user.last_record = new_record
        last_active_date = datetime.datetime.strptime(user.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
        if (user.registered_data + ((incoming_n + outgoing_n) - user.last_record)) >= daily_limit:
            acct_req["Acct-Input-Octets"] = incoming_n
            acct_req["Acct-Output-Octets"] = outgoing_n
            acct_req["Acct-Status-Type"] = "Stop"
            acct_req["Acct-Terminate-Cause"] = "Host-Request"
            try:
                reply = srv.SendPacket(acct_req)
            except pyrad.client.Timeout:
                message = "RADIUS server does not reply"
            except socket.error as error:
                message = "Network error: " + error[1]
            if last_active_date == datetime.date.today():
                user.registered_data = (user.registered_data + (new_record - user.last_record))
            else:
                user.registered_data = 0
            if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                user.month_data = (user.month_data + (new_record - user.last_record))
            else:
                user.month_data = 0
            user.last_record = 0
            db.session.commit()
            return "Auth: 0"
        else:
            acct_req["Acct-Input-Octets"] = incoming_n
            acct_req["Acct-Output-Octets"] = outgoing_n
            acct_req["Acct-Status-Type"] = "Interim-Update"
            try:
                reply = srv.SendPacket(acct_req)
            except pyrad.client.Timeout:
                message = "RADIUS server does not reply"
            except socket.error as error:
                message = "Network error: " + error[1]
            if last_active_date == datetime.date.today():
                user.registered_data = (user.registered_data + (new_record - user.last_record))
            else:
                user.registered_data = 0
            if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                user.month_data = (user.month_data + (new_record - user.last_record))
            else:
                user.month_data = 0
            user.last_record = new_record
            user.last_active = str(datetime.datetime.now())
            db.session.commit()
    else:

        # <------ AUTHENTICATION FOR FREE ACCESS | @authFree ------>

        if trans.package == "One-Click":            
            device = Devices.query.filter_by(mac=trans.mac).first()
            daily_limit = getLimit(trans.gw_id, 1, 'dd', 50000000)
            month_limit = getLimit(trans.gw_id, 1, 'mm', 1000000000)
            new_record = incoming_n + outgoing_n
            if new_record < device.last_record:
                device.last_record = new_record
            last_active_date = datetime.datetime.strptime(device.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
            if (device.free_data + (incoming_n + outgoing_n - device.last_record)) >= daily_limit:
                acct_req["Acct-Input-Octets"] = incoming_n
                acct_req["Acct-Output-Octets"] = outgoing_n
                acct_req["Acct-Status-Type"] = "Stop"
                acct_req["Acct-Terminate-Cause"] = "Host-Request"
                try:
                    reply = srv.SendPacket(acct_req)
                except pyrad.client.Timeout:
                    message = "RADIUS server does not reply"
                except socket.error as error:
                    message = "Network error: " + error[1]
                if last_active_date == datetime.date.today():
                    device.free_data = (device.free_data + (new_record - device.last_record))
                else:
                    device.free_data = 101
                if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                    device.month_data = (device.month_data + (new_record - device.last_record))
                else:
                    device.month_data = 0
                device.last_record = 0
                db.session.commit()
                return "Auth: 0"
            else:
                acct_req["Acct-Input-Octets"] = incoming_n
                acct_req["Acct-Output-Octets"] = outgoing_n
                acct_req["Acct-Status-Type"] = "Interim-Update"
                try:
                    reply = srv.SendPacket(acct_req)
                except pyrad.client.Timeout:
                    message = "RADIUS server does not reply"
                except socket.error as error:
                    message = "Network error: " + error[1]
                if last_active_date == datetime.date.today():
                    device.free_data = (device.free_data + (new_record - device.last_record))
                else:
                    device.free_data = 0
                if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                    device.month_data = (device.month_data + (new_record - device.last_record))
                else:
                    device.month_data = 0
                device.last_record = new_record
                device.last_active = str(datetime.datetime.now())
                db.session.commit()
        
        # <------ AUTHENTICATION FOR CERTIFIED ACCESS | @authCert ------>

        if trans.package == "Certified":
            device = CertifiedDevices.query.filter_by(mac=trans.mac).first()
            daily_limit = getLimit(trans.gw_id, 3, 'dd', 300000000)
            month_limit = getLimit(trans.gw_id, 3, 'mm', 3000000000)
            new_record = incoming_n + outgoing_n
            if new_record < device.last_record:
                device.last_record = new_record
            last_active_date = datetime.datetime.strptime(device.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
            if (device.cert_data + (incoming_n + outgoing_n - device.last_record)) >= daily_limit:
                acct_req["Acct-Input-Octets"] = incoming_n
                acct_req["Acct-Output-Octets"] = outgoing_n
                acct_req["Acct-Status-Type"] = "Stop"
                acct_req["Acct-Terminate-Cause"] = "Host-Request"
                try:
                    reply = srv.SendPacket(acct_req)
                except pyrad.client.Timeout:
                    message = "RADIUS server does not reply"
                except socket.error as error:
                    message = "Network error: " + error[1]
                if last_active_date == datetime.date.today():
                    device.cert_data = (device.cert_data + (new_record - device.last_record))
                else:
                    device.cert_data = 101
                if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                    device.month_data = (device.month_data + (new_record - device.last_record))
                else:
                    device.month_data = 0
                device.last_record = 0
                db.session.commit()
                return "Auth: 0"
            else:
                acct_req["Acct-Input-Octets"] = incoming_n
                acct_req["Acct-Output-Octets"] = outgoing_n
                acct_req["Acct-Status-Type"] = "Interim-Update"
                try:
                    reply = srv.SendPacket(acct_req)
                except pyrad.client.Timeout:
                    message = "RADIUS server does not reply"
                except socket.error as error:
                    message = "Network error: " + error[1]
                if last_active_date == datetime.date.today():
                    device.cert_data = (device.cert_data + (new_record - device.last_record))
                else:
                    device.cert_data = 0
                if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                    device.month_data = (device.month_data + (new_record - device.last_record))
                else:
                    device.month_data = 0
                device.last_record = new_record
                device.last_active = str(datetime.datetime.now())
                db.session.commit()

    # authentication success, update database
    trans.stage = stage_n
    trans.date_modified = str(datetime.datetime.now())
    db.session.commit()
    return "Auth: 1"


# <------ RETRIEVE ANNOUNCEMENT IMAGE SETTINGS | @getAnnouncement ------>

def getAnnouncement(gw_id):
    announcement = Announcements.query.filter_by(gw_id=gw_id, status=1).first()
    if announcement:
        return 'uploads/' + announcement.path
    else:
        default = Announcements.query.filter_by(gw_id='default', status=1).first()
        if default:
            return 'uploads/' + default.path
    return None


# <------ PORTAL | @portal  ------>

@app.route('/portal/')
def portal():
    if not session.get('type'):
        today = datetime.date.today().strftime('%Y-%m-%d')
        trans = Transaction.query.filter_by(mac=session['mac']).filter_by(device=session['device']).filter(Transaction.date_modified.like(today + '%')).first()
        if trans:
            session["type"] = trans.package
        else:
            return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
    trans = Transaction.query.filter_by(token=session['token']).first()
    # Splash page/message for authenticated users for email validation
    if trans and trans.stage == 'start_email_validation':
        return render_template('logout.html',message='Check your email inbox or spam folder to verify. You are given five (5) minutes of internet connection to activate your email.', hideReturnToHome=True) 
    if trans and trans.stage == 'reset_password':
        return render_template("logout.html", message="Check your email inbox or spam folder for the password reset link. You are given five (5) minutes of internet connection to reset your password.", hideReturnToHome=True)
    # Calculate Usage and Limits for Free Access
    if session["type"] == "One-Click":
        display_type = "Level One"
        daily_limit = getLimit(session['gw_id'], 1, 'dd', 50000000)
        month_limit = getLimit(session['gw_id'], 1, 'mm', 1000000000)
        device = Devices.query.filter_by(mac=session["mac"]).first()
        daily_used = "{0:.2f}".format(device.free_data / 1000000)
        monthly_used = "{0:.2f}".format(device.month_data / 1000000)
        day_rem = daily_limit - device.free_data if daily_limit - device.free_data >= 0 else 0
        month_rem = month_limit - device.month_data if month_limit - device.month_data >= 0 else 0
        daily_remaining = "{0:.2f}".format(day_rem / 1000000)
        monthly_remaining = "{0:.2f}".format(month_rem / 1000000)
    else:
        # Calculate Usage and Limits for Registered Access
        if session["type"] == "Registered":
            display_type = "Level Two"
            daily_limit = getLimit(session['gw_id'], 2, 'dd', 100000000)
            month_limit = getLimit(session['gw_id'], 2, 'mm', 2000000000)
            user = Registered_Users.query.filter_by(uname=session["uname"]).first()
            daily_used = "{0:.2f}".format(user.registered_data / 1000000)
            monthly_used = "{0:.2f}".format(user.month_data / 1000000)
            day_rem = daily_limit - user.registered_data if daily_limit - user.registered_data >= 0 else 0
            month_rem = month_limit - user.month_data if month_limit - user.month_data >= 0 else 0
            daily_remaining = "{0:.2f}".format((day_rem) / 1000000)
            monthly_remaining = "{0:.2f}".format((month_rem) / 1000000)
        else:
            # Certified Access computations here
            display_type = "Level Three"
            daily_limit = getLimit(session['gw_id'], 3, 'dd', 300000000)
            month_limit = getLimit(session['gw_id'], 3, 'mm', 3000000000)
            device = CertifiedDevices.query.filter_by(mac=session["mac"]).first()
            daily_used = "{0:.2f}".format(device.cert_data / 1000000)
            monthly_used = "{0:.2f}".format(device.month_data / 1000000)
            day_rem = daily_limit - device.cert_data if daily_limit - device.cert_data >= 0 else 0
            month_rem = month_limit - device.month_data if month_limit - device.month_data >= 0 else 0
            daily_remaining = "{0:.2f}".format(day_rem / 1000000)
            monthly_remaining = "{0:.2f}".format(month_rem / 1000000)
    ddd_limit = "{0:.2f}".format(daily_limit/1000000000)
    mmm_limit = "{0:.2f}".format(month_limit/1000000000)
    return render_template('portal.html', daily_used=daily_used, monthly_used=monthly_used, daily_remaining=daily_remaining, monthly_remaining=monthly_remaining, daily_limit=ddd_limit, monthly_limit=mmm_limit, ad_img_path=getAnnouncement(session['gw_id']), display_type=display_type)


# <------ REGISTERED MEMBER SIGN UP FORM | @regForm ------>

class RegisterForm(FlaskForm):
    def birthdayValidator(form, field):
        try:
            datetime.datetime(int(form.birth_y.data),int(form.birth_m.data), int(form.birth_d.data))
        except ValueError:
            raise validators.ValidationError('Please enter a valid date.')
        if datetime.datetime(int(form.birth_y.data),int(form.birth_m.data), int(form.birth_d.data)).date() > datetime.date.today():
            raise validators.ValidationError('Please enter a valid birthdate.')

    def passwordValidator(form, field):
        if not form.password1.data == form.password2.data:
            raise validators.ValidationError('Passwords do not match.')

    def uniqueEmailValidator(form, field):
        if RegisterUser.query.filter_by(username=form.email.data).first():
            raise validators.ValidationError('Email already registered.')

    email = StringField('email', validators=[validators.InputRequired(), validators.Email(message='Please enter a valid email address.'), uniqueEmailValidator])
    full_name = StringField('full_name', validators=[validators.InputRequired()])
    address = TextAreaField('address',validators=[validators.InputRequired()])
    phone_no = StringField('phone_no', validators=[validators.InputRequired(),validators.Regexp(r'^[\d]*$',message="Please enter a valid number."),validators.Length(min=7,message="Phone number too short.")])
    year_range = [str(i) for i in list(reversed(range(1900,datetime.date.today().year + 1,1)))]
    month_range = ["{:02d}".format(i) for i in range(1,13)]
    day_range = ["{:02d}".format(i) for i in range(1,32)]
    birth_y = SelectField('birth_y', choices=list(zip(year_range, year_range)), validators=[birthdayValidator])
    birth_m = SelectField('birth_m', choices=list(zip(month_range, month_range)))
    birth_d = SelectField('birth_d', choices=list(zip(day_range, day_range)))
    gender = SelectField('gender',choices=[('f','Female'),('m','Male')])
    govt_id_type = SelectField('govt_id_type', choices=[('ID', 'ID'),('PP', 'Passport')])
    govt_id_value = StringField('govt_id_value', validators=[validators.InputRequired()])
    password1 = PasswordField('password1', validators=[passwordValidator, validators.InputRequired(), validators.Regexp(r'^[^\s]+$',message='No spaces allowed.'), validators.Length(min=6,message="Password must be at least 6 characters.")])
    password2 = PasswordField('password2', validators=[validators.InputRequired()])

# <------ MEMBER REGISTRATION ROUTE | @register ------>

@app.route('/register/', methods=['GET', 'POST'])
def register():
    if not session.get('ip'):
        return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
    uptime = Uptimes.query.filter_by(gw_id=session['gw_id'],status=1).first()
    tz = get_localzone()
    if uptime:
        start = datetime.time(*map(int, str(uptime.start_time).split(':')))
        end = datetime.time(*map(int, str(uptime.end_time).split(':')))
        if not time_in_range(start, end, tz.localize(datetime.datetime.now()).time()):
            return render_template('logout.html', message=("Sorry, Pipol Konek is only available from " + start.strftime("%-I:%M %p") + " to " + end.strftime("%-I:%M %p") + "."), hideReturnToHome=True)
    regForm = RegisterForm()
    if regForm.validate_on_submit():
        bday = regForm.birth_y.data + '-' + regForm.birth_m.data + '-' + regForm.birth_d.data
        token = uuid.uuid4().hex
        while RegisterUser.query.filter_by(token=token).count() > 0:
            token = uuid.uuid4().hex
        message = "Click on the following link to activate your membership: " + str(request.url_root) + "activate/" + str(token)
        # try:
        send_mail(subject="PIPOL KONEK Membership Activation", recipient=regForm.email.data, message=message)
        newUser = RegisterUser(username=regForm.email.data,value=regForm.password1.data,full_name=regForm.full_name.data,address=regForm.address.data,phone_no=regForm.phone_no.data,birthday=bday,gender=regForm.gender.data,id_type=regForm.govt_id_type.data,id_value=regForm.govt_id_value.data,status=0,token=token,registration_date=str(datetime.datetime.now()),validated=0)
        db.session.add(newUser)
        if session.get('token'):
            srv = Client(server=pyradServer, secret=b"ap0ll0",
                     dict=Dictionary("dictionary"))
            trans = Transaction.query.filter_by(token=session['token']).first()
            trans.uname = trans.mac
            trans.stage = 'pending_confirmation'
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            acct_req = srv.CreateAcctPacket(User_Name=trans.mac)
            acct_req["NAS-Identifier"] = trans.gw_id
            acct_req["Framed-IP-Address"] = trans.ip
            acct_req["Acct-Session-Id"] = trans.mac
            acct_req["Acct-Status-Type"] = "Start"
            try:
                reply = srv.SendPacket(acct_req)
            except pyrad.client.Timeout:
                message = "RADIUS server does not reply"
            except socket.error as error:
                message = "Network error: " + error[1]
            return redirect("http://" + trans.gw_address + ":" + trans.gw_port + "/wifidog/auth?token=" + trans.token, code=302, Response=None)
        else:
            return render_template('logout.html', message='There was an error in creating your registration. Please try again later.', returnLink=url_for('access'))
    if regForm.errors.items():
        flash("Your form has some invalid input(s). Please fix them, and re-enter passwords, before submitting.")
    return render_template('register.html', form=regForm, logo_path=getLogo(session['gw_id']))


# <------ REGISTERED MEMBER ACTIVATION | @regActivate ------>

@app.route('/activate/<token>')
def activateUser(token):
    user = RegisterUser.query.filter_by(token=token).first()
    if user:
        if user.status == 1:
            return render_template("logout.html", message="Your account has already been activated.", hideReturnToHome=True)
        else:
            user.status = 1
            db.session.commit()
            return render_template("logout.html", message="Your have successfully activated your account. You can now use the portal as a registered member.", returnLink=url_for('access'))
    else:
        return render_template("logout.html", message="You have submitted an invalid activation link.", hideReturnToHome=True)

# <------ REGISTERED MEMBER SEND PASSWORD RESET LINK | @emailReset ------>
@app.route('/email-reset/', methods=['GET', 'POST'])
def sendPasswordResetLink():
    if request.method == 'GET':
        return render_template("email-reset.html")
    else:
        if request.form['email'] == None or request.form['email'] == '' or request.form['email'] == ' ':
            return render_template("email-reset.html", message="Please enter a valid email address.")
        else:
            reguser = RegisterUser.query.filter_by(username=request.form['email']).first()
            if reguser:
                message = "Click on the following link to reset your password: " + str(request.url_root) + "reset/" + str(reguser.token)
                # try:
                send_mail(subject="PIPOL KONEK Password Reset", recipient=reguser.username, message=message)
                srv = Client(server=pyradServer, secret=b"ap0ll0",
                     dict=Dictionary("dictionary"))
                trans = Transaction.query.filter_by(token=session['token']).first()
                trans.uname = trans.mac
                trans.stage = 'reset_password'
                trans.date_modified = str(datetime.datetime.now())
                db.session.commit()
                acct_req = srv.CreateAcctPacket(User_Name=trans.mac)
                acct_req["NAS-Identifier"] = trans.gw_id
                acct_req["Framed-IP-Address"] = trans.ip
                acct_req["Acct-Session-Id"] = trans.mac
                acct_req["Acct-Status-Type"] = "Start"
                try:
                    reply = srv.SendPacket(acct_req)
                except pyrad.client.Timeout:
                    message = "RADIUS server does not reply"
                except socket.error as error:
                    message = "Network error: " + error[1]
                return redirect("http://" + trans.gw_address + ":" + trans.gw_port + "/wifidog/auth?token=" + trans.token, code=302, Response=None)
            else:
                return render_template("email-reset.html", message=("Please enter an email address that is registered with Pipol Konek. " + Markup('<a href="%s">Register here.</a>' % url_for('register'))))

# <------ REGISTERED MEMBER RESET PASSWORD FORM | @reset ------>
@app.route('/reset/<token>', methods=['GET', 'POST'])
def resetUser(token):
    if request.method == 'GET':
        return render_template("reset.html", token=token)
    else:
        password1 = request.form['password1']
        password2 = request.form['password2']
        if not password1 == password2:
            return render_template("reset.html", token=token, message="The passwords you entered do not match.")
        else:
            if password1 == None or password1 == '' or password2 == None or password2 == '':
                return render_template("reset.html", token=token, message="Please fill in all fields.")
            if len(password1) <= 6 or len(password2) <= 6:
                return render_template("reset.html", token=token, message="Password must be at least 6 characters.")
        reguser = RegisterUser.query.filter_by(token=token).first()
        if reguser:
            reguser.password = generate_password_hash(password1)
            db.session.commit()
            return render_template("logout.html", message="Your password has been reset.", returnLink=url_for('access'))
        else:
            return render_template("logout.html", message="There was an error resetting your password.", returnLink=url_for('access'))


# <------ CERTIFIED ACCESS AUTHENTICATION | @certVerify @loginCert ------>

@app.route("/cert/")
def cert():
    try:
        verify = request.environ.get('SSL_CLIENT_VERIFY')
        uname = request.environ.get('SSL_CLIENT_S_DN_CN')
    except:
        return render_template('logout.html', message="Your browser/device certificate does not exist or is invalid. Please contact DICT to apply for a valid certificate.", returnLink=url_for('access'))
    if verify == "SUCCESS" and session.get('token'):
        srv = Client(server=pyradServer, secret=b"ap0ll0",
                     dict=Dictionary("dictionary"))
        # get dynamic limits, @hardcoded defaults
        daily_limit = getLimit(session['gw_id'], 3, 'dd', 300000000)
        month_limit = getLimit(session['gw_id'], 3, 'mm', 3000000000)
        session['type'] = 'Certified'
        session['uname'] = uname

        #check if device already exists in database
        trans = Transaction.query.filter_by(token=session['token']).first()
        if CertifiedDevices.query.filter_by(mac=trans.mac).count() > 0:
            device = CertifiedDevices.query.filter_by(mac=trans.mac).first()
            last_active_date = datetime.datetime.strptime(
                device.last_active, '%Y-%m-%d %H:%M:%S.%f').date()
            if device.cert_data >= daily_limit:
                if last_active_date == datetime.date.today():
                    return render_template('logout.html', message="You have exceeded your data usage limit for today.", returnLink=url_for('access'))
                else:
                    device.cert_data = 0
                    db.session.commit()
            else:
                if device.month_data >= month_limit:
                    if last_active_date.month == datetime.date.today().month and last_active_date.year == datetime.date.today().year:
                        return render_template('logout.html', message="You have exceeded your data usage limit for this month.", returnLink=url_for('access'))
                    else:
                        device.month_data = 0
                        db.session.commit()
        else:
            # add to database if new device
            new_device = CertifiedDevices(mac=trans.mac, common_name=uname, cert_data=0, month_data=0, last_active=str(datetime.datetime.now()), last_record=0)
            db.session.add(new_device)
            db.session.commit()
        
        # authenticate certified access device   
        trans.stage = "authenticated"
        trans.package = "Certified"
        trans.uname = uname
        trans.date_modified = str(datetime.datetime.now())
        db.session.commit()
        acct_req = srv.CreateAcctPacket(User_Name=trans.mac)
        acct_req["NAS-Identifier"] = trans.gw_id
        acct_req["Framed-IP-Address"] = trans.ip
        acct_req["Acct-Session-Id"] = trans.mac
        acct_req["Acct-Status-Type"] = "Start"
        try:
            reply = srv.SendPacket(acct_req)
        except pyrad.client.Timeout:
            message = "RADIUS server does not reply"
        except socket.error as error:
            message = "Network error: " + error[1]
        return redirect("http://" + trans.gw_address + ":" + trans.gw_port + "/wifidog/auth?token=" + trans.token, code=302, Response=None)
    else:
        return render_template('logout.html', message="Your browser/device certificate does not exist or is invalid. Please contact DICT to apply for a valid certificate.", returnLink=url_for('access'))


# <------ LOGOUT | @logout ------>

# @tofollow: not yet disconnecting 
@app.route('/logout/')
def logout():
    if session.get('token'):
        trans = Transaction.query.filter_by(token=session['token']).first()
        if trans:
            trans.stage = "logout"
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            #print("i entered here")
    return render_template('logout.html', message="You have logged out. Your Pipol Konek connection will automatically terminate after one (1) minute.")


# /------ ADMIN INTERFACE STARTS HERE | @admin ------/ #

@app.errorhandler(403)
@app.errorhandler(400)
def page_forbidden(e):
    return redirect(url_for('admin.login_view'))

# Define login and registration forms (for flask-login)
class LoginForm(form.Form):
    username = fields.StringField(validators=[validators.InputRequired()],render_kw={"class": "form-control login-input"})
    password = fields.PasswordField(validators=[validators.InputRequired()],render_kw={"class": "form-control login-input"})


    def validate_username(self, field):
        user = self.get_user()

        if not user:
            raise validators.ValidationError('Invalid user')

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
            # to compare plain text passwords use
            # if user.password != self.password.data:
            raise validators.ValidationError('Invalid password')

    def get_user(self):
        return Admin_Users.query.filter_by(username=self.username.data).first()


class RegistrationForm(form.Form):
    username = fields.StringField(validators=[validators.InputRequired()])
    password = fields.PasswordField(validators=[validators.InputRequired()])
    first_name = fields.StringField()
    last_name = fields.StringField()

    def validate_login(self, field):
        if Admin_Users.query.filter_by(username=self.username.data).first().count() > 0:
            raise validators.ValidationError('Duplicate username')


# Initialize flask-login
def init_login():
    login_manager = LoginManager()
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(Admin_Users).get(user_id)


# Create customized model view class

def _mod_date_formatter(view, context, model, name):
    if model.modified_on:
        return datetime.datetime.strptime(model.modified_on, '%Y-%m-%d %H:%M:%S.%f').strftime('%Y-%m-%d %I:%M:%S %p')
    return ""

def _cre_date_formatter(view, context, model, name):
    if model.created_on:
        return datetime.datetime.strptime(model.created_on, '%Y-%m-%d %H:%M:%S.%f').strftime('%Y-%m-%d %I:%M:%S %p')
    return ""

def _status_formatter(view, context, model, name):
    if model.status:
        return "Active" if model.status == 1 else "Inactive"
    return "Inactive"

def _mod_by_formatter(view, context, model, name):
    if model.modified_by:
        role = UserRoles.query.filter_by(id=model.modified_by.role_id).first().role
        return (model.modified_by.first_name + " " + model.modified_by.last_name + " (" + role + ")").title()
    return ""

def _cre_by_formatter(view, context, model, name):
    if model.created_by:
        role = UserRoles.query.filter_by(id=model.created_by.role_id).first().role
        return (model.created_by.first_name + " " + model.created_by.last_name + " (" + role + ")").title()
    return ""

class BaseView(ModelView):
    create_template = 'admin/create.html'
    edit_template = 'admin/edit.html'
    list_template = 'admin/list.html'

    @expose('/')
    def index_view(self):
        """
            List view
        """
        if self.can_delete:
            delete_form = self.delete_form()
        else:
            delete_form = None

        # Grab parameters from URL
        view_args = self._get_list_extra_args()

        # Map column index to column name
        sort_column = self._get_column_by_idx(view_args.sort)
        if sort_column is not None:
            sort_column = sort_column[0]

        # Get page size
        page_size = view_args.page_size or self.page_size

        # Get count and data
        count, data = self.get_list(view_args.page, sort_column, view_args.sort_desc,
                                    view_args.search, view_args.filters, page_size=page_size)

        list_forms = {}
        if self.column_editable_list:
            for row in data:
                list_forms[self.get_pk_value(row)] = self.list_form(obj=row)

        # Calculate number of pages
        if count is not None and page_size:
            num_pages = int(ceil(count / float(page_size)))
        elif not page_size:
            num_pages = 0  # hide pager for unlimited page_size
        else:
            num_pages = None  # use simple pager

        # Various URL generation helpers
        def pager_url(p):
            # Do not add page number if it is first page
            if p == 0:
                p = None

            return self._get_list_url(view_args.clone(page=p))

        def sort_url(column, invert=False, desc=None):
            if not desc and invert and not view_args.sort_desc:
                desc = 1

            return self._get_list_url(view_args.clone(sort=column, sort_desc=desc))

        def page_size_url(s):
            if not s:
                s = self.page_size

            return self._get_list_url(view_args.clone(page_size=s))

        # Actions
        actions, actions_confirmation = self.get_actions_list()
        if actions:
            action_form = self.action_form()
        else:
            action_form = None

        clear_search_url = self._get_list_url(view_args.clone(page=0,
                                                              sort=view_args.sort,
                                                              sort_desc=view_args.sort_desc,
                                                              search=None,
                                                              filters=None))

        return self.render(
            self.list_template,
            data=data,
            list_forms=list_forms,
            delete_form=delete_form,
            action_form=action_form,

            # List
            list_columns=self._list_columns,
            sortable_columns=self._sortable_columns,
            editable_columns=self.column_editable_list,
            list_row_actions=self.get_list_row_actions(),

            # Pagination
            count=count,
            pager_url=pager_url,
            num_pages=num_pages,
            can_set_page_size=self.can_set_page_size,
            page_size_url=page_size_url,
            page=view_args.page,
            page_size=page_size,
            default_page_size=self.page_size,

            # Sorting
            sort_column=view_args.sort,
            sort_desc=view_args.sort_desc,
            sort_url=sort_url,

            # Search
            search_supported=self._search_supported,
            clear_search_url=clear_search_url,
            search=view_args.search,
            search_placeholder=self.search_placeholder(),

            # Filters
            filters=self._filters,
            filter_groups=self._get_filter_groups(),
            active_filters=view_args.filters,
            filter_args=self._get_filters(view_args.filters),

            # Actions
            actions=actions,
            actions_confirmation=actions_confirmation,

            # Misc
            enumerate=enumerate,
            get_pk_value=self.get_pk_value,
            get_value=self.get_list_value,
            get_raw_value=self._get_field_value,
            return_url=self._get_list_url(view_args),
        )

class UserView(BaseView):
    column_list = ('first_name', 'last_name', 'username', 'role', 'mpop', 'created_by', 'created_on')
    form_columns = ('username', 'first_name', 'last_name', 'password', 'role', 'mpop')
    column_labels = {
        'mpop': 'Gateway/MPOP ID'
    }
    form_args = {
        'username': {
            'validators' : [validators.InputRequired()]
        },
        'password': {
            'validators' : [validators.InputRequired()]
        },
        'first_name': {
            'validators' : [validators.InputRequired()]
        },
        'last_name': {
            'validators' : [validators.InputRequired()]
        }
    }

    form_overrides = dict(
        password=PasswordField, 
    )

    column_formatters = {
        'created_on': _cre_date_formatter,
        'created_by': _cre_by_formatter
    }

    def on_model_change(self, form, model, is_created):
        if form.mpop.data == None or form.mpop.data == '':
            if not str(form.role.data) == 'Tenant':
                raise NotImplementedError('Please assign the MPOP ID for Manager/User.')
        if form.mpop.data and str(form.role.data) == 'Tenant':
            raise NotImplementedError('Please leave the MPOP ID blank for Tenant users.')
        model.password = generate_password_hash(form.password.data)
        model.first_name = form.first_name.data.title()
        model.last_name = form.last_name.data.title()
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())

    def on_model_delete(self,model):
        if model.id == current_user.id:
            raise NotImplementedError('Currently logged in user cannot be deleted.')

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)

class ManagerUserView(UserView):
    def get_query(self):
      return self.session.query(self.model).filter(self.model.mpop_id==current_user.mpop_id)

    def get_count_query(self):
      return self.session.query(func.count('*')).filter(self.model.mpop_id==current_user.mpop_id)

    form_args = {
        'username': {
            'validators' : [validators.InputRequired()]
        },
        'password': {
            'validators' : [validators.InputRequired()]
        },
        'first_name': {
            'validators' : [validators.InputRequired()]
        },
        'last_name': {
            'validators' : [validators.InputRequired()]
        },
        'role': {
            'query_factory': lambda:  db.session.query(UserRoles).filter_by(id=2)
        },
        'mpop': {
            'query_factory': lambda:  db.session.query(Gateways).filter_by(gw_id=current_user.mpop_id),
            'validators' : [validators.InputRequired()]
        }
    }

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 1)

class GatewayView(BaseView):
    edit_modal = True
    column_list = ('gw_id', 'name', 'created_by', 'created_on', 'modified_by', 'modified_on')
    column_labels = {
        'gw_id': 'Gateway/MPOP ID',
        'name': 'Municipality Name'
    }
    form_columns = ('gw_id', 'name')
    form_args = {
        'gw_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()]
        },
        'name': {
            'label': 'Municipality Name',
            'validators' : [validators.InputRequired()]
        }
    }
    form_overrides = dict(
        status=RadioField
    )
    column_formatters = {
        'modified_on': _mod_date_formatter,
        'created_on': _cre_date_formatter,
        'modified_by': _mod_by_formatter,
        'created_by': _cre_by_formatter
    }

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)


class DataLimitsView(BaseView):
    column_list = ('gateway_id', 'access_type', 'limit_type', 'value', 'status', 'created_by', 'created_on', 'modified_by', 'modified_on')
    column_labels = {
        'gateway_id': 'Region or Municipality',
        'value': 'Data Usage Limit (Bytes)'
    }
    form_columns = ('gateway_id', 'access_type', 'limit_type', 'value', 'status')
    form_extra_fields = {
        'status': RadioField(
            'Status',
            choices=[('1', 'Active'), ('0', 'Inactive')],validators=[validators.InputRequired()],default='0'
        )
    }
    form_overrides = dict(
        access_type=SelectField,
        limit_type=SelectField
    )

    form_args = {
        'gateway_id': {
            'label': 'Gateway / MPOP ID',
            'validators' : [validators.InputRequired()]
        },
        'access_type': {
            'choices': [
                ('1', 'Level 1: Free'),
                ('2', 'Level 2: Registered'),
                ('3', 'Level 3: Certified')
            ],
            'default': '1',
            'validators' : [validators.InputRequired()]
        },
        'limit_type': {
            'choices': [
                ('dd', 'Daily'),
                ('mm', 'Monthly')
            ],
            'default': 'dd',
            'validators' : [validators.InputRequired()]
        },
        'value' : {
            'validators' : [validators.InputRequired()]
        }
    }

    def _bytes_formatter(view, context, model, name):
        if model.value:
            return "{:,.0f}".format(model.value)
        else:
            return ""

    def _access_formatter(view, context, model, name):
        if model.access_type:
            return "Level " + str(model.access_type)
        return ""

    def _limit_formatter(view, context, model, name):
        if model.limit_type:
            if model.limit_type == 'dd':
                return "Daily"
            else:
                if model.limit_type == 'mm':
                    return "Monthly"
        return ""

    column_formatters = {
        'access_type': _access_formatter,
        'limit_type': _limit_formatter,
        'created_on': _cre_date_formatter,
        'modified_on': _mod_date_formatter,
        'value': _bytes_formatter,
        'status': _status_formatter,
        'modified_by': _mod_by_formatter,
        'created_by': _cre_by_formatter
    }

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)

class ManagerDataLimitsView(DataLimitsView):

    def get_query(self):
      return self.session.query(self.model).filter(self.model.gw_id==current_user.mpop_id)

    def get_count_query(self):
      return self.session.query(func.count('*')).filter(self.model.gw_id==current_user.mpop_id)

    form_args = {
        'modified_on': {
            'default': str(datetime.datetime.now())
        },
        'gateway_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()],
            'query_factory' : lambda:  db.session.query(Gateways).filter_by(gw_id=current_user.mpop_id)
        },
        'access_type': {
            'choices': [
                ('1', 'Level 1: Free'),
                ('2', 'Level 2: Registered'),
                ('3', 'Level 3: Certified')
            ],
            'default': '1',
            'validators' : [validators.InputRequired()]
        },
        'limit_type': {
            'choices': [
                ('dd', 'Daily'),
                ('mm', 'Monthly')
            ],
            'default': 'dd',
            'validators' : [validators.InputRequired()]
        },
        'value' : {
            'validators' : [validators.InputRequired()]
        }
    }

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 1)

class UserDataLimitsView(ManagerDataLimitsView):
    form_columns = ('gateway_id', 'access_type', 'limit_type', 'value')

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())
            model.status = 0

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id > 1)

hours = [('00:00:00','12:00 AM'),('01:00:00','01:00 AM'),('02:00:00','02:00 AM'),('03:00:00','03:00 AM'),('04:00:00','04:00 AM'),('05:00:00','05:00 AM'),
            ('06:00:00','06:00 AM'),('07:00:00', '07:00 AM'),('08:00:00','08:00 AM'),('09:00:00','09:00 AM'),('10:00:00','10:00 AM'),('11:00:00','11:00 AM'),
            ('12:00:00','12:00 PM'),('13:00:00','01:00 PM'),('14:00:00','02:00 PM'),('15:00:00','03:00 PM'),('16:00:00','04:00 PM'),('17:00:00','05:00 PM'),
            ('18:00:00','06:00 PM'),('19:00:00', '07:00 PM'),('20:00:00','08:00 PM'),('21:00:00','09:00 PM'),('22:00:00','10:00 PM'),('23:00:00','11:00 PM')]

class UptimesView(BaseView):      
    column_list = ('gateway_id', 'start_time', 'end_time', 'status', 'created_by', 'created_on', 'modified_by', 'modified_on')
    column_labels = {
        'gateway_id': 'Gateway/MPOP ID',
    }
    form_columns = ('gateway_id', 'start_time', 'end_time', 'status')
    form_extra_fields = {
        'status': RadioField(
            'Status',
            choices=[('1', 'Active'), ('0', 'Inactive')],validators=[validators.InputRequired()],default='0'
        )
    }
    form_args = {
        'gateway_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()]
        },
        'start_time': {
            'validators' : [validators.InputRequired()],
            'choices': hours
            # 'format': '%I:%M %p',
            # 'description': "must be 12 hr format, ex. '07:00 AM'"
        },
        'end_time': {
            'validators' : [validators.InputRequired()],
            'choices': hours
            # 'format': '%I:%M %p',
            # 'description': "must be 12 hr format, ex. '01:00 PM'"
            }
    }
    form_overrides = dict(
        start_time=SelectField,
        end_time=SelectField
    )

    def _start_time_formatter(view, context, model, name):
        if model.start_time:
            return model.start_time.strftime('%I:%M %p')
        return ""
    
    def _end_time_formatter(view, context, model, name):
        if model.end_time:
            return model.end_time.strftime('%I:%M %p')
        return ""

    column_formatters = {
        'modified_on': _mod_date_formatter,
        'start_time': _start_time_formatter,
        'end_time': _end_time_formatter,
        'status': _status_formatter,        
        'modified_by': _mod_by_formatter,
        'created_by': _cre_by_formatter
    }

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)

class ManagerUptimesView(UptimesView):
    def get_query(self):
      return self.session.query(self.model).filter(self.model.gw_id==current_user.mpop_id)

    def get_count_query(self):
      return self.session.query(func.count('*')).filter(self.model.gw_id==current_user.mpop_id)

    form_args = {
        'gateway_id': {
            'label': 'Gateway / MPOP ID',
            'validators' : [validators.InputRequired()],
            'query_factory' : lambda:  db.session.query(Gateways).filter_by(gw_id=current_user.mpop_id)
        },
        'start_time': {
            'validators' : [validators.InputRequired()],
            'choices': hours
            # 'format': '%I:%M %p',
            # 'description': "must be 12 hr format, ex. '07:00 AM'"
        },
        'end_time': {
            'validators' : [validators.InputRequired()],
            'choices': hours
            # 'format': '%I:%M %p',
            # 'description': "must be 12 hr format, ex. '01:00 PM'"
            }
    }

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 1)

class UserUptimesView(ManagerUptimesView):

    form_columns = ('gateway_id', 'start_time', 'end_time')

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())
            model.status = 0

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 1)


app.config['UPLOADED_IMAGES_DEST'] = imagedir = os.path.join(os.path.dirname(__file__), 'static/uploads')
app.config['UPLOADED_IMAGES_URL'] = '/static/uploads/'

images = UploadSet('images', IMAGES)
configure_uploads(app, (images))
patch_request_class(app, 16 * 1024 * 1024)

def _list_thumbnail(view, context, model, name):
    if not model.path:
        return ''

    return Markup(
        '<img src="{model.url}" style="width: 150px;">'.format(model=model)
    )


class AnnouncementsView(BaseView):

    column_list = [
        'gateway_id', 'image', 'status', 'created_by', 'created_on', 'modified_by', 'modified_on'
    ]

    column_labels = {
        'gateway_id': 'Gateway/MPOP ID', 'image': 'Announcement Image'
    }

    form_extra_fields = {
        'path': admin_form.ImageUploadField(
            'Image',
            base_path=imagedir,
            url_relative_path='uploads/',validators=[validators.InputRequired()]
        ),
        'status': RadioField(
            'Status',
            choices=[('1', 'Active'), ('0', 'Inactive')],validators=[validators.InputRequired()],default='0'
        )
    }
    form_columns = ('gateway_id', 'name', 'path', 'status')

    form_args = {
        'gateway_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()]
        },
        'name': {
            'validators' : [validators.InputRequired()],
            'label': 'Image Name'
        }
    }
    
    column_formatters = {
        'modified_on': _mod_date_formatter,
        'image': _list_thumbnail,
        'status': _status_formatter,
        'modified_by': _mod_by_formatter,
        'created_by': _cre_by_formatter,
        'created_on': _cre_date_formatter
    }

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.modified_on = str(datetime.datetime.now())

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)

class ManagerAnnouncementsView(AnnouncementsView):
    def get_query(self):
      return self.session.query(self.model).filter(self.model.gw_id==current_user.mpop_id)

    def get_count_query(self):
      return self.session.query(func.count('*')).filter(self.model.gw_id==current_user.mpop_id)

    form_args = {
        'gateway_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()],
            'query_factory' : lambda:  db.session.query(Gateways).filter_by(gw_id=current_user.mpop_id)
        },
        'name': {
            'validators' : [validators.InputRequired()],
            'label': 'Image Name'
        }
    }

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 1)

class UserAnnouncementsView(ManagerAnnouncementsView):

    form_columns = ('gateway_id', 'name', 'path')

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())
            model.status = 0

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 2)


@event.listens_for(Announcements, 'after_delete')
def del_image(mapper, connection, target):
    if target.filepath is not None:
        try:
            os.remove(target.filepath)
        except OSError:
            pass

class GroupAnnouncementsView(BaseView):

    column_list = [
        'group', 'image', 'status', 'created_by', 'created_on', 'modified_by', 'modified_on'
    ]

    column_labels = {
        'group': 'Gateway Group', 'image': 'Announcement Image'
    }

    form_extra_fields = {
        'path': admin_form.ImageUploadField(
            'Image',
            base_path=imagedir,
            url_relative_path='uploads/',validators=[validators.InputRequired()]
        ),
        'status': RadioField(
            'Status',
            choices=[('1', 'Active'), ('0', 'Inactive')],validators=[validators.InputRequired()],default='0'
        )
    }
    form_columns = ('group', 'name', 'path', 'status')

    form_args = {
        'group': {
            'label': 'Gateway Group',
            'validators' : [validators.InputRequired()]
        },
        'name': {
            'validators' : [validators.InputRequired()],
            'label': 'Image Name'
        }
    }
    
    column_formatters = {
        'modified_on': _mod_date_formatter,
        'image': _list_thumbnail,
        'status': _status_formatter,
        'modified_by': _mod_by_formatter,
        'created_by': _cre_by_formatter,
        'created_on': _cre_date_formatter
    }

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.modified_on = str(datetime.datetime.now())

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)


@event.listens_for(GroupAnnouncements, 'after_delete')
def del_image(mapper, connection, target):
    if target.filepath is not None:
        try:
            os.remove(target.filepath)
        except OSError:
            pass

class LogosView(BaseView):

    column_list = [
        'image', 'gateway_id', 'status', 'created_by', 'created_on', 'modified_by', 'modified_on'
    ]

    column_labels = {
        'gateway_id': 'Gateway/MPOP ID', 'image': 'Logo Image'
    }

    form_extra_fields = {
        'path': admin_form.ImageUploadField(
            'Image',
            base_path=imagedir,
            url_relative_path='uploads/',validators=[validators.InputRequired()]
        ),
        'status': RadioField(
            'Status',
            choices=[('1', 'Active'), ('0', 'Inactive')],validators=[validators.InputRequired()],default='0'
        )
    }

    form_columns = ('gateway_id', 'name', 'path', 'status')

    form_args = {
        'gateway_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()]
        },
        'name': {
            'validators' : [validators.InputRequired()],
            'label': 'Image Name'
        }
    }  
    
    column_formatters = {
        'modified_on': _mod_date_formatter,
        'image': _list_thumbnail,
        'status': _status_formatter,
        'modified_by': _mod_by_formatter,
        'created_by': _cre_by_formatter,
        'created_on': _cre_date_formatter
    }

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())

    def is_accessible(self):
        return current_user.is_authenticated

class ManagerLogosView(LogosView):
    def get_query(self):
      return self.session.query(self.model).filter(self.model.gw_id==current_user.mpop_id)

    def get_count_query(self):
      return self.session.query(func.count('*')).filter(self.model.gw_id==current_user.mpop_id)

    form_args = {
        'gateway_id': {
            'label': 'Gateway/MPOP ID',
            'validators' : [validators.InputRequired()],
            'query_factory' : lambda:  db.session.query(Gateways).filter_by(gw_id=current_user.mpop_id)
        },
        'name': {
            'validators' : [validators.InputRequired()],
            'label': 'Image Name'
        }
    }

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 2)

class UserLogosView(ManagerLogosView):

    form_columns = ('gateway_id', 'name', 'path', 'status')

    def on_model_change(self, form, model, is_created):
        model.modified_by = current_user
        if is_created:
            model.created_by = current_user
            model.created_on = str(datetime.datetime.now())
            model.status = 0

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 2)

@event.listens_for(Logos, 'after_delete')
def del_image(mapper, connection, target):
    if target.filepath is not None:
        try:
            os.remove(target.filepath)
        except OSError:
            pass

class GatewayGroupsView(BaseView):
    column_list = ('name', 'gateways')

    def is_accessible(self):
        return (current_user.is_authenticated and current_user.role_id == 0)


# Create customized index view class that handles login & registration

class AdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(AdminIndexView, self).index()

    @expose('/sign-in/', methods=('GET', 'POST'))
    def login_view(self):
        # handle user login
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            if user:
                login_user(user)

        if current_user.is_authenticated:
            return redirect(url_for('.index'))
        #link = '<p>Don\'t have an account? <a href="' + url_for('.register_view') + '">Click here to register.</a></p>'
        link = '<p></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return self.render('admin_login.html', form=form)

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = Admin_Users()

            form.populate_obj(user)
            # we hash the users password to avoid saving it as plaintext in the db,
            # remove to use plain text:
            user.password = generate_password_hash(form.password.data)

            db.session.add(user)
            db.session.commit()

            login_user(user)
            return redirect(url_for('.index'))
        link = '<p>Already have an account? <a href="' + url_for('.login_view') + '">Click here to log in.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(AdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        logout_user()
        return redirect(url_for('.index'))


# Initialize flask-login
init_login()

# Create admin
admin = admin.Admin(app, 'Wild Weasel Admin', index_view=AdminIndexView(), base_template='my_master.html', template_mode='bootstrap3')
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True
#app.config['FLASK_ADMIN_SWATCH'] = 'flatly'

# Add view
admin.add_view(GatewayView(Gateways, db.session, name='Gateways'))
admin.add_view(GatewayGroupsView(GatewayGroup,db.session, name='Gateway Groups'))
admin.add_view(UserView(Admin_Users, db.session, name='Users'))
admin.add_view(ManagerUserView(Admin_Users, db.session, name='Users', endpoint='users_mgr'))
admin.add_view(DataLimitsView(Data_Limits, db.session, name="Data Limits"))
admin.add_view(ManagerDataLimitsView(Data_Limits, db.session, name="Data Limits", endpoint='limits_mgr'))
admin.add_view(UserDataLimitsView(Data_Limits, db.session, name="Data Limits", endpoint='limits_usr'))
admin.add_view(UptimesView(Uptimes, db.session, name="Portal Uptimes"))
admin.add_view(ManagerUptimesView(Uptimes, db.session, name="Portal Uptimes", endpoint='uptimes_mgr'))
admin.add_view(UserUptimesView(Uptimes, db.session, name="Portal Uptimes", endpoint='uptimes_usr'))
admin.add_view(LogosView(Logos, db.session))
admin.add_view(ManagerLogosView(Logos, db.session, name="Logos", endpoint='logos_mgr'))
admin.add_view(UserLogosView(Logos, db.session, name="Logos", endpoint='logos_usr'))
admin.add_view(AnnouncementsView(Announcements, db.session))
admin.add_view(ManagerAnnouncementsView(Announcements, db.session, name="Announcements", endpoint='announcements_mgr'))
admin.add_view(UserAnnouncementsView(Announcements, db.session, name="Announcements", endpoint='announcements_usr'))
admin.add_view(GroupAnnouncementsView(GroupAnnouncements, db.session, name="Group Announcements"))

if __name__ == '__main__':
    app.run()
