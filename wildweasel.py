from flask import Flask, redirect, url_for, request, make_response, url_for
from pyrad.dictionary import Dictionary
from pyrad.client import Client
from pyrad.packet import Packet
from models import db, Transaction, Devices, Registered_Users
import pyrad.packet
import datetime
import socket
import uuid

app = Flask(__name__)

POSTGRES = {
    'user': 'wildweasel',
    'pw': 'ap0ll0',
    'db': 'wildweasel',
    'host': '192.168.88.145',
    'port': '5432',
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

@app.route('/')
def hello_world():
    return "Hello! Welcome to WildWeasel!"

@app.route('/ping/')
def ping():
    return "Pong"

@app.route('/login/', methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        srv = Client(server="192.168.88.145", secret=b"ap0ll0", dict=Dictionary("dictionary"))
        uname = request.form['uname']
        pword = request.form['pword']
        package = request.form['package']
        token = request.cookies.get('token')
        if package == 'Registered':
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
                if Registered_Users.query.filter_by(uname=uname).count() > 0:
                    user = Registered_Users.query.filter_by(uname=uname).first()
                    if datetime.datetime.now().timestamp() - datetime.datetime.strptime(user.last_active, '%Y-%m-%d %H:%M:%S.%f').timestamp() > 86400:
                        if user.month_data >= user.month_limit:
                            return "Monthly usage limit exceeded!"
                    else:
                        if user.registered_data >= user.registered_limit:
                            return "Daily usage limit exceeded!"
                else:
                    new_user = Registered_Users(uname=uname, registered_data=0, registered_limit=100000000, month_data=0, month_limit=5000000000, last_active=str(datetime.datetime.now()), last_record=0)
                    db.session.add(new_user)
                    db.session.commit()
                trans = Transaction.query.filter_by(token=token).first()
                trans.stage = "authenticated"
                trans.package = "Registered"
                trans.uname = uname
                trans.date_modified = str(datetime.datetime.now())
                db.session.commit()
                acct_req = srv.CreateAcctPacket(User_Name=trans.uname)
                acct_req["NAS-Identifier"] = trans.gw_sn
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
                message = "Access denied!"
                resp_string =  "<html><head>LOGIN FORM</head><br><br><br><body><form action='/login/' method='post'>Username: <input type='text' name='uname'/><br>Password: <input type='password' name='pword'/><input type='hidden' name='package' value='Registered'/><br><br><input type='submit' value='submit'/></form><br><br><form action='/login/' method='post'><input type='hidden' name='uname' value='None'/><input type='hidden' name='pword' value='None'/><input type='hidden' name='package' value='Free'/><input type='submit' value='Free Access'/></form><br><br><br><h3>" + message + "</h3></body></html>"
                resp = make_response(resp_string)
                resp.set_cookie('token', token)
                return resp
        else:
            trans = Transaction.query.filter_by(token=token).first()
            if Devices.query.filter_by(mac=trans.mac).count() > 0:
                device = Devices.query.filter_by(mac=trans.mac).first()
                if datetime.datetime.now().timestamp() - datetime.datetime.strptime(device.last_active, '%Y-%m-%d %H:%M:%S.%f').timestamp() > 86400:
                    if device.month_data >= device.month_limit:
                        return "Monthly usage limit exceeded!"
                else:
                    if device.free_data >= device.free_limit:
                        return "Daily usage limit exceeded!"
            else:
                new_device = Devices(mac=trans.mac, free_data=0, free_limit=50000000, month_data=0, month_limit=2500000000, last_active=str(datetime.datetime.now()), last_record=0)
                db.session.add(new_device)
                db.session.commit()
            trans.stage = "authenticated"
            trans.package = "One-Click"
            trans.uname = trans.mac
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            acct_req = srv.CreateAcctPacket(User_Name=trans.mac)
            acct_req["NAS-Identifier"] = trans.gw_sn
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
        gw_id_n = request.args.get('gw_id', default = '', type = str)
        gw_sn_n = request.args.get('gw_sn', default = '', type = str)
        gw_address_n = request.args.get('gw_address', default = '', type = str)
        gw_port_n = request.args.get('gw_port', default = '', type = str)
        ip_n = request.args.get('ip', default = '', type = str)
        mac_n = request.args.get('mac', default = '', type = str)
        apmac_n = request.args.get('apmac', default = '', type = str)
        ssid_n = request.args.get('ssid', default = '', type = str)
        vlanid_n = request.args.get('vlanid', default = '', type = str)
        token_n = request.cookies.get('token')
        device_n = request.headers.get('User-Agent')
        if Transaction.query.filter_by(mac=mac_n).filter_by(device=device_n).count() > 0:
            token_n = Transaction.query.filter_by(mac=mac_n).filter_by(device=device_n).first().token
        if token_n == None:
            token_n = uuid.uuid4().hex
            while Transaction.query.filter_by(token=token_n).count() > 0:
                token_n = uuid.uuid4().hex
            trans = Transaction(gw_sn=gw_sn_n, ip=ip_n, gw_address=gw_address_n, gw_port=gw_port_n, mac=mac_n, apmac=apmac_n, ssid=ssid_n, vlanid=vlanid_n, token=token_n, stage="capture", device=device_n, date_modified=str(datetime.datetime.now()))
            db.session.add(trans)
            db.session.commit()
        else:
            trans = Transaction.query.filter_by(token=token_n).first()
            trans.gw_sn = gw_sn_n
            trans.ip = ip_n
            trans.gw_address = gw_address_n
            trans.gw_port = gw_port_n
            trans.mac = mac_n
            trans.apmac = apmac_n
            trans.ssid = ssid_n
            trans.vlanid = vlanid_n
            trans.stage = "capture"
            trans.device = device_n
            trans.date_modified = str(datetime.datetime.now())
            db.session.commit()
            if trans.stage == "counters":
                return redirect(url_for('portal'))
        resp_string = "<html><head>LOGIN FORM</head><br><br><br><body><form action='/login/' method='post'>Username: <input type='text' name='uname'/><br>Password: <input type='password' name='pword'/><input type='hidden' name='package' value='Registered'/><br><br><input type='submit' value='submit'/></form><br><br><form action='/login/' method='post'><input type='hidden' name='uname' value='None'/><input type='hidden' name='pword' value='None'/><input type='hidden' name='package' value='Free'/><input type='submit' value='Free Access'/></form></body></html>"
        resp = make_response(resp_string)
        resp.set_cookie('token', token_n)
        return resp

@app.route('/auth/')
def auth():
    token_n = request.args.get('token', default = '', type = str)
    stage_n = request.args.get('stage', default = '', type = str)
    incoming_n = request.args.get('incoming', default = '', type = int)
    outgoing_n = request.args.get('outgoing', default = '', type = int)
    trans = Transaction.query.filter_by(token=token_n).first()
    srv = Client(server="192.168.88.145", secret=b"ap0ll0", dict=Dictionary("dictionary"))
    acct_req = srv.CreateAcctPacket(User_Name=trans.uname)
    acct_req["NAS-Identifier"] = trans.gw_sn
    acct_req["Framed-IP-Address"] = trans.ip
    acct_req["Acct-Session-Id"] = trans.mac

    if stage_n == "logout":
        return "Auth: 0"

    if trans.package == "Registered":
        user = Registered_Users.query.filter_by(uname=trans.uname).first()
        if (user.registered_data + ((incoming_n + outgoing_n) - user.last_record)) >= user.registered_limit:
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
            user.registered_data = (user.registered_data + ((incoming_n + outgoing_n) - user.last_record))
            user.month_data = (user.month_data + ((incoming_n + outgoing_n) - user.last_record))
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
            user.registered_data = (user.registered_data + ((incoming_n + outgoing_n) - user.last_record))
            user.month_data = (user.month_data + ((incoming_n + outgoing_n) - user.last_record))
            user.last_record = (incoming_n + outgoing_n)
            db.session.commit()
    else:
        device = Devices.query.filter_by(mac=trans.mac).first()
        if (device.free_data + ((incoming_n + outgoing_n) - device.last_record)) >= device.free_limit:
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
            device.free_data = (device.free_data + ((incoming_n + outgoing_n) - device.last_record))
            device.month_data = (device.month_data + ((incoming_n + outgoing_n) - device.last_record))
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
            device.free_data = (device.free_data + ((incoming_n + outgoing_n) - device.last_record))
            device.month_data = (device.month_data + ((incoming_n + outgoing_n) - device.last_record))
            device.last_record = (incoming_n + outgoing_n)
            db.session.commit()

    return "Auth: 1"

@app.route('/portal/')
def portal():
    return "Show data usage here"

if __name__ == '__main__':
   app.run()
