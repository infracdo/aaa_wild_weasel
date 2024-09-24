from pyrad.client import Client
from pyrad.dictionary import Dictionary
import random
import socket
import sys
import pyrad.packet


# srv = Client(server="202.60.10.140", secret=b"ap0ll0", dict=Dictionary("dictionary"))
srv = Client(server="localhost",authport=1812, secret=b"ap0ll0", dict=Dictionary("dictionary"))
req = srv.CreateAcctPacket(User_Name="admin")
print(srv.SendPacket(req))

#req["Event-Timestamp"] = 2346743541
# req["Acct-Status-Type"] = "Alive"
# req["Acct-Delay-Time"] = 0
# req["Called-Station-Id"] = "23000000000"
# req["Calling-Station-Id"] = "263000000000"
# req["Acct-Session-Id"] = "test_session_id"
# req["Acct-Session-Time"] = "0"
# req["NAS-Identifier"] = "test_gatway"
# req["Framed-IP-Address"] = "0.0.0.0"
# req["Login-LAT-Service"] = "test_mode"
# req["Connect-Info"] = "test_device"
# req["Login-LAT-Node"] = "test.test.test.test"

#print("Sending accounting start packet")
# reply = srv.SendPacket(req)
# print(reply)
