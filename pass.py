
import hashlib

user_entered_password = '123456'
salt = "ap0ll0"
db_password = user_entered_password + salt
h = hashlib.md5(db_password.encode()).hexdigest()
print(h)