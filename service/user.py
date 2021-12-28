import base64
import hashlib
import hmac
import calendar
import datetime

import jwt

from dao.user import UserDAO
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS, secret, algo


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, bid):
        return self.dao.get_one(bid)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_d):
        user_d["password"] = self.get_hash(user_d.get("password"))
        return self.dao.create(user_d)

    def update(self, user_d):
        user_d["password"] = self.get_hash(user_d.get("password"))
        self.dao.update(user_d)
        return self.dao

    def get_hash(self, password):
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_passwords(self, password_hash, password):
        return hmac.compare_digest(
            base64.b64decode(password_hash),
            hashlib.pbkdf2_hmac('sha256', password.encode(), PWD_HASH_SALT, PWD_HASH_ITERATIONS)
        )

    def auth_user(self, username):
        return self.dao.auth_user(username)

    def get_token(self, data):
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)
        return {"access_token": access_token, "refresh_token": refresh_token}



