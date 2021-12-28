from flask import abort, request
import jwt
from constants import *


def auth_required(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            jwt.decode(token, secret, algorithms=algo)
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        try:
            user = jwt.decode(token, secret, algorithms=algo)
            role = user.get("role")
            if role != "admin":
                abort(401)
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)

    return wrapper



