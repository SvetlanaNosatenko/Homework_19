from flask_restx import Resource, Namespace
from flask import abort, request
import jwt
from constants import *
from implemented import user_service

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get('username', None)
        password = req_json.get('password', None)

        if None in [username, password]:
            abort(400)

        user = user_service.auth_user(username)

        if user is None:
            return {"error": "Неверные учётные данные"}, 401

        compare = user_service.compare_passwords(password_hash=user.password, password=password)

        if not compare:
            return {"error": "Неверные учётные данные"}, 401

        data = {
            "username": user.username,
            "role": user.role
        }
        rez = user_service.get_token(data=data)
        return rez, 201

    def put(self):
        req_json = request.json
        refresh_token = req_json.get("refresh_token")

        if refresh_token is None:
            abort(400)

        data = jwt.decode(jwt=refresh_token, key=secret, algorithms=[algo])

        username = data.get("username")
        user = user_service.auth_user(username)

        data = {"username": user.username,
                "role": user.role
                }

        rez = user_service.get_token(data=data)
        return rez, 201