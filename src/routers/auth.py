from decouple import config
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from models.enums import AccessLevel
from models.userModel import LoginModel, UserModel
import services.redis_sessionlist as sessionlist
from services.dbMethods import user_login

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        login_user = LoginModel(**data)
        login_result = user_login(username=login_user.username, password=login_user.password)
        if not login_result:
            return jsonify({"detail": "Invalid credentials"}), 401

        user = login_result

        access_token = create_access_token(identity=user.json(), fresh=False)
        refresh_token = create_refresh_token(identity=user.json())

        sessionlist.add_session_tokens(
            access_jti=get_jwt_identity(),
            refresh_jti=get_jwt_identity(),
        )

        return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@auth_bp.route("/login/new", methods=["POST"])
def fresh_login():
    try:
        data = request.json
        login_user = LoginModel(**data)
        login_result = user_login(username=login_user.username, password=login_user.password)
        if not login_result:
            return jsonify({"detail": "Invalid credentials"}), 401

        user = login_result

        access_token = create_access_token(identity=user.json(), fresh=True)

        sessionlist.add_session_tokens(access_jti=get_jwt_identity())

        return jsonify({"access_token": access_token}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    try:
        jti = get_jwt_identity()
        if jti:
            sessionlist.delete_session_tokens(jti=jti)

        return jsonify({"detail": "Successfully logged out"}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500
