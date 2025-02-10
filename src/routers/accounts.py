from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.enums import AccessLevel
import services.dbMethods as dbMethods
import services.passwordMethods as passwordMethods
from models.userModel import UserModel

accounts_bp = Blueprint('accounts', __name__)

@accounts_bp.route("/addApplicationCreds", methods=["GET"])
@jwt_required()
def add_application_creds():
    try:
        user_claims = get_jwt_identity()
        user = UserModel.parse_raw(user_claims)  # type: ignore

        if user.access_level.value != AccessLevel.admin.value:
            return jsonify({"detail": "Forbidden"}), 403

        data = request.args
        username = data.get("username")
        application_name = data.get("application_name")
        password = data.get("password")

        result = dbMethods.add_application_password_pair(username, application_name, password)

        if not result:
            return jsonify({"detail": "Failed to add credentials"}), 500

        return jsonify({"message": "Credentials added successfully"}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@accounts_bp.route("/getApplicationCreds", methods=["GET"])
@jwt_required()
def get_application_creds():
    try:
        user_claims = get_jwt_identity()
        user = UserModel.parse_raw(user_claims)  # type: ignore

        passwords = dbMethods.get_all_application_password_pairs(user.username)

        if not passwords:
            return jsonify({"detail": "No credentials found"}), 404

        return jsonify({"passwords": passwords}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@accounts_bp.route("/addUser", methods=["GET"])
@jwt_required()
def add_user():
    try:
        user_claims = get_jwt_identity()
        user = UserModel.parse_raw(user_claims)  # type: ignore

        if user.access_level.value != AccessLevel.admin.value:
            return jsonify({"detail": "Forbidden"}), 403

        data = request.args
        username = data.get("username")
        password = data.get("password")
        access_level = AccessLevel(data.get("access_level"))

        policy = dbMethods.get_policy()

        if not policy:
            return jsonify({"detail": "Policy not found"}), 500

        if not passwordMethods.validate_password(password, policy):
            return jsonify({"detail": "Password does not meet policy requirements"}), 400

        if passwordMethods.check_leaks_via_HIBP(password) > 0:
            return jsonify({"detail": "Password has been leaked"}), 400

        ret_code, message = dbMethods.add_user(username, password, access_level=access_level)

        if ret_code != 0:
            return jsonify({"detail": message}), 400

        return jsonify({"message": message}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@accounts_bp.route("/changeUserPassword", methods=["GET"])
@jwt_required(fresh=True)
def change_user_password():
    try:
        user_claims = get_jwt_identity()
        user = UserModel.parse_raw(user_claims)  # type: ignore

        data = request.args
        password = data.get("password")

        policy = dbMethods.get_policy()
        if not policy:
            return jsonify({"detail": "Policy not found"}), 500

        if not passwordMethods.validate_password(password, policy):
            return jsonify({"detail": "Password does not meet policy requirements"}), 400

        if passwordMethods.check_leaks_via_HIBP(password) > 0:
            return jsonify({"detail": "Password has been leaked"}), 400

        ret_code, message = dbMethods.change_user_pass(user.username, password)

        if ret_code != 0:
            return jsonify({"detail": message}), 400

        return jsonify({"message": message}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500
