from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.enums import AccessLevel
from models.userModel import UserModel
import services.dbMethods as dbMethods
import services.passwordMethods as passwordMethods

password_bp = Blueprint('password', __name__)

@password_bp.route("/generatePasswords", methods=["GET"])
@jwt_required()
def generate_passwords():
    try:
        user_claims = get_jwt_identity()
        user = UserModel.parse_raw(user_claims)  # type: ignore

        if user.access_level.value != AccessLevel.admin.value:
            return jsonify({"detail": "Forbidden"}), 403

        policy = dbMethods.get_policy()
        if policy:
            passwords = passwordMethods.generate_passwords(policy)

            if passwords:
                return jsonify({"passwords": passwords}), 200
        return jsonify({"detail": "Failed to generate passwords"}), 500
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@password_bp.route("/checkIfPasswordLeaked", methods=["GET"])
@jwt_required()
def check_password_leak():
    try:
        password = request.args.get("password")
        leak_count = passwordMethods.check_leaks_via_HIBP(password)
        return jsonify({"leak_count": leak_count}), 200
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500
