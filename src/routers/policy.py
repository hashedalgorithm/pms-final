import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.enums import AccessLevel
from models.policyModel import CreatedBy, PolicyModel, Rules
from models.userModel import UserModel
import services.dbMethods as dbMethods

policy_bp = Blueprint('policy', __name__)

@policy_bp.route("/setPolicy", methods=["POST"])
@jwt_required()
def set_policy():
    try:
        user_claims = get_jwt_identity()
        user = UserModel.parse_raw(user_claims)  # type: ignore

        if user.access_level.value != AccessLevel.admin.value:
            return jsonify({"detail": "Forbidden"}), 403

        data = request.json
        min_upper_case_letters = data.get("min_upper_case_letters", 1)
        min_lower_case_letters = data.get("min_lower_case_letters", 1)
        min_digits = data.get("min_digits", 1)
        min_symbols = data.get("min_symbols", 1)
        min_length = data.get("min_length", 8)

        if any(param is None for param in [min_upper_case_letters, min_lower_case_letters, min_digits, min_symbols, min_length]):
            return jsonify({"detail": "Missing parameters"}), 400

        policy = PolicyModel(
            id=uuid.uuid4(),
            created_at=datetime.utcnow().timestamp(),
            created_by=CreatedBy(admin_id=uuid.uuid4()),
            rules=Rules(
                min_upper_case_letters=min_upper_case_letters,
                min_lower_case_letters=min_lower_case_letters,
                min_digits=min_digits,
                min_symbols=min_symbols,
                min_length=min_length,
            ),
        )

        dbMethods.add_policy(policy)
        return jsonify({"message": "Policy Updated"}), 200

    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500

@policy_bp.route("/getPolicy", methods=["GET"])
@jwt_required()
def get_policy():
    try:
        policy = dbMethods.get_policy()

        if policy:
            return jsonify({"policy": policy.json()}), 200

        return jsonify({"detail": "Policy not found"}), 404
    except Exception:
        return jsonify({"detail": "Internal Server Error"}), 500
