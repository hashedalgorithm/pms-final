from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from routers.auth import auth_bp
from routers.password import password_bp
from routers.policy import policy_bp
from routers.accounts import accounts_bp

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"  # Change this to your secret key
jwt = JWTManager(app)

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(password_bp, url_prefix="/password")
app.register_blueprint(policy_bp, url_prefix="/policy")
app.register_blueprint(accounts_bp, url_prefix="/accounts")

@app.errorhandler(Exception)
def handle_exception(e):
    response = e.get_response()
    response.data = jsonify({"detail": str(e)})
    response.content_type = "application/json"
    return response

if __name__ == "__main__":
    app.run(debug=True)
