from flask import Flask, jsonify, request
from supabase import create_client, Client
import bcrypt
import os
from dotenv import load_dotenv
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from typing import Optional
import jwt
from datetime import datetime, timedelta
import functools

# Load environment variables from the .env file
load_dotenv()

# Initialize Flask app and Supabase client
app = Flask(__name__)
CORS(app, origins=os.environ.get("FRONTEND_URLS").split(","))
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Supabase configuration
url: Optional[str] = os.environ.get("SUPABASE_URL")
key: Optional[str] = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")


def generate_jwt(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(weeks=1),
    }
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")


def jwt_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")

        if auth_header:
            parts = auth_header.split(" ")
            if len(parts) == 2 and parts[0] == "Bearer":
                token = parts[1]

        if not token:
            return (
                jsonify({"status": "error", "message": "Token is missing or invalid!"}),
                401,
            )

        try:
            data = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            current_user = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"status": "error", "message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": "error", "message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated_function


@limiter.limit(
    "5 per minute", error_message="Too many requests, please try again later."
)
@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify(status="error", message=str(e.description)), 429


@app.route("/add-user", methods=["POST"])
@limiter.limit(
    "1 per minute", error_message="Too many attempts, please try again later..."
)
def add_user():
    data = request.get_json()

    if data is None:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return (
            jsonify(
                {"status": "error", "message": "Username and password are required"}
            ),
            400,
        )

    if len(username) > 50:
        limiter.reset()
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Username cannot be longer than 50 characters",
                }
            ),
            400,
        )

    if len(password) > 72:
        limiter.reset()
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Password cannot be longer than 72 characters, sorry.",
                }
            ),
            400,
        )
    elif len(password) <= 8:
        limiter.reset()
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "A secure password should be longer than 8 characters.",
                }
            ),
            400,
        )

    # Check if the username already exists in the database
    response = supabase.table("players").select("id").eq("username", username).execute()

    if response.data:
        print(response.data)
        return (
            jsonify(
                {"status": "error", "message": f"Username {username} is already taken"}
            ),
            409,
        )

    # If the username doesn't exist, proceed to create the user
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )
    response = (
        supabase.table("players")
        .insert({"username": username, "password": hashed_password})
        .execute()
    )

    if response and response.data:
        user_id = response.data[0].get("id")
        token = generate_jwt(user_id)
    else:
        user_id = None
        token = None
        return jsonify(
            {"status": "error", "message": "An unexpected error occurred..."}
        )

    return (
        jsonify(
            {
                "status": "success",
                "message": f"{username} added to database",
                "token": token,
                "userid": user_id,
            }
        ),
        200,
    )


@app.route("/login-user", methods=["POST"])
@limiter.limit(
    "5 per minute", error_message="Too many attempts, please try again later..."
)
def login_user():
    data = request.get_json()
    if data is None:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    response = (
        supabase.table("players")
        .select("id, password")
        .eq("username", username)
        .execute()
    )
    user_data = response.data

    if user_data and len(user_data) > 0:
        hashed_password = user_data[0]["password"]
        if bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
            user_id = user_data[0]["id"]
            token = generate_jwt(user_id)
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "Login successful!",
                        "token": token,
                    }
                ),
                200,
            )
        else:
            return (
                jsonify({"status": "error", "message": "Invalid username or password"}),
                401,
            )
    else:
        return (
            jsonify({"status": "error", "message": "Invalid username or password"}),
            401,
        )


@app.route("/get-challenge", methods=["POST"])
@jwt_required
def get_challenge(current_user):
    # data = request.get_json()
    # if data is None:
    #     return jsonify({"status": "error", "message": "No data provided"}), 400

    # userid = data.get("userid")
    # if not userid:
    #     return jsonify({"error": "User ID is required"}), 400

    response = supabase.table("players").select("*").eq("id", current_user).execute()
    if response.data:
        challenge = response.data[0].get("challenge_num")
        username = response.data[0].get("username")
    else:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "No challenge number or userid found for this user",
                }
            ),
            404,
        )

    return (
        jsonify({"status": "success", "message": username, "challenge": challenge}),
        200,
    )


@app.route("/get-userid", methods=["POST"])
@jwt_required
def get_userid(current_user):
    data = request.get_json()
    if data is None:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    username = data.get("username")
    if not username:
        return jsonify({"error": "Username is required"}), 400

    response = supabase.table("players").select("id").eq("username", username).execute()
    if response.data:
        userid = response.data[0].get("id")
        return jsonify({"status": "success", "id": userid, "message": username}), 200
    else:
        return (
            jsonify({"status": "error", "message": "No userid found for this user"}),
            404,
        )


@app.route("/update-challenge-num/<int:value>", methods=["POST"])
@limiter.limit(
    "5 per minute", error_message="Too many attempts, please try again later..."
)
@jwt_required
def add_to_challenge(current_user, value):
    # data = request.get_json()
    # if data is None:
    #     return jsonify({"status": "error", "message": "No data provided"}), 400

    # userid = data.get("userid")
    # if not userid:
    #     return jsonify({"status": "error", "message": "UserID is required"}), 400

    # Step 1: Retrieve the current challenge_num for the userid
    # response = (
    #     supabase.table("players").select("challenge_num").eq("id", current_user).execute()
    # )

    # if response.data:
    #     current_challenge_num = response.data[0]["challenge_num"]

    #     # Step 2: Add the amount to the current challenge_num
    #     new_challenge_num = current_challenge_num + amount

    # Step 3: Update the database with the new challenge_num
    update_response = (
        supabase.table("players")
        .update({"challenge_num": value})
        .eq("id", current_user)
        .execute()
    )

    if update_response.data:
        return (
            jsonify(
                {
                    "status": "success",
                    "message": f"changed challenge num to {value}",
                }
            ),
            200,
        )
    else:
        return (
            jsonify(
                {"status": "error", "message": "Failed to update challenge number"}
            ),
            500,
        )
    # else:
    #     return (
    #         jsonify({"status": "error", "message": "No userid found for this user"}),
    #         404,
    #     )


@app.route("/get-userdata", methods=["POST"])
@jwt_required
def get_all_data(current_user):
    # data = request.get_json()
    # if data is None:
    #     return jsonify({"status": "error", "message": "No data provided"}), 400

    # userid = data.get("userid")
    # if not userid:
    #     return jsonify({"error": "User ID is required"}), 400

    response = (
        supabase.table("players")
        .select("id, created_at, username, challenge_num, completed")
        .eq("id", current_user)
        .execute()
    )

    if response.data:
        return (
            jsonify(
                {
                    "status": "success",
                    "message": "Here is your user data",
                    "data": response.data[0],
                }
            ),
            200,
        )

    return jsonify({"status": "error", "message": "User not found"}), 404


@app.route("/delete-account", methods=["DELETE"])
@jwt_required
def delete_account(current_user):
    response = supabase.table("players").delete().eq("id", current_user).execute()

    if response.data:
        return (
            jsonify({"status": "success", "message": "Account successfully deleted."}),
            200,
        )
    else:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to delete account. Please try again later.",
                }
            ),
            500,
        )


@app.route("/check-token", methods=["POST"])
def check_token():
    token = None
    if "Authorization" in request.headers:
        token = request.headers["Authorization"].split(" ")[1]

    if not token:
        return jsonify({"status": "error", "message": "Token is missing!"}), 401

    try:
        # Decode the token to get user_id
        decoded_token = jwt.decode(
            token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"]
        )
        user_id = decoded_token.get("user_id")

        # Check if user_id exists in the database
        response = supabase.table("players").select("id").eq("id", user_id).execute()

        if not response.data:
            return jsonify({"status": "error", "message": "User does not exist!"}), 404

        return (
            jsonify(
                {"status": "success", "message": "Token is valid and user exists!"}
            ),
            200,
        )

    except jwt.ExpiredSignatureError:
        return jsonify({"status": "error", "message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"status": "error", "message": "Token is invalid!"}), 401


if __name__ == "__main__":
    app.run(debug=True)  # This will change for production, just here for debugging
