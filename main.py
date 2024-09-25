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


@limiter.limit(
    "5 per minute", error_message="Too many requests, please try again later."
)
@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify(status="error", message=str(e.description)), 429


@app.route("/add-user", methods=["POST"])
@limiter.limit(
    "5 per minute", error_message="Too many attempts, please try again later..."
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
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Password cannot be longer than 72 characters, sorry.",
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
    supabase.table("players").insert(
        {"username": username, "password": hashed_password}
    ).execute()

    return (
        jsonify({"status": "success", "message": f"{username} added to database"}),
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
        supabase.table("players").select("password").eq("username", username).execute()
    )
    user_data = response.data

    if user_data and len(user_data) > 0:
        hashed_password = user_data[0]["password"]
        if bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
            return jsonify({"status": "success", "message": "Login successful!"}), 200
        else:
            return (
                jsonify({"status": "error", "message": "Invalid username or password"}),
                401,
            )
    else:
        return jsonify({"status": "error", "message": "User not found"}), 404


@app.route("/get-challenge", methods=["POST"])
def get_challenge():
    data = request.get_json()
    if data is None:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    userid = data.get("userid")
    if not userid:
        return jsonify({"error": "User ID is required"}), 400

    response = supabase.table("players").select("*").eq("id", userid).execute()
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
def get_userid():
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


@app.route("/add-to-challenge/<int:amount>", methods=["POST"])
@limiter.limit("5 per minute", error_message="Too many attempts, please try again later...")
def add_to_challenge(amount):
    data = request.get_json()
    if data is None:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    userid = data.get("userid")
    if not userid:
        return jsonify({"status": "error", "message": "UserID is required"}), 400

    # Step 1: Retrieve the current challenge_num for the userid
    response = supabase.table("players").select("challenge_num").eq("id", userid).execute()
    
    if response.data:
        current_challenge_num = response.data[0]["challenge_num"]

        # Step 2: Add the amount to the current challenge_num
        new_challenge_num = current_challenge_num + amount

        # Step 3: Update the database with the new challenge_num
        update_response = supabase.table("players").update({"challenge_num": new_challenge_num}).eq("id", userid).execute()

        if update_response.data:
            return jsonify({"status": "success", "message": f"changed challenge num to {new_challenge_num}"}), 200
        else:
            return jsonify({"status": "error", "message": "Failed to update challenge number"}), 500
    else:
        return jsonify({"status": "error", "message": "No userid found for this user"}), 404



@app.route("/get-userdata", methods=["POST"])
@limiter.limit(
    "10 per minute", error_message="Too many attempts, please try again later..."
)
def get_all_data():
    data = request.get_json()
    if data is None:
        return jsonify({"status": "error", "message": "No data provided"}), 400

    userid = data.get("userid")
    if not userid:
        return jsonify({"status": "error", "message": "UserID is required"}), 400

    response = supabase.table("players").select("id, created_at, username, challenge_num").eq("id", userid).execute()

    if response.data:
        return (
            jsonify({"status": "success", "message": "success", **response.data[0]}),
            200,
        )
    else:
        return (
            jsonify({"status": "error", "message": "No userid found for this user"}),
            404,
        )


if __name__ == "__main__":
    app.run(debug=True)
