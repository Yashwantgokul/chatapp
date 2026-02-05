
import os
from flask import Flask, request, render_template, flash, redirect, url_for, session, jsonify
from supabase import create_client, Client
from gotrue.errors import AuthApiError
from dotenv import load_dotenv
import traceback

from encryption import encrypt_message, decrypt_message, AES_KEY

load_dotenv()

# --- App & DB Initialization ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://jnywwpkeabojfgvtlwqr.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "sb_publishable_lD5iD1gAXxjSsiXYBMXTVQ_8PEUNb62")

supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__, template_folder='src')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key-that-you-should-change")

def get_user_client() -> Client | None:
    if 'access_token' in session:
        client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        client.auth.set_session(
            access_token=session["access_token"],
            refresh_token=session.get("refresh_token", "")
        )
        return client
    return None

# --- Auth & Core Routes ---
@app.route("/")
def login():
    return render_template('login.html')

@app.route("/signup")
def signup():
    return render_template('signup.html')

@app.route("/chat")
def chat():
    if 'user' not in session:
        flash("Please log in to access the chat.", "error")
        return redirect(url_for("login"))
    return render_template('chat.html')

@app.route("/signup-handler", methods=["POST"])
def signup_handler():
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        # Create user in Supabase Auth
        res = supabase_admin.auth.admin.create_user({"email": email, "password": password, "email_confirm": True})
        user_id = res.user.id

        # Check if profile already exists before inserting
        existing_profile = supabase_admin.table('profiles').select('id').eq('id', user_id).execute()
        if not existing_profile.data:
            # If no profile exists, insert it
            supabase_admin.table('profiles').insert({'id': user_id, 'email': email}).execute()
        
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))
    except AuthApiError as e:
        if "User already exists" in str(e):
            flash("An account with this email already exists. Please log in.", "error")
            return redirect(url_for("login"))
        flash(f"Could not create account: {e}", "error")
        return redirect(url_for("signup"))
    except Exception as e:
        traceback.print_exc()
        flash(f"An unexpected error occurred during signup: {e}", "error")
        return redirect(url_for("signup"))

@app.route("/login-handler", methods=["POST"])
def login_handler():
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        temp_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        user_session = temp_client.auth.sign_in_with_password({"email": email, "password": password})
        session['user'] = user_session.user.dict()
        session['access_token'] = user_session.session.access_token
        session['refresh_token'] = user_session.session.refresh_token
        return redirect(url_for("chat"))
    except AuthApiError:
        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))
    except Exception as e:
        traceback.print_exc()
        flash(f"An unexpected error occurred during login: {e}", "error")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# --- API Routes ---
@app.before_request
def before_request_func():
    if request.path.startswith('/api/') and 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

@app.route("/api/me")
def get_current_user():
    return jsonify(session['user'])

@app.route("/api/conversations")
def get_conversations():
    user_client = get_user_client()
    if not user_client:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session['user']['id']

    # ---- STEP 1: fetch conversations ----
    try:
        convos_res = (
            user_client
            .table("conversations")
            .select("id, participant_ids, created_at")
            .contains("participant_ids", [user_id])
            .execute()
        )
        conversations = convos_res.data or []
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "error": "Failed fetching conversations",
            "details": str(e)
        }), 500

    if not conversations:
        return jsonify([])

    # ---- STEP 2: fetch profiles ----
    try:
        participant_ids = set()
        for c in conversations:
            participant_ids.update(c.get("participant_ids", []))

        profiles_res = (
            user_client
            .table("profiles")
            .select("id, email")
            .in_("id", list(participant_ids))
            .execute()
        )
        profiles = profiles_res.data or []
        profile_map = {p["id"]: p["email"] for p in profiles}
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "error": "Failed fetching profiles",
            "details": str(e)
        }), 500

    # ---- STEP 3: fetch messages ----
    try:
        convo_ids = [c["id"] for c in conversations]

        messages_res = (
            user_client
            .table("messages")
            .select("conversation_id, ciphertext, iv, sender_id, created_at") # Fetch ciphertext and iv
            .in_("conversation_id", convo_ids)
            .order("created_at", desc=True)
            .execute()
        )
        messages = messages_res.data or []
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "error": "Failed fetching messages",
            "details": str(e)
        }), 500

    # ---- STEP 4: build response ----
    last_message_map = {}
    for m in messages:
        cid = m["conversation_id"]
        if cid not in last_message_map:
            last_message_map[cid] = m

    response = []
    for c in conversations:
        other_user_id = next(
            (pid for pid in c["participant_ids"] if pid != user_id),
            None
        )

        lm = last_message_map.get(c["id"])
        last_message_content = None
        if lm and lm.get("ciphertext") and lm.get("iv"):
            last_message_content = decrypt_message(lm["ciphertext"], lm["iv"], AES_KEY)

        response.append({
            "id": c["id"],
            "other_user_id": other_user_id,
            "other_user_email": profile_map.get(other_user_id, "Unknown"),
            "last_message": last_message_content, # Decrypted last message
            "timestamp": lm["created_at"] if lm else c["created_at"],
            "last_message_sender_id": lm["sender_id"] if lm else None
        })

    return jsonify(response)

@app.route("/api/messages/<conversation_id>")
def get_messages(conversation_id):
    user_client = get_user_client()
    try:
        # Fetch ciphertext and iv, and content for backward compatibility
        messages = user_client.table('messages').select('id, conversation_id, content, ciphertext, iv, sender_id, created_at').eq('conversation_id', conversation_id).order('created_at').execute().data
        
        # PHASE 1: Confirm the real backend error
        print("Fetched messages from DB:", messages)

        processed_messages = []
        for msg in messages:
            # PHASE 2: Make message decoding safe
            try:
                if msg.get("ciphertext") and msg.get("iv"):
                    msg["content"] = decrypt_message(msg["ciphertext"], msg["iv"], AES_KEY)
                else:
                    msg["content"] = msg.get("content") or ""
            except Exception as e:
                print("Decryption error:", e)
                msg["content"] = "[Undecipherable]"

            # Handle file URL generation
            # try:
            #     if msg.get("file_path"):
            #         signed = user_client.storage.from_("attachments").create_signed_url(msg["file_path"], 3600) # 1 hour
            #         msg["file_url"] = signed["signedURL"]
            #     else:
            #         msg["file_url"] = None
            # except Exception as file_error:
            #     traceback.print_exc()
            #     print(f"Failed to generate file URL for message ID {msg.get('id')} path {msg.get('file_path')}: {file_error}")
            #     msg["file_url"] = None
                
            # PHASE 3 & 4: Fix JSON serialization and return clean objects
            processed_messages.append({
                "id": msg.get("id"),
                "conversation_id": msg.get("conversation_id"),
                "sender_id": msg.get("sender_id"),
                "created_at": str(msg.get("created_at")) if msg.get("created_at") else None,
                "content": msg.get("content") or ""
            })

        return jsonify(processed_messages)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to fetch messages: {e}"}), 500

@app.route("/api/send-message", methods=["POST"])
def send_message():
    user_client = get_user_client()
    if not user_client:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    content = data.get('content')
    recipient_email = data.get('recipient_email')
    conversation_id = data.get('conversation_id')

    if not content or not content.strip():
        return jsonify({"error": "Message content cannot be empty"}), 400

    sender = session['user']
    sender_id = sender['id']

    try:
        # Encrypt the message content
        ciphertext, iv = encrypt_message(content, AES_KEY)

        message_data = {
            'ciphertext': ciphertext, 
            'iv': iv, 
            'sender_id': sender_id, 
            'sender_email': sender['email']
        }

        if conversation_id:
            message_data['conversation_id'] = conversation_id
            user_client.table('messages').insert(message_data).execute()
            return jsonify({"success": True, "conversation_id": conversation_id})

        elif recipient_email:
            if recipient_email == sender['email']:
                return jsonify({"error": "You cannot start a conversation with yourself."}), 400

            recipient_res = user_client.table('profiles').select('id').eq('email', recipient_email).execute()
            if not recipient_res.data:
                return jsonify({"error": "The specified recipient does not exist."}), 404
            recipient_id = recipient_res.data[0]['id']

            existing_convo_res = user_client.table('conversations').select('id').contains('participant_ids', [sender_id, recipient_id]).contained_by('participant_ids', [sender_id, recipient_id]).execute()

            if existing_convo_res.data:
                convo_id = existing_convo_res.data[0]['id']
            else:
                new_convo_res = user_client.table('conversations').insert({'participant_ids': [sender_id, recipient_id]}).execute()
                if not new_convo_res.data:
                    raise Exception("Failed to create a new conversation in the database.")
                convo_id = new_convo_res.data[0]['id']
            
            message_data['conversation_id'] = convo_id
            user_client.table('messages').insert(message_data).execute()
            return jsonify({"success": True, "conversation_id": convo_id})
        
        else:
            return jsonify({"error": "A recipient email or an existing conversation ID is required."}), 400

    except Exception as e:
        traceback.print_exc()
        error_message = getattr(e, 'message', str(e))
        return jsonify({"error": f"Failed to send message: {error_message}"}), 500

@app.route("/api/upload-attachment", methods=["POST"])
def upload_attachment():
    user_client = get_user_client()
    if not user_client:
        return jsonify({"error": "Unauthorized"}), 401

    conversation_id = request.form.get('conversation_id')
    content = request.form.get('content', '') # Get message content, if any

    if not conversation_id:
        return jsonify({"error": "conversation_id is required"}), 400

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    sender_id = session['user']['id']
    sender_email = session['user']['email']

    try:
        # Upload file to Supabase Storage
        file_path_in_bucket = f"{conversation_id}/{file.filename}"
        user_client.storage.from_('attachments').upload(file=file.read(), path=file_path_in_bucket, file_options={"content-type": file.content_type})

        # Encrypt the message content (if provided) before storing
        encrypted_content = None
        iv = None
        if content:
            encrypted_content, iv = encrypt_message(content, AES_KEY)

        # Insert message with file_path and file_name (and encrypted content if available)
        message_data = {
            "conversation_id": conversation_id,
            "sender_id": sender_id,
            "sender_email": sender_email,
            "file_path": file_path_in_bucket,
            "file_name": file.filename,
            "ciphertext": encrypted_content, # Store ciphertext
            "iv": iv # Store IV
        }
        user_client.table('messages').insert(message_data).execute()

        return jsonify({"success": True})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to upload attachment: {e}"}), 500

# --- Main Execution ---
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
