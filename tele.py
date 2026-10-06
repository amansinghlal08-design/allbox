# file: telegram_miniapp_backend.py
import base64
import hashlib
import hmac
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# Replace with your bot token
BOT_TOKEN = "7958152477:AAE4rPnLckY8iuyjNkDaqaTyUg63gBxUTvw"

def verify_init_data_string(init_data_str: str) -> bool:
    """
    Verify Telegram WebApp initData string (key1=val1&key2=val2...).
    Uses Telegram recommended method: secret_key = sha256(bot_token).
    """
    # Parse into dict (preserves percent-encoding)
    items = {}
    for pair in init_data_str.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            items[k] = v

    received_hash = items.pop("hash", None)
    if not received_hash:
        return False

    # Build data_check_string: sorted by key, "k=v" joined by '\n'
    data_check_list = [f"{k}={items[k]}" for k in sorted(items.keys())]
    data_check_string = "\n".join(data_check_list)

    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    computed_hmac = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return hmac.compare_digest(computed_hmac, received_hash)

@app.route("/", methods=["GET"])
def index():
    return (
        "<html><body>"
        "<h3>Mini App backend running</h3>"
        "<p>This endpoint only used for testing. Real launches come from Telegram WebView.</p>"
        "</body></html>"
    )

@app.route("/api/auth", methods=["GET", "POST"])
def api_auth():
    # 1) Prefer header-based flow (HAR): X-Init-Data-B64
    init_b64 = request.headers.get("X-Init-Data-B64")
    if init_b64:
        try:
            decoded = base64.b64decode(init_b64).decode("utf-8")
        except Exception:
            return jsonify({"ok": False, "error": "invalid initData base64"}), 400

        # decoded is expected to be a query string like "user=...&auth_date=...&hash=..."
        if verify_init_data_string(decoded):
            return jsonify({"ok": True, "message": "authorized via header"}), 200
        else:
            return jsonify({"ok": False, "error": "invalid initData signature (header)"}), 401

    # 2) Fallback: query param flow (older)
    init_query = request.args.get("tgWebAppData") or request.query_string.decode()
    # If query string contains hash param, try verify
    if init_query and "hash=" in init_query:
        # If tgWebAppData is URL-encoded JSON, you may need to reconstruct the full query string
        # Here we attempt to use the raw query string if present
        raw_qs = request.query_string.decode()
        if verify_init_data_string(raw_qs):
            return jsonify({"ok": True, "message": "authorized via query params"}), 200
        else:
            return jsonify({"ok": False, "error": "invalid initData signature (query)"}), 401

    # 3) No valid initData found
    return jsonify({"ok": False, "error": "Telegram se open karo — direct browser mein nahi chalega 📱"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
