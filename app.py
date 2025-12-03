import os
import hmac
import hashlib
import time
import requests
from flask import Flask, request, jsonify, abort
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

app = Flask(__name__)

# ---------- ENV VARS (Render) ----------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET")

# e.g. "fragrantsouq.myshopify.com"
SHOPIFY_SHOP = os.environ.get("SHOPIFY_SHOP")
SHOPIFY_ACCESS_TOKEN = os.environ.get("SHOPIFY_ACCESS_TOKEN")

# 🔴 Your Shopify-Slack channel
TARGET_CHANNEL_ID = "C0A068PHZMY"

# default Slack channel for Flow → Slack (if Flow doesn't send channel)
DEFAULT_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", TARGET_CHANNEL_ID)

client = WebClient(token=SLACK_BOT_TOKEN)


# ---------- HELPER: VERIFY SLACK SIGNATURE ----------
def verify_slack_request(req):
    """Verify that the request really came from Slack."""
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    slack_signature = req.headers.get("X-Slack-Signature", "")

    if not timestamp or not slack_signature:
        abort(400, "Missing Slack headers")

    # Protect against replay attacks (older than 5 minutes)
    if abs(time.time() - int(timestamp)) > 60 * 5:
        abort(400, "Invalid timestamp")

    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode("utf-8"),
        sig_basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(my_signature, slack_signature):
        abort(400, "Invalid signature")


# ---------- HELPER: MAP STATUS -> EMOJI ----------
def pick_emoji(payment_status, fulfillment_status):
    ps = (payment_status or "").lower()
    fs = (fulfillment_status or "").lower()

    # payment-based
    if ps == "paid":
        return "white_check_mark"          # ✅ everything done
    if ps in ("payment_pending", "pending"):
        return "hourglass_flowing_sand"    # ⏳ waiting for payment
    if ps == "authorized":
        return "money_with_wings"          # 💸 auth only
    if ps == "refunded":
        return "arrows_counterclockwise"   # 🔄 refunded
    if ps == "voided":
        return "x"                         # ❌ cancelled

    # fulfillment-based
    if fs == "fulfilled":
        return "package"                   # 📦 fulfilled
    if fs == "unfulfilled":
        return "no_entry_sign"             # ⛔ not shipped
    if fs == "on_hold":
        return "hand"                      # ✋ on hold
    if fs in ("in_progress", "partial", "partially_fulfilled"):
        return "arrows_clockwise"          # 🔁 in progress

    # default
    return "eyes"                          # 👀 default / unknown


# ---------- HELPER: FIND ORDER MESSAGE IN SLACK ----------
def find_message_ts_for_order(channel_id, order_name):
    """
    Look through recent messages in the channel and
    return ts of the message that contains the order_name (e.g. "#1224").
    """
    try:
        resp = client.conversations_history(channel=channel_id, limit=50)
        for msg in resp.get("messages", []):
            text = msg.get("text", "")
            if order_name in text:
                return msg.get("ts")
    except SlackApiError as e:
        print(f"[FLOW] Error fetching history: {e.response['error']}")
    return None


# ---------- ROUTES ----------

@app.route("/")
def home():
    return "Slack + Shopify bot is running!", 200


# ---- SLACK EVENTS ----
@app.route("/slack/events", methods=["POST"])
def slack_events():
    """
    For every *user* message in TARGET_CHANNEL_ID:
      - add a ✅ reaction
      - send one threaded reply
    Ignores all other channels and bot messages.
    """
    verify_slack_request(request)
    data = request.get_json()

    # 1) URL verification (when you set the Request URL in Slack)
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data.get("challenge")})

    # 2) Event callbacks
    if data.get("type") == "event_callback":
        event = data.get("event", {})

        # Only handle message events
        if event.get("type") != "message":
            return "", 200

        # ignore edits, deletes, bot messages, etc.
        if event.get("subtype") is not None:
            return "", 200
        if event.get("bot_id"):
            return "", 200

        channel = event.get("channel")
        user = event.get("user")
        text = (event.get("text") or "").strip()
        ts = event.get("ts")
        thread_ts = event.get("thread_ts")

        # ❗ only our Shopify-Slack channel
        if channel != TARGET_CHANNEL_ID:
            return "", 200

        print(f"[SLACK] user={user} channel={channel} text={text}")

        # only create a **threaded reply** for top-level messages
        is_root_message = (thread_ts is None) or (thread_ts == ts)

        try:
            if is_root_message:
                client.chat_postMessage(
                    channel=channel,
                    thread_ts=ts,
                    text=f"Hi <@{user}> 👋, noted this message."
                )

            # Add a ✅ reaction on the original message
            client.reactions_add(
                channel=channel,
                timestamp=ts,
                name="white_check_mark",
            )

        except SlackApiError as e:
            print(f"[SLACK] API error: {e.response.get('error')}")

        return "", 200

    return "", 200


# ---- SHOPIFY FLOW ENDPOINT ----
@app.route("/shopify/order-status", methods=["POST"])
def shopify_order_status():
    """
    Called from Shopify Flow when:
      - order created
      - order transaction created (payment)
      - order fulfilled, etc.

    Expected JSON body from Flow, for example:

    {
      "order_id": "gid://shopify/Order/1234567890",
      "order_name": "#1224",
      "event_type": "payment",        // optional, for your info
      "channel": "C0A068PHZMY"        // Slack channel id (optional)
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    raw_id = data.get("order_id")  # gid://shopify/Order/1234567
    order_id = int(raw_id.split("/")[-1]) if raw_id else None

    order_name = data.get("order_name")   # "#1249"
    event_type = data.get("event_type")
    channel_id = data.get("channel") or DEFAULT_CHANNEL_ID

    print(f"[FLOW] event_type={event_type}, order_id={order_id}, "
          f"order_name={order_name}, channel={channel_id}")

    if not (order_id and order_name and channel_id):
        return jsonify({"ok": False,
                        "error": "order_id, order_name, channel required"}), 400

    # 1) Fetch order from Shopify
    try:
        url = f"https://{SHOPIFY_SHOP}/admin/api/2024-01/orders/{order_id}.json"
        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json",
        }
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        order = resp.json().get("order", {})
    except Exception as e:
        print(f"[FLOW] Error fetching order from Shopify: {e}")
        return jsonify({"ok": False, "error": "shopify_fetch_failed"}), 500

    payment_status = order.get("financial_status") or ""
    fulfillment_status = order.get("fulfillment_status") or ""

    emoji = pick_emoji(payment_status, fulfillment_status)
    print(f"[FLOW] payment={payment_status}, "
          f"fulfillment={fulfillment_status}, emoji={emoji}")

    # 2) Find the original Slack message that contains this order name (e.g. "#1224")
    ts = find_message_ts_for_order(channel_id, order_name)
    if not ts:
        print("[FLOW] No matching Slack message found for", order_name)
        # Not an error for Flow – just nothing to react to
        return jsonify({"ok": False, "error": "message_not_found"}), 200

    # 3) Add reaction
    try:
        client.reactions_add(
            channel=channel_id,
            timestamp=ts,
            name=emoji,
        )
    except SlackApiError as e:
        # Ignore "already_reacted" etc., just log
        print(f"[FLOW] Error adding reaction: {e.response.get('error')}")

    return jsonify({
        "ok": True,
        "order_id": order_id,
        "order_name": order_name,
        "payment_status": payment_status,
        "fulfillment_status": fulfillment_status,
        "emoji": emoji,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
