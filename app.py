import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify, abort
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import requests

app = Flask(__name__)

# ------------ ENV VARS (Render) ------------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")            # xoxb-...
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET")  # from Slack

SHOPIFY_SHOP = os.environ.get("SHOPIFY_SHOP")                  # e.g. "your-store.myshopify.com"
SHOPIFY_ACCESS_TOKEN = os.environ.get("SHOPIFY_ACCESS_TOKEN")  # Admin API access token

client = WebClient(token=SLACK_BOT_TOKEN)


# ------------ HELPER: VERIFY SLACK SIGNATURE ------------
def verify_slack_request(req):
    """Verify that the request really came from Slack."""
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    slack_signature = req.headers.get("X-Slack-Signature", "")

    if not timestamp or not slack_signature:
        abort(400, "Missing Slack headers")

    # Reject requests older than 5 minutes
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


# ------------ HELPER: PICK EMOJI ------------
def pick_emoji(payment_status: str, fulfillment_status: str) -> str:
    ps = (payment_status or "").lower()
    fs = (fulfillment_status or "").lower()

    # Payment based
    if ps == "paid":
        return "white_check_mark"       # ✅ everything done
    if ps == "payment_pending" or ps == "pending":
        return "hourglass_flowing_sand" # ⏳ waiting for payment
    if ps == "authorized":
        return "money_with_wings"       # 💸 auth only
    if ps == "refunded":
        return "arrows_counterclockwise" # 🔄 refunded
    if ps == "voided":
        return "x"                      # ❌ cancelled

    # Fulfillment based
    if fs == "fulfilled":
        return "package"                # 📦 fulfilled
    if fs == "unfulfilled":
        return "no_entry_sign"          # ⛔ not shipped
    if fs == "on_hold":
        return "hand"                   # ✋ on hold
    if fs in ("in_progress", "partial", "partially_fulfilled"):
        return "arrows_clockwise"       # 🔁 in progress

    # Default
    return "eyes"                       # 👀 default / unknown


# ------------ HELPER: SHOPIFY ORDER FETCH ------------
def get_order_from_shopify(order_id: int) -> dict:
    """Fetch order from Shopify Admin API."""
    url = f"https://{SHOPIFY_SHOP}/admin/api/2024-07/orders/{order_id}.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json",
    }
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    return data.get("order", {})


# ------------ BASIC HOME ROUTE ------------
@app.route("/")
def home():
    return "Slack + Shopify bot is running!", 200


# ------------ SLACK EVENTS (your existing one) ------------
@app.route("/slack/events", methods=["POST"])
def slack_events():
    verify_slack_request(request)

    data = request.get_json()

    # URL verification
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data.get("challenge")})

    if data.get("type") == "event_callback":
        event = data.get("event", {})

        if event.get("subtype") == "bot_message":
            return "", 200

        if event.get("type") == "message":
            user = event.get("user")
            text = (event.get("text") or "").lower()
            channel = event.get("channel")
            ts = event.get("ts")

            print(f"[SLACK EVENT] from {user} in {channel}: {text}")

            try:
                # simple chat behaviour: reply & react when user types "hello"
                if "hello" in text:
                    client.chat_postMessage(
                        channel=channel,
                        thread_ts=ts,
                        text=f"Hi <@{user}> 👋, I got your message: “{text}”"
                    )

                client.reactions_add(
                    channel=channel,
                    timestamp=ts,
                    name="white_check_mark"
                )

            except SlackApiError as e:
                print(f"Slack API error in /slack/events: {e.response['error']}")

        return "", 200

    return "", 200


# ------------ SHOPIFY FLOW WEBHOOK ------------
@app.route("/shopify/order-status", methods=["POST"])
def shopify_order_status():
    """
    Called from Shopify Flow.

    Expected JSON body:
    {
      "order_id": 1234567890,
      "order_name": "#1224",
      "channel": "C12345678"
    }
    """
    data = request.get_json() or {}
    order_id = data.get("order_id")
    order_name = (data.get("order_name") or "").strip()
    channel = data.get("channel")

    if not order_id or not order_name or not channel:
        return jsonify({"error": "order_id, order_name, channel are required"}), 400

    print(f"[FLOW] order_id={order_id}, order_name={order_name}, channel={channel}")

    # 1) Get latest order data from Shopify
    try:
        order = get_order_from_shopify(order_id)
    except Exception as e:
        print(f"Error calling Shopify: {e}")
        return jsonify({"error": "failed to fetch order from Shopify"}), 500

    payment_status = (order.get("financial_status") or "").lower()
    fulfillment_status = (order.get("fulfillment_status") or "unfulfilled").lower()

    emoji = pick_emoji(payment_status, fulfillment_status)
    print(f"payment={payment_status}, fulfillment={fulfillment_status}, emoji={emoji}")

    # 2) Find the Slack message that contains this order name (e.g. "#1224")
    try:
        history = client.conversations_history(channel=channel, limit=50)
        messages = history.get("messages", [])
    except SlackApiError as e:
        print(f"Slack history error: {e.response['error']}")
        return jsonify({"error": "failed to read Slack history"}), 500

    target_ts = None
    for msg in messages:
        text = msg.get("text", "")
        if order_name in text:
            target_ts = msg.get("ts")
            break

    if not target_ts:
        print("Could not find matching Slack message for order_name:", order_name)
        return jsonify({"error": "no matching Slack message found"}), 404

    # 3) Add reaction with selected emoji
    try:
        client.reactions_add(
            channel=channel,
            timestamp=target_ts,
            name=emoji
        )
    except SlackApiError as e:
        # If reaction already exists, Slack returns "already_reacted"
        print(f"Slack reaction error: {e.response['error']}")

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
