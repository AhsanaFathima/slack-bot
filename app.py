import os
import hmac
import hashlib
import base64
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- ENV VARS ---
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID")
SHOPIFY_WEBHOOK_SECRET = os.environ.get("SHOPIFY_WEBHOOK_SECRET")


# ---------- Shopify webhook verify ----------
def verify_shopify_webhook(req):
    """
    Verify webhook using HMAC from Shopify
    """
    hmac_header = req.headers.get("X-Shopify-Hmac-Sha256", "")
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        req.data,
        hashlib.sha256
    ).digest()
    calculated_hmac = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(hmac_header, calculated_hmac)


# ---------- Slack helper: find message ----------
def find_slack_message_for_order(order_name):
    """
    Search the last N messages in the #orders channel
    to find the one that contains the order_name, e.g. '#1001'
    """
    url = "https://slack.com/api/conversations.history"
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "channel": SLACK_CHANNEL_ID,
        "limit": 200  # check last 200 messages
    }

    resp = requests.get(url, headers=headers, params=params)
    data = resp.json()
    if not data.get("ok"):
        print("Error conversations.history:", data)
        return None

    for msg in data.get("messages", []):
        text = msg.get("text", "")
        if order_name in text:
            # This is the matching message
            return msg.get("ts")

    return None


# ---------- Slack helper: add reaction ----------
def add_reaction(emoji, channel, ts):
    url = "https://slack.com/api/reactions.add"
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "name": emoji,        # e.g. 'white_check_mark'
        "channel": channel,
        "timestamp": ts
    }

    resp = requests.post(url, headers=headers, json=payload)
    print("Reaction add response:", resp.json())


# ---------- Test route ----------
@app.route("/", methods=["GET"])
def health():
    return "Shopify → Slack bot running", 200


# ---------- Webhook route ----------
@app.route("/shopify/payment", methods=["POST"])
def shopify_payment():
    # 1. Verify webhook
    if not verify_shopify_webhook(request):
        return "Unauthorized", 401

    order = request.get_json()
    if not order:
        return "No JSON", 400

    # 2. Extract order name and payment status
    order_name = order.get("name")  # e.g. '#1001'
    financial_status = order.get("financial_status")

    print("Received webhook for", order_name, "status:", financial_status)

    # 3. Decide emoji
    if financial_status == "paid":
        emoji = "white_check_mark"
    elif financial_status == "pending":
        emoji = "hourglass_flowing_sand"
    elif financial_status == "refunded":
        emoji = "money_with_wings"
    elif financial_status == "voided":
        emoji = "x"
    else:
        # default emoji for other statuses
        emoji = "eyes"

    # 4. Find Slack message with this order name
    if not order_name:
        print("No order name found in payload")
        return "ok", 200

    ts = find_slack_message_for_order(order_name)

    if not ts:
        print("Could not find Slack message for order", order_name)
        return "ok", 200

    # 5. Add emoji reaction to that message
    add_reaction(emoji, SLACK_CHANNEL_ID, ts)

    return "ok", 200


if __name__ == "__main__":
    # for local testing only
    app.run(host="0.0.0.0", port=5000)
