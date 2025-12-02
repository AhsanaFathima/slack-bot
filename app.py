import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify, abort
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

app = Flask(__name__)

# Environment variables set in Render
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")        # xoxb-...
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET")  # from Basic Info

client = WebClient(token=SLACK_BOT_TOKEN)


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


@app.route("/")
def home():
    return "Slack bot is running!", 200


@app.route("/slack/events", methods=["POST"])
def slack_events():
    # 1) verify Slack signature
    verify_slack_request(request)

    data = request.get_json()

    # 2) URL verification (only when you set the Request URL)
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data.get("challenge")})

    # 3) Actual events
    if data.get("type") == "event_callback":
        event = data.get("event", {}) or {}

        # Ignore messages from bots (including this bot)
        if event.get("subtype") == "bot_message" or event.get("bot_id"):
            return "", 200

        # Handle message events only
        if event.get("type") == "message":
            user = event.get("user")
            text = (event.get("text") or "")
            channel = event.get("channel")
            ts = event.get("ts")

            # Sometimes there is no user (e.g. message_changed events)
            if not user or not channel or not ts:
                return "", 200

            lower_text = text.lower().strip()
            print(f"Received from {user} in {channel}: {lower_text}")

            try:
                # ------- AUTO REPLY EXAMPLE -------
                # Reply to ANY message for now
                client.chat_postMessage(
                    channel=channel,
                    thread_ts=ts,  # reply in a thread
                    text=f"Hi <@{user}> 👋, I got your message: “{text}”"
                )

                # If you only want for hi/hello, you can do:
                # if "hello" in lower_text or "hi" in lower_text:

                # ------- AUTO REACTION EXAMPLE -------
                client.reactions_add(
                    channel=channel,
                    timestamp=ts,
                    name="white_check_mark"  # :white_check_mark:
                )

            except SlackApiError as e:
                print(f"Slack API error: {e.response['error']}")

        return "", 200

    return "", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
