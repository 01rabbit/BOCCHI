import json
from flask import Flask, request
import requests

BOT_TOKEN = 'i3kjhoc6k3fzuqsdejquhr5bwr'
CHANNEL_ID = '5zeseysurpbudp114wgs7zsosa' #Town Square
MM_API_ADDRESS = 'http://127.0.0.1/api/v4/posts' 

app = Flask(__name__)

@app.route("/")
def hello():
    return "HelloWorld"

@app.route("/matter", methods=['POST'])
def bot_reply():
    posted_user = request.json['user_name']
    posted_msg = request.json['text']

    reply_headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_user} Bot reply message.",
        "props": {
            "attachments": [
                    {
                "author_name": posted_user,
                "text": posted_msg,
                }
            ]
        },
    }

    reply_request = requests.post(
        MM_API_ADDRESS,
        headers = reply_headers,
        data = json.dumps(reply_data)
    )

    return reply_request

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)