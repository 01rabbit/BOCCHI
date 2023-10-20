import json
from config import matter_conf as mm_conf
import requests

params = mm_conf()
BOT_TOKEN = params['bot_token']
CHANNEL_ID = params['channel_id'] #Town Square
MM_API_ADDRESS = params['mm_api_address']

def messenger(posted_user, msg):
    reply_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_user} BOCCHI reply message. :wave:",
        "props": {
            "attachments": [
                    {
                        "text": msg,
                    
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
