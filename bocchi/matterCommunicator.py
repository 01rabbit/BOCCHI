#!/usr/bin/python3

import json
import requests
from bocchi.config import matter_conf as mm_conf

params = mm_conf()
BOT_TOKEN = params['bot_token']
CHANNEL_ID = params['channel_id'] #Town Square
MM_API_ADDRESS = params['mm_api_address']
BOCCHI_SERVER = params['bocchi_server']

# ---------------------------------------------------------------------
# send_message_to_user
# ---------------------------------------------------------------------
def send_message_to_user(posted_user, message):
    """
    指定されたユーザーにメッセージを送信するメソッド。

    Parameters:
        posted_user (str): メッセージを受信するユーザーのID
        message (str): 送信するメッセージの内容

    Returns:
        requests.Response: Mattermostへのリクエストのレスポンス
    """
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
                        "text": message,
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

# ---------------------------------------------------------------------
# askForStdScanConfirmation
# ---------------------------------------------------------------------
def askForStdScanConfirmation(posted_usr,ipaddr):
    """
    Mattermostに対して標準スキャンの承認メッセージを送信し、ボタンのアクションに応じた処理を行うメソッド。

    Parameters:
        posted_usr (str): メッセージを投稿したユーザーのID
        ipaddr (str): スキャン対象のIPアドレス

    Returns:
        requests.Response: Mattermostへのリクエストのレスポンス
    """
    reply_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "response_type": "in_channel",
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_usr} BOCCHI reply message. :wave:",
        "props": {

            "attachments": [{
                "title": "スキャンの実施",
                "text": "この行為は法律に抵触する可能性があります。管理者から許可を得た端末や自身の端末に対して使用してください。\nスキャンを承認しますか？",
                "actions": [{
                    # Acceptボタン
                    "name": "Accept",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/std_scan?token={BOT_TOKEN}",
                        "context": {
                            "text": posted_usr +","+ ipaddr
                        }
                    }
                }, {
                    # Rejectボタン
                    "name": "Reject",
                    "style": "danger",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/reject?token={BOT_TOKEN}"
                    }
                }]
            }]
        }
    }
    reply_request = requests.post(
        MM_API_ADDRESS,
        headers = reply_headers,
        data = json.dumps(reply_data)
    )
    return reply_request

# ---------------------------------------------------------------------
# askForFullScanConfirmation
# ---------------------------------------------------------------------
def askForFullScanConfirmation(posted_usr,ipaddr):
    """
    Mattermostに対してフルポートスキャンの承認メッセージを送信し、ボタンのアクションに応じた処理を行うメソッド。

    Parameters:
        posted_usr (str): メッセージを投稿したユーザーのID
        ipaddr (str): スキャン対象のIPアドレス

    Returns:
        requests.Response: Mattermostへのリクエストのレスポンス
    """
    reply_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "response_type": "in_channel",
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_usr} BOCCHI reply message. :wave:",
        "props": {

            "attachments": [{
                "title": "フルポートスキャンの実施",
                "text": "この行為は法律に抵触する可能性があります。管理者から許可を得た端末や自身の端末に対して使用してください。\nフルポートスキャンを承認しますか？",
                "actions": [{
                    # Acceptボタン
                    "name": "Accept",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/full_scan?token={BOT_TOKEN}",
                        "context": {
                            "text": posted_usr +","+ ipaddr
                        }
                    }
                }, {
                    # Rejectボタン
                    "name": "Reject",
                    "style": "danger",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/reject?token={BOT_TOKEN}"
                    }
                }]
            }]
        }
    }
    reply_request = requests.post(
        MM_API_ADDRESS,
        headers = reply_headers,
        data = json.dumps(reply_data)
    )
    return reply_request

# ---------------------------------------------------------------------
# askForVulnScanConfirmation
# ---------------------------------------------------------------------
def askForVulnScanConfirmation(posted_usr,ipaddr):
    """
    Mattermostに対して脆弱性診断の承認メッセージを送信し、ボタンのアクションに応じた処理を行うメソッド。

    Parameters:
        posted_usr (str): メッセージを投稿したユーザーのID
        ipaddr (str): スキャン対象のIPアドレス

    Returns:
        requests.Response: Mattermostへのリクエストのレスポンス
    """
    reply_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "response_type": "in_channel",
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_usr} BOCCHI reply message. :wave:",
        "props": {

            "attachments": [{
                "title": "脆弱性診断の実施",
                "text": "この行為は法律に抵触する可能性があります。管理者から許可を得た端末や自身の端末に対して使用してください。\n脆弱性診断を承認しますか？",
                "actions": [{
                    # Acceptボタン
                    "name": "Accept",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/vuln_scan?token={BOT_TOKEN}",
                        "context": {
                            "text": posted_usr +","+ ipaddr
                        }
                    }
                }, {
                    # Rejectボタン
                    "name": "Reject",
                    "style": "danger",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/reject?token={BOT_TOKEN}"
                    }
                }]
            }]
        }
    }
    reply_request = requests.post(
        MM_API_ADDRESS,
        headers = reply_headers,
        data = json.dumps(reply_data)
    )
    return reply_request

# ---------------------------------------------------------------------
# askForBruteAttackConfirmation
# ---------------------------------------------------------------------
def askForBruteAttackConfirmation(posted_usr,ipaddr):
    """
    Mattermostに対してブルートフォース攻撃の承認メッセージを送信し、ボタンのアクションに応じた処理を行うメソッド。

    Parameters:
        posted_usr (str): メッセージを投稿したユーザーのID
        ipaddr (str): 攻撃対象のIPアドレス

    Returns:
        requests.Response: Mattermostへのリクエストのレスポンス
    """
    reply_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "response_type": "in_channel",
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_usr} BOCCHI reply message. :wave:",
        "props": {

            "attachments": [{
                "title": "認証試行の実施",
                "text": "この行為は法律に抵触する可能性があります。管理者から許可を得た端末や自身の端末に対して使用してください。\n認証試行を承認しますか？",
                "actions": [{
                    # Acceptボタン
                    "name": "Accept",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/brute_attack?token={BOT_TOKEN}",
                        "context": {
                            "text": posted_usr +","+ ipaddr
                        }
                    }
                }, {
                    # Rejectボタン
                    "name": "Reject",
                    "style": "danger",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/reject?token={BOT_TOKEN}"
                    }
                }]
            }]
        }
    }
    reply_request = requests.post(
        MM_API_ADDRESS,
        headers = reply_headers,
        data = json.dumps(reply_data)
    )
    return reply_request

# ---------------------------------------------------------------------
# askForAllAttacks
# ---------------------------------------------------------------------
def askForAllAttacks(posted_usr,ipaddr):
    """
    Mattermostに対してフルポートスキャン、脆弱性診断、ブルートフォース攻撃の承認メッセージを送信し、ボタンのアクションに応じた処理を行うメソッド。

    Parameters:
        posted_usr (str): メッセージを投稿したユーザーのID
        ipaddr (str): 攻撃対象のIPアドレス

    Returns:
        requests.Response: Mattermostへのリクエストのレスポンス
    """
    reply_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + BOT_TOKEN,
    }

    reply_data = {
        "response_type": "in_channel",
        "channel_id": CHANNEL_ID,
        "message": f"@{posted_usr} BOCCHI reply message. :wave:",
        "props": {

            "attachments": [{
                "title": "フルポートスキャン、脆弱性診断及び、認証試行の実施",
                "text": "この行為は法律に抵触する可能性があります。管理者から許可を得た端末や自身の端末に対して使用してください。\n認証試行を承認しますか？",
                "actions": [{
                    # Acceptボタン
                    "name": "Accept",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/all_attacks?token={BOT_TOKEN}",
                        "context": {
                            "text": posted_usr +","+ ipaddr
                        }
                    }
                }, {
                    # Rejectボタン
                    "name": "Reject",
                    "style": "danger",
                    "integration": {
                        "url": f"{BOCCHI_SERVER}/actions/reject?token={BOT_TOKEN}"
                    }
                }]
            }]
        }
    }
    reply_request = requests.post(
        MM_API_ADDRESS,
        headers = reply_headers,
        data = json.dumps(reply_data)
    )
    return reply_request
