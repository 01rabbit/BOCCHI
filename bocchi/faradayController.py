#!/usr/bin/python3

import os
import subprocess
from bocchi.config import faraday_conf as f_conf

params = f_conf()
FARADAY_USER = params['user']
FARADAY_PASS = params['password']
FARADAY_SERVER = params['server']
FARADAY_WORKSPACE = params['workspace']

# ---------------------------------------------------------------------
# show_faraday
# ---------------------------------------------------------------------
def show_faraday():
    messages = f"情報はFaradayで確認します。以下のリンクをクリック\n{FARADAY_SERVER}"
    return messages

# ---------------------------------------------------------------------
# connect_to_faraday
# ---------------------------------------------------------------------
def connect_to_faraday():
    """
    Faradayに接続し、認証を行い、指定したワークスペースを作成および選択するメソッド。

    Returns:
        str: 接続結果のメッセージ
    """
    messages = ""

    # Faradayに接続して認証を試みる
    result = subprocess.run(["faraday-cli", "auth", "-f", FARADAY_SERVER, "-u", FARADAY_USER, "-p", FARADAY_PASS], capture_output=True, text=True)

    if "Authenticated" in result.stdout:
        print(result.stdout)  # デバッグ用（必要に応じて削除）

        # ワークスペースを作成する
        subprocess.run(["faraday-cli", "workspace", "create", FARADAY_WORKSPACE], capture_output=True, text=True)

        # ワークスペースを選択する
        result = subprocess.run(["faraday-cli", "workspace", "select", FARADAY_WORKSPACE], capture_output=True, text=True)

        if "Selected" in result.stdout:
            print(result.stdout)  # デバッグ用（必要に応じて削除）
            # 問題がない場合は空メッセージを返す
            return messages
        else:
            # ワークスペースの選択に問題がある場合
            messages = "ワークスペースの選択時に問題がありました。"
            return messages
    else:
        # 認証に問題がある場合
        messages = "認証に問題がありました。"
        return messages

# ---------------------------------------------------------------------
# import_results_to_faraday
# ---------------------------------------------------------------------
def import_results_to_faraday(dir_path):
    """
    指定されたディレクトリ内のXML結果をFaradayにインポートするメソッド。

    Parameters:
        dir_path (str): XML結果が保存されているディレクトリのパス

    Returns:
        str: インポート結果のメッセージ
    """
    messages = connect_to_faraday()

    if messages == "":
        dir_list = os.listdir(dir_path)

        for i in range(len(dir_list)):
            if ".xml" == os.path.splitext(dir_list[i])[1]:
                xml_path = os.path.join(dir_path, dir_list[i])
                print(xml_path)
                subprocess.run(["faraday-cli", "tool", "report", xml_path])

        messages = "結果をFaradayにインポートしました。"
    else:
        messages += "\n結果のインポートに失敗しました。"

    return messages

# ---------------------------------------------------------------------
# show_service_list_in_faraday
# ---------------------------------------------------------------------
def show_service_list_in_faraday():
    """
    Faradayに登録されたサービスのリストを表示するメソッド。

    Returns:
        str: サービスのリストまたはエラーメッセージ
    """
    messages = connect_to_faraday()

    if messages == "":
        result = subprocess.run(["faraday-cli", "service", "list"], capture_output=True, text=True)
        return result.stdout
    else:
        return messages

# ---------------------------------------------------------------------
# show_vulnerability_list_in_faraday
# ---------------------------------------------------------------------
def show_vulnerability_list_in_faraday():
    """
    Faradayに登録された脆弱性のリストを表示するメソッド。

    Returns:
        str: 脆弱性のリストまたはエラーメッセージ
    """
    messages = connect_to_faraday()

    if messages == "":
        result = subprocess.run(["faraday-cli", "vuln", "list"], capture_output=True, text=True)
        return result.stdout
    else:
        return messages
