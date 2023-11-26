#!/usr/bin/python3

import logging
from datetime import datetime
import os
import random
import subprocess
import threading
from flask import Flask, request, jsonify
from janome.analyzer import Analyzer
from janome.tokenfilter import *
from socket import inet_aton, error
from bocchi.matterCommunicator import *
from bocchi.config import brutespray_conf as b_conf
import bocchi.faradayController as fc
import bocchi.gvmController as gc

app = Flask(__name__)

# ログの設定
log_file = f"log_{datetime.now().strftime('%Y%m%d')}.txt"
logging.basicConfig(filename=log_file, level=logging.INFO)

# ---------------------------------------------------------------------
# valid_ip
# ---------------------------------------------------------------------
def valid_ip(order):
    for word in order:
        try:
            # inet_atonが成功するとIPアドレスが正しいとみなす
            inet_aton(word)
            return word
        except error:
            # 失敗した場合は次の単語を試す
            pass

    # IPアドレスが見つからない場合はNoneを返す
    return None

# ---------------------------------------------------------------------
# get_timestamp
# ---------------------------------------------------------------------
def get_timestamp():
    return datetime.now().strftime('%Y%m%d_%H%M%S')

# ---------------------------------------------------------------------
# get_menu
# ---------------------------------------------------------------------
def get_menu():
    menuText = "## メニュー\n\
### 調査系\n\
- スキャン\n\
    - nmapを使用してターゲットを調査します。\n\
    - **通常**\n\
        - ［**IPアドレス**］をスキャンして\n\
    - **フルポート**\n\
        - ［**IPアドレス**］をフルポートスキャンして\n\
- 脆弱性診断\n\
    - GVM(Openvas)を使用して脆弱性診断します。\n\
    - ［**IPアドレス**］を脆弱性診断して\n\n\
### 攻撃系\n\
- 認証試行\n\
    - Brutesprayを使用して認証試行をします。\n\
    - ［**IPアドレス**］を認証試行して\n\n\
### 情報表示\n\
- faradayの表示\n\
    - faradayのダッシュボードを表示します。\n\
    - ［**情報** or **ファラデー** or **faraday**］を表示して\n\
- サービスリストの表示\n\
    - 検出したサービスをリストで表示します。\n\
    - ［**サービス**］を表示して\n\
- 脆弱性リストの表示\n\
    - 検出した脆弱性をリストで表示します。\n\
    - ［**脆弱性**］を表示して\n\
- 脆弱性診断結果の表示\n\
    - GVMのダッシュボードを表示します。\n\
    - ［**脆弱性診断の結果**］を表示して\n\n\
:warning: トリガーワード（**@bocchi**,**@ぼっち**）の後、半角スペースを入れてから要件をお伝えください。"
    return menuText

# ---------------------------------------------------------------------
# check_directory
# ---------------------------------------------------------------------
def check_directory(target_ip):
    """
    指定されたIPアドレスに対応するディレクトリが存在するか確認し、存在しない場合は作成するメソッド。

    Parameters:
        target_ip (str): チェックするディレクトリのIPアドレス

    Returns:
        str: ディレクトリのパス
    """
    dir_path = f"results/{target_ip}"

    if os.path.isdir(dir_path):
        return dir_path
    else:
        os.makedirs(dir_path)  # os.mkdirではなくos.makedirsを使用してサブディレクトリも作成する
        return dir_path
# ---------------------------------------------------------------------
# answer
# ---------------------------------------------------------------------
def answer():
    rand = random.randint(1,30)
    if rand % 3 == 0 and rand % 5 == 0:
        messages = "「メニューを表示して」と言ってもらえればメニューを表示します。"
    elif rand % 3 == 0:
        messages = "何かお困りですか？"
    elif rand % 5 == 0:
        messages = "はい、なんでしょうか？"
    else:
        messages = "呼びました？"
    return messages

# ---------------------------------------------------------------------
# perform_full_port_scan
# ---------------------------------------------------------------------
def perform_full_port_scan(ipaddr, posted_user):
    """
    フルポートスキャンを実行し、結果をMattermostおよびFaradayに通知するメソッド。

    Parameters:
        ipaddr (str): スキャン対象のIPアドレス
        posted_user (str): Mattermostへの通知時に使用するユーザー情報

    Returns:
        str: スキャン結果およびFaradayのインポート結果のメッセージ
    """
    # フルポートスキャンの開始連絡
    messages = f"nmapで{ipaddr}のフルポートスキャンを開始します。\nしばらくお待ちください:coffee:"
    send_message_to_user(posted_user=posted_user, msg=messages)

    # nmapコマンドの作成
    resultsPath = check_directory(ipaddr)
    nmap_command = ["nmap", "-vv", "--reason", "-Pn", "-T4", "-sV", "-sC", "--version-all", "-A", "-p-", "--osscan-guess", "--script=vuln", "-oA", f"{resultsPath}/FullScan_{get_timestamp()}", ipaddr]

    # ログにnmapコマンドを記録
    logging.info(f"フルポートスキャンの実行: {' '.join(nmap_command)}")

    # nmapをsubprocessで呼び出してフルポートスキャンを実行
    try:
        nmap_output = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, text=True)
        logging.info(f"フルポートスキャン終了\nnmapの出力:\n{nmap_output}")
        messages = f"{ipaddr}のフルポートスキャンが終了しました."

        # Faradayへの結果のインポート
        addText = fc.import_results_to_faraday(resultsPath)

        # インポート成功時に結果を追加
        messages += f"\n{addText}"

    except subprocess.CalledProcessError as e:
        logging.error(f"nmapコマンドの実行中にエラーが発生しました: {' '.join(nmap_command)}\nエラー出力: {e.output}")
        messages = f"{ipaddr}のフルポートスキャン中にエラーが発生しました."

    send_message_to_user(posted_user, messages)
# ---------------------------------------------------------------------
# perform_standard_scan
# ---------------------------------------------------------------------
def perform_standard_scan(ipaddr, posted_user):
    """
    標準スキャンを実行し、結果をMattermostおよびFaradayに通知するメソッド。

    Parameters:
        ipaddr (str): スキャン対象のIPアドレス
        posted_user (str): Mattermostへの通知時に使用するユーザー情報

    Returns:
        str: スキャン結果およびFaradayのインポート結果のメッセージ
    """

    # 標準スキャンの開始連絡
    messages = f"nmapで{ipaddr}のスキャンを開始します。\nしばらくお待ちください:coffee:"
    send_message_to_user(posted_user, messages)

    # nmapコマンドの作成
    resultsPath = check_directory(ipaddr)
    nmap_command = ["nmap", "-vv", "--reason", "-Pn", "-T4", "-sV", "-sC", "--version-all", "-A", "--osscan-guess", "--script=vuln", "-oA", f"{resultsPath}/Scan_{get_timestamp()}", ipaddr]

    # ログにnmapコマンドを記録
    logging.info(f"スキャンの実行: {' '.join(nmap_command)}")

    # nmapをsubprocessで呼び出してスキャンを実行
    try:
        nmap_output = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, text=True)
        logging.info(f"スキャン終了\nnmapの出力:\n{nmap_output}")
        messages = f"{ipaddr}のスキャンが終了しました."

        # Faradayへの結果のインポート
        addText = fc.import_results_to_faraday(resultsPath)

        # インポート成功時に結果を追加
        messages += f"\n{addText}"

    except subprocess.CalledProcessError as e:
        logging.error(f"nmapコマンドの実行中にエラーが発生しました: {' '.join(nmap_command)}\nエラー出力: {e.output}")
        messages = f"{ipaddr}のスキャン中にエラーが発生しました."

    # 終了連絡の追加
    send_message_to_user(posted_user, messages)

# ---------------------------------------------------------------------
# perform_vulnerability_scan_with_gvm
# ---------------------------------------------------------------------
def perform_vulnerability_scan_with_gvm(ipaddr, posted_user):
    """
    GVM(Openvas)を使用して脆弱性診断を実行し、結果をMattermostに通知するメソッド。

    Parameters:
        ipaddr (str): スキャン対象のIPアドレス
        posted_user (str): Mattermostへの通知時に使用するユーザー情報

    Returns:
        str: 脆弱性スキャン結果のメッセージ
    """
    try:
        # 脆弱性スキャンの開始連絡
        messages = f"GVM(Openvas)で{ipaddr}の脆弱性診断を開始します。\nしばらくお待ちください:coffee:"
        send_message_to_user(posted_user, messages)

        # ログに脆弱性スキャン開始のメッセージを残す
        logging.info(f"{ipaddr}の脆弱性スキャンを開始します。")

        # ターゲットの作成
        targetID = gc.get_target_id(ipaddr)

        # タスクの作成
        taskID = gc.get_task_id(targetID)

        # タスクの開始
        gc.start_task(taskID)

        # タスクの終了待機
        gc.check_status(taskID)

        # GVM結果の取得
        messages = gc.check_gvm(ipaddr)

        send_message_to_user(posted_user, messages)

    except Exception as e:
            logging.error(f"脆弱性スキャン中にエラーが発生しました: {str(e)}")
            messages = f"{ipaddr}の脆弱性スキャン中にエラーが発生しました。"

            # エラーメッセージを通知
            send_message_to_user(posted_user, messages)

# ---------------------------------------------------------------------
# perform_brutespray_attack
# ---------------------------------------------------------------------
def perform_brutespray_attack(ipaddr, posted_user):
    """
    Brutesprayを使用して認証攻撃を実行し、結果をMattermostに通知するメソッド。

    Parameters:
        ipaddr (str): 攻撃対象のIPアドレス
        posted_user (str): Mattermostへの通知時に使用するユーザー情報

    Returns:
        str: 認証攻撃の結果メッセージ
    """
    try:
        # Brutespray攻撃のパラメータ取得
        params = b_conf()
        USER = params['user_list']
        PASS = params['password_list']

        # 攻撃結果保存ディレクトリの作成
        resultsPath = check_directory(ipaddr)

        # 認証攻撃の開始連絡
        messages = "認証試行を開始します。\nしばらくお待ちください:coffee:"
        send_message_to_user(posted_user, messages)
        logging.info(f"Brutespray攻撃を開始します。対象IP: {ipaddr}")

        # Nmapを使用してサービスバージョンを取得
        subprocess.run(["nmap", "-vv", "-Pn", "-T4", "-sV", "-oG", f"{resultsPath}/result", ipaddr])

        # Brutesprayで認証攻撃を実行
        subprocess.run(["brutespray", "--file", f"{resultsPath}/result", "-U", f"{USER}", "-P", f"{PASS}", "-o", f"{resultsPath}", "--threads", "5"])

        # 結果ファイルから結果を取得
        dir_list = os.listdir(resultsPath)
        results = ""
        for i in range(len(dir_list)):
            if ".txt" == os.path.splitext(dir_list[i])[1]:
                filePath = os.path.join(resultsPath, dir_list[i])
                with open(filePath) as f:
                    results += f.read()

        # 認証攻撃終了連絡
        messages = "認証試行終了。\n" + results
        logging.info(f"Brutespray攻撃が終了しました。")

        send_message_to_user(posted_user, messages)

    except Exception as e:
        logging.error(f"認証攻撃中にエラーが発生しました: {str(e)}")
        messages = f"{ipaddr}の認証攻撃中にエラーが発生しました。"

        # エラーメッセージを通知
        send_message_to_user(posted_user, messages)

@app.route("/matter", methods=['POST'])
def bot_reply():
    posted_user = request.json['user_name']
    posted_msg = request.json['text']
    try:
        # トリガーワードと命令文の分解
        firstSegment = posted_msg.split(" ")
        # firstSegment[0] : WakeUp Code
        # firstSegment[1] : Target & Command
        userOrder=[]
        # janomeで形態素解析した結果を複合名詞化してリスト化
        a = Analyzer(token_filters=[CompoundNounFilter()])
        for token in a.analyze(firstSegment[1]):
            userOrder.append(token.base_form)
        # IPアドレスが含まれていたら変数に格納
        ipaddr = valid_ip(userOrder)
        # IPアドレスが格納されているか？
        if ipaddr is not None:
            f = open('target_IPs.txt','r')
            targetIPList = f.readline()
            f.close()
            if ipaddr in targetIPList:
                # nmapを使用した各種スキャン
                if "フルポートスキャン" in userOrder:
                    # フルポートスキャン
                    askForFullScanConfirmation(posted_user, ipaddr)
                elif "スキャン" in userOrder:
                    # 標準スキャン
                    askForStdScanConfirmation(posted_user, ipaddr)
                    return
                elif "脆弱性診断" in userOrder:
                    # GVMを使用した脆弱性診断
                    askForVulnScanConfirmation(posted_user, ipaddr)
                elif "認証試行" in userOrder:
                    # Brutesprayで認証攻撃
                    askForBruteAttackConfirmation(posted_user, ipaddr)
            else:
                send_message_to_user(posted_user,":no_entry: 指定されたIPアドレスは診断対象外です。\n対象に加えるならば***target_IPs.txt***に追記してください。")
                return
        elif "表示" in userOrder or "見る" in userOrder or "見せる" in userOrder:
            if "メニュー" in userOrder:
                # メニューを表示
                send_message_to_user(posted_user,get_menu())
            elif "サービス" in userOrder:
                # サービスをリストで表示
                send_message_to_user(posted_user,fc.show_service_list_in_faraday())
            elif "脆弱性診断" in userOrder or "gvm" in userOrder or "GVM" in userOrder:
                # GVMのダッシュボードを表示
                send_message_to_user(posted_user,gc.show_gvm())
            elif "脆弱性" in userOrder:
                # 脆弱性情報をリストで表示
                send_message_to_user(posted_user,fc.show_vulnerability_list_in_faraday())
            elif "情報" in userOrder or "ファラデー" in userOrder or "faraday" in userOrder or "Faraday" in userOrder:
                # Faradayのダッシュボードを表示
                send_message_to_user(posted_user,fc.show_faraday())
        else:
            send_message_to_user(posted_user,get_menu())

    except IndexError:
        send_message_to_user(posted_user,answer())

    return

@app.route('/actions/std_scan', methods=['POST'])
def std_scan():
    data = request.get_json()
    text = data.get("context", {}).get("text", "")
    if not text:
        return jsonify({"ephemeral_text": "Invalid request. Context['text'] is not found."})
    posted_usr,ipaddr = text.split(",")
    thread = threading.Thread(target=perform_standard_scan, args=(ipaddr, posted_usr))
    thread.start()

    response = {
        "update": {
            "props": {}
        },
        "ephemeral_text": f"{posted_usr}によりスキャンが承認されました。"
    }
    return jsonify(response)

@app.route('/actions/full_scan', methods=['POST'])
def full_scan():
    data = request.get_json()
    text = data.get("context", {}).get("text", "")
    if not text:
        return jsonify({"ephemeral_text": "Invalid request. Context['text'] is not found."})
    posted_usr,ipaddr = text.split(",")
    thread = threading.Thread(target=perform_full_port_scan, args=(ipaddr, posted_usr))
    thread.start()

    response = {
        "update": {
            "props": {}
        },
        "ephemeral_text": f"{posted_usr}によりフルポートスキャンが承認されました。"
    }
    return jsonify(response)

@app.route('/actions/vuln_scan', methods=['POST'])
def vuln_scan():
    data = request.get_json()
    text = data.get("context", {}).get("text", "")
    if not text:
        return jsonify({"ephemeral_text": "Invalid request. Context['text'] is not found."})
    posted_usr,ipaddr = text.split(",")
    thread = threading.Thread(target=perform_vulnerability_scan_with_gvm, args=(ipaddr, posted_usr))
    thread.start()

    response = {
        "update": {
            "props": {}
        },
        "ephemeral_text": f"{posted_usr}により脆弱性診断が承認されました。"
    }
    return jsonify(response)

@app.route('/actions/brute_attack', methods=['POST'])
def brute_attack():
    data = request.get_json()
    text = data.get("context", {}).get("text", "")
    if not text:
        return jsonify({"ephemeral_text": "Invalid request. Context['text'] is not found."})
    posted_usr,ipaddr = text.split(",")
    thread = threading.Thread(target=perform_brutespray_attack, args=(ipaddr, posted_usr))
    thread.start()

    response = {
        "update": {
            "props": {}
        },
        "ephemeral_text": f"{posted_usr}により認証試行が承認されました。"
    }
    return jsonify(response)

@app.route('/actions/reject', methods=['POST'])
def reject():
    response = {
        "update": {
            "props": {}
        },
        "ephemeral_text": "拒否されました。"
    }
    return jsonify(response)

def main():
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()