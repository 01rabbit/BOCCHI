#!/usr/bin/python3

import os
from flask import Flask, request
import subprocess
from matterCommunicator import messenger
import faradayController as fc
from config import autorecon_conf as ar_conf
import datetime

app = Flask(__name__)

commands = ['表示', 'スキャン', 'フルポートスキャン']
params = ar_conf()
CMD_PATH = params['path']

def get_timestamp():
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

def get_menu():
    menuText = "## メニュー\n\
### 調査系\n\
- スキャン\n\
    - nmapを使用してターゲットを調査します。\n\
    - **使用方法**：［**IPアドレス**］をスキャンして\n\
- フルポートスキャン\n\
    - nmapを使用してターゲットのポート全てを調査します。\n\
    - **使用方法**：［**IPアドレス**］をフルポートスキャンして\n\n\
### 情報表示\n\
- faradayの表示\n\
    - faradayのダッシュボードを表示します。\n\
    - **使用方法**：［**情報** or **ファラデー** or **faraday**］を表示して\n\
- サービスリストの表示\n\
    - 検出したサービスをリストで表示します。\n\
    - **使用方法**：［**サービス**］を表示して\n\
- 脆弱性リストの表示\n\
    - 検出した脆弱性をリストで表示します。\n\
    - **使用方法**：［**脆弱性**］を表示して\n\n\
:rotating_light:WakeUp Code（#BOCCHI、#ぼっち等）の後、半角スペースを入れてから要件をお伝えください。"
    return menuText

def check_dir(targetIP):
    dirPath = f"results/{targetIP}"
    if os.path.isdir(dirPath):
        return dirPath
    else:
        os.mkdir(dirPath)
        return dirPath

def get_command(cmd):
    for command in commands:
        if command in cmd:
            return command
    return ""

@app.route("/matter", methods=['POST'])
def bot_reply():
    posted_user = request.json['user_name']
    posted_msg = request.json['text']
    try:
        firstSegment = posted_msg.split(" ")
        # firstSegment[0] : WakeUp Code
        # firstSegment[1] : Target & Command

        secondSegment = firstSegment[1].split("を")
        # secondSegment[0] : Target
        # secondSegment[1] : Command

        target = secondSegment[0]
        command = get_command(secondSegment[1])

        if command != "":
            if command in "表示":
                if target in "サービス":
                    messages = fc.show_service_list()
                elif target in "脆弱性":
                    messages = fc.show_vuln_list()
                elif target in "情報" or target in "ファラデー" or target in "faraday" or target in "Faraday":
                    messages = fc.show_service_message()
                elif target in "メニュー":
                    messages = get_menu()
                else:
                    messages = f"表示するものがありません。"
            # nmapを使用した各種スキャン
            elif command in "スキャン":
                # Mattermostへの開始連絡
                messages = f"nmapで{target}のスキャンを開始します。\nしばらくお待ちください:coffee:"
                messenger(posted_user=posted_user, msg=messages)

                # nmapをsubprocessで呼び出してスキャンを実行
                resultsPath = check_dir(targetIP=target)
                subprocess.run(["nmap","-vv","--reason","-Pn","-T4","-sV","-sC","--version-all","-A","-p21","--osscan-guess","--script=vuln","-oA",f"{resultsPath}/Scan_"+get_timestamp(),target])
                messages = f"{target}のスキャンが終了しました。"

                # faradayへ結果のインポート
                addText = fc.import_from_results(dir_path=resultsPath)

                # Mattermostへの終了連絡
                messages += f"\n{addText}"
            elif command in "フルポートスキャン":
                # Mattermostへの開始連絡
                messages = f"nmapで{target}のフルポートスキャンを開始します。\nしばらくお待ちください:coffee:"
                messenger(posted_user=posted_user, msg=messages)

                # nmapをsubprocessで呼び出してフルポートスキャンを実行
                resultsPath = check_dir(targetIP=target)
                subprocess.run(["nmap","-vv","--reason","-Pn","-T4","-sV","-sC","--version-all","-A","-p-","--osscan-guess","--script=vuln","-oA",f"{resultsPath}/FullScan_"+get_timestamp(),target])
                messages = f"{target}のフルポートスキャンが終了しました。"

                # faradayへ結果のインポート
                addText = fc.import_from_results(dir_path=resultsPath)

                # Mattermostへの終了連絡
                messages += f"\n{addText}"
            # Hydraで辞書攻撃

        else:
            messages  = get_menu()
        
    except IndexError:
        messages = "呼びました？"

    finally:
        messenger(posted_user=posted_user, msg=messages)

    return

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)