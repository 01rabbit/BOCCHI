#!/usr/bin/python3

import os
from janome.analyzer import Analyzer
from janome.tokenfilter import *
import random
from flask import Flask, request
import subprocess
import datetime
from socket import inet_aton
from bocchi.matterCommunicator import messenger
from bocchi.config import brutespray_conf as b_conf
import bocchi.faradayController as fc
import bocchi.gvmController as gc

app = Flask(__name__)

# commands = ['表示', 'スキャン', '脆弱性診断','認証試行']

def valid_ip(order):
    for word in order:
        try:
            inet_aton(word)
            return word
        except:
            None

def get_timestamp():
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

def get_menu():
    menuText = "## メニュー\n\
### 調査系\n\
- スキャン\n\
    - nmapを使用してターゲットを調査します。\n\
    - **通常**\n\
        - ［**IPアドレス**］をスキャンして\n\
    - **フルポート**\n\
        - ［**IPアドレス**］をフルポートでスキャンして\n\
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
:warning: WakeUp Code（**@bocchi**,**@ぼっち**）の後、半角スペースを入れてから要件をお伝えください。"
    return menuText

def check_dir(targetIP):
    dirPath = f"results/{targetIP}"
    if os.path.isdir(dirPath):
        return dirPath
    else:
        os.mkdir(dirPath)
        return dirPath

def answer():
    rand = random.randint(1,20)
    if rand % 3 == 0 and rand % 5 == 0:
        messages = "「メニューを表示して」と言ってもらえればメニューを表示します。"
    elif rand % 3 == 0:
        messages = "何かお困りですか？"
    elif rand % 5 == 0:
        messages = "はい、なんでしょうか？"
    else:
        messages = "呼びました？"
    return messages

@app.route("/matter", methods=['POST'])
def bot_reply():
    posted_user = request.json['user_name']
    posted_msg = request.json['text']
    messages=""
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
                    # Mattermostへの開始連絡
                    messages = f"nmapで{ipaddr}のフルポートスキャンを開始します。\nしばらくお待ちください:coffee:"
                    messenger(posted_user=posted_user, msg=messages)

                    # nmapをsubprocessで呼び出してフルポートスキャンを実行
                    resultsPath = check_dir(targetIP=ipaddr)
                    subprocess.run(["nmap","-vv","--reason","-Pn","-T4","-sV","-sC","--version-all","-A","-p-","--osscan-guess","--script=vuln","-oA",f"{resultsPath}/FullScan_"+get_timestamp(),ipaddr])
                    messages = f"{ipaddr}のフルポートスキャンが終了しました。"

                    # faradayへ結果のインポート
                    addText = fc.import_from_results(dir_path=resultsPath)

                    # Mattermostへの終了連絡
                    messages += f"\n{addText}"
                    # 標準スキャン
                elif "スキャン" in userOrder:
                    # Mattermostへの開始連絡
                    messages = f"nmapで{ipaddr}のスキャンを開始します。\nしばらくお待ちください:coffee:"
                    messenger(posted_user=posted_user, msg=messages)

                    # nmapをsubprocessで呼び出してスキャンを実行
                    resultsPath = check_dir(targetIP=ipaddr)
                    subprocess.run(["nmap","-vv","--reason","-Pn","-T4","-sV","-sC","--version-all","-A","--osscan-guess","--script=vuln","-oA",f"{resultsPath}/Scan_"+get_timestamp(),ipaddr])
                    messages = f"{ipaddr}のスキャンが終了しました。"

                    # faradayへ結果のインポート
                    addText = fc.import_from_results(dir_path=resultsPath)

                    # Mattermostへの終了連絡
                    messages += f"\n{addText}"
                # GVMを使用した脆弱性診断
                elif "脆弱性診断" in userOrder:
                    # Mattermostへの開始連絡
                    messages = f"GVM(Openvas)で{ipaddr}の脆弱性診断を開始します。\nしばらくお待ちください:coffee:"
                    messenger(posted_user=posted_user, msg=messages)

                    # ターゲットの作成
                    targetID = gc.getTargetID(ipaddr)

                    # タスクの作成
                    taskID = gc.getTaskID(targetID)

                    # タスクの開始
                    gc.startTask(taskID)

                    # タスクの終了待機
                    gc.checkStatus(taskID)
                    messages = gc.check_gvm(ipaddr)
                    # IPアドレスがないと診断できない
                # Brutesprayで認証攻撃
                elif "認証試行" in userOrder:
                    params = b_conf()
                    USER = params['user_list']
                    PASS = params['password_list']

                    resultsPath = check_dir(targetIP=ipaddr)
                    messages = "認証試行を開始します。\nしばらくお待ちください:coffee:"
                    messenger(posted_user=posted_user, msg=messages)
                    subprocess.run(["nmap","-vv","-Pn","-T4","-sV","-oG",f"{resultsPath}/result",ipaddr])
                    subprocess.run(["brutespray", "--file", f"{resultsPath}/result", "-U", f"{USER}", "-P", f"{PASS}", "-o", f"{resultsPath}", "--threads", "5"])

                    dir_list = os.listdir(resultsPath)
                    results = ""

                    for i in range(len(dir_list)):

                        if ".txt" == os.path.splitext(dir_list[i])[1]: ## os.path.splitext()[1]で拡張子を取得
                            filePath = os.path.join(resultsPath, dir_list[i])
                            print(filePath)
                            with open(filePath) as f:
                                results += f.read()
                    messages = "認証試行終了。\n" + results
            else:
                messages = ":no_entry: 指定されたIPアドレスは診断対象外です。\n対象に加えるならば***target_IPs.txt***に追記してください。"
                return
        elif "表示" in userOrder:
            if "メニュー" in userOrder:
                # メニューを表示
                messages = get_menu()
            elif "サービス" in userOrder:
                # サービスをリストで表示
                messages = fc.show_service_list()
            elif "脆弱性診断" in userOrder:
                # GVMのダッシュボードを表示
                messages = gc.show_gvm()
            elif "脆弱" in userOrder:
                # 脆弱性情報をリストで表示
                messages = fc.show_vuln_list()
            elif "情報" in userOrder or "ファラデー" in userOrder or "faraday" in userOrder or "Faraday" in userOrder:
                # Faradayのダッシュボードを表示
                messages = fc.show_faraday()
        else:
            messages  = get_menu()

    except IndexError:
        messages = answer()

    finally:
        messenger(posted_user=posted_user, msg=messages)

    return

def main():
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()