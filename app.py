import json
import os
from flask import Flask, request
import requests
import subprocess
import threading
from config import matter_conf as config
from matter_communicator import messenger

app = Flask(__name__)

commands = ['表示', 'スキャン']

def get_menu():
    menuText = "## メニュー\n\
- test1\n\
- test2\n\
- test3"
    return menuText

def check_dir(targetIP):
    dirPath = f"results/{targetIP}"
    if os.path.isdir(dirPath):
        return
    else:
        os.mkdir(dirPath)
        return

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
            messages = f"{command}を開始します"
            messenger(posted_user=posted_user, msg=messages)

            if command in "表示":
                if target in "ファイル":
                    result = subprocess.run(["ls","-l"], capture_output=True, text=True)
                    messages = f"{command}が終了しました。\n" + result.stdout
                elif target in "メニュー":
                    messages = get_menu()
                else:
                    messages = f"表示するものがありません。"
            elif command in "スキャン":
                check_dir(targetIP=target)
                result = subprocess.run(["nmap", "-sn", "-oA", f"results/{target}/PingScan_{target}", f"{target}"], capture_output=True, text=True)
                messages = f"{command}が終了しました。\n" + result.stdout
        else:
            messages  = "Hi"
        
    except IndexError:
        messages = "呼びました？"

    finally:
        messenger(posted_user=posted_user, msg=messages)

    return

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)