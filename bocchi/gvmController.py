#!/usr/bin/python3

import datetime
import subprocess
import time
import xmltodict
from bocchi.config import gvm_conf as g_conf

CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
# Port list
All_IANA_assigned_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
All_IANA_assigned_TCP_and_UDP = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
All_TCP_and_Nmap_top_100_UDP = "730ef368-57e2-11e1-a90f-406186ea4fc5"

params = g_conf()
GVM_SERVER = params['server']

# ---------------------------------------------------------------------
# show_gvm
# ---------------------------------------------------------------------
def show_gvm():
    messages = f"脆弱性診断の結果を確認します。以下のリンクをクリック\n{GVM_SERVER}"
    return messages

# ---------------------------------------------------------------------
# check_gvm
# ---------------------------------------------------------------------
def check_gvm(TARGET):
    messages = f"{TARGET}の脆弱性診断が完了しました。レポートを確認してください。\n{GVM_SERVER}"
    return messages


# ---------------------------------------------------------------------
# get_target_id
# ---------------------------------------------------------------------
def get_target_id(ip_address):
    """
    指定されたIPアドレスに対するGVMのターゲットIDを取得するメソッド。

    Parameters:
        ip_address (str): ターゲットのIPアドレス

    Returns:
        str: ターゲットのID
    """
    target_name = "Target_" + datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    result = subprocess.run(["gvm-cli", "socket", "--xml",
                            f"<create_target><name>{target_name}</name><hosts>{ip_address}</hosts><port_list id=\"{All_IANA_assigned_TCP}\"></port_list></create_target>"],
                            capture_output=True, text=True)

    if result.stdout == "":
        return None
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['create_target_response']
        return response['@id']

# ---------------------------------------------------------------------
# get_task_id
# ---------------------------------------------------------------------
def get_task_id(target_id):
    """
    指定されたGVMのターゲットIDに対するタスクIDを取得するメソッド。

    Parameters:
        target_id (str): ターゲットのID

    Returns:
        str: タスクのID
    """
    task_name = "Task_" + datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    result = subprocess.run(["gvm-cli", "socket", "--xml",
                            f"<create_task><name>{task_name}</name><target id=\"{target_id}\"/><config id=\"{CONFIG_ID}\"/><scanner id=\"{SCANNER_ID}\"/></create_task>"],
                            capture_output=True, text=True)

    if result.stdout == "":
        return None
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['create_task_response']
        return response['@id']

# ---------------------------------------------------------------------
# start_task
# ---------------------------------------------------------------------
def start_task(task_id):
    """
    指定されたGVMのタスクIDに対するタスクを開始し、レポートIDを取得するメソッド。

    Parameters:
        task_id (str): タスクのID

    Returns:
        str: レポートのID
    """
    result = subprocess.run(["gvm-cli", "socket", "--xml",
                            f"<start_task task_id=\"{task_id}\"/>"],
                            capture_output=True, text=True)

    if result.stdout == "":
        return None
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['start_task_response']
        return response['report_id']
# ---------------------------------------------------------------------
# check_status
# ---------------------------------------------------------------------
def check_status(task_id):
    """
    指定されたGVMのタスクIDに対するタスクの状態を確認するメソッド。

    Parameters:
        task_id (str): タスクのID

    Returns:
        str: タスクの最終状態
    """
    while True:
        result = subprocess.run(["gvm-cli", "socket", "--xml",
                                f"<get_tasks task_id=\"{task_id}\" />"],
                                capture_output=True, text=True)

        if result.stdout == "":
            break
        else:
            xml = result.stdout
            root = xmltodict.parse(xml)
            response = root['get_tasks_response']['task']['status']

            if response == "Done":
                break
            else:
                time.sleep(60)  # 60秒待機

    return "Done"

# ---------------------------------------------------------------------
# delete_task
# ---------------------------------------------------------------------
def delete_task(task_id):
    """
    指定されたGVMのタスクIDに対するタスクを削除するメソッド。

    Parameters:
        task_id (str): タスクのID

    Returns:
        str: ステータステキスト
    """
    result = subprocess.run(["gvm-cli", "socket", "--xml",
                            f"<delete_task task_id=\"{task_id}\" />"],
                            capture_output=True, text=True)

    if result.stdout == "":
        return None
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['delete_task_response']
        return response['@status_text']

# ---------------------------------------------------------------------
# delete_target
# ---------------------------------------------------------------------
def delete_target(target_id):
    """
    指定されたGVMのターゲットIDに対するターゲットを削除するメソッド。

    Parameters:
        target_id (str): ターゲットのID

    Returns:
        str: ステータステキスト
    """
    result = subprocess.run(["gvm-cli", "socket", "--xml",
                            f"<delete_target target_id=\"{target_id}\" />"],
                            capture_output=True, text=True)

    if result.stdout == "":
        return None
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['delete_target_response']
        return response['@status_text']
