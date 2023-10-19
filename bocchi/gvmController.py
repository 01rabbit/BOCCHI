import subprocess
import xmltodict
import datetime
import time
from bocchi.config import gvm_conf as g_conf

CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
# Port list
All_IANA_assigned_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
All_IANA_assigned_TCP_and_UDP = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
All_TCP_and_Nmap_top_100_UDP = "730ef368-57e2-11e1-a90f-406186ea4fc5"

params = g_conf()
GVM_SERVER = params['server']

def show_gvm():
    messages = f"脆弱性診断の結果を確認します。以下のリンクをクリック\n{GVM_SERVER}"
    return messages

def check_gvm(TARGET):
    messages = f"{TARGET}の脆弱性診断が完了しました。レポートを確認してください。\n{GVM_SERVER}"
    return messages


def getTargetID(IPADDRESS):
    TARGET_NAME = "Target_" + datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<create_target><name>{TARGET_NAME}</name><hosts>{IPADDRESS}</hosts><port_list id=\"{All_IANA_assigned_TCP}\"></port_list></create_target>"], capture_output=True, text=True)
    if result.stdout == "":
        return
    else:
        xml = result.stdout
        # print(xml)
        root = xmltodict.parse(xml)
        response = root['create_target_response']
        return response['@id']

def getTaskID(TARGET_ID):
    TASK_NAME = "Task_" + datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<create_task><name>{TASK_NAME}</name><target id=\"{TARGET_ID}\"/><config id=\"{CONFIG_ID}\"/><scanner id=\"{SCANNER_ID}\"/></create_task>"], capture_output=True, text=True)
    if result.stdout == "":
        return
    else:
        xml = result.stdout
        # print(xml)
        root = xmltodict.parse(xml)
        response = root['create_task_response']
        return response['@id']
        # print(TASK_ID)

def startTask(TASK_ID):
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<start_task task_id=\"{TASK_ID}\"/>"], capture_output=True, text=True)
    if result.stdout == "":
        return
    else:
        xml = result.stdout
        # print(xml)
        root = xmltodict.parse(xml)
        response = root['start_task_response']
        return response['report_id']
        # print(REPORT_ID)

def checkStatus(TASK_ID):
    while True:
        result = subprocess.run(["gvm-cli", "socket", "--xml",\
                                f"<get_tasks task_id=\"{TASK_ID}\" />"], capture_output=True, text=True)
        if result.stdout == "":
            break
        else:
            xml = result.stdout
            root = xmltodict.parse(xml)
            response = root['get_tasks_response']['task']['status']
            # print(response)
            if response == "Done":
                break
            else:
                time.sleep(60) # ６０秒待機
    # print("done")
    return "Done"

def deleteTask(TASK_ID):
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<delete_task task_id=\"{TASK_ID}\" />"], capture_output=True, text=True)
    if result.stdout == "":
        return
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['delete_task_response']
        return response['@status_text']

def deleteTarget(TARGET_ID):
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<delete_target target_id=\"{TARGET_ID}\" />"], capture_output=True, text=True)
    if result.stdout == "":
        return
    else:
        xml = result.stdout
        root = xmltodict.parse(xml)
        response = root['delete_target_response']
        return response['@status_text']
