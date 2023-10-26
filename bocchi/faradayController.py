from bocchi.config import faraday_conf as f_conf
import subprocess
import os 

params = f_conf()
FARADAY_USER = params['user']
FARADAY_PASS = params['password']
FARADAY_SERVER = params['server']
FARADAY_WORKSPACE = params['workspace']

def show_faraday():
    messages = f"情報はFaradayで確認します。以下のリンクをクリック\n{FARADAY_SERVER}"
    return messages

def connect_faraday():
    messages = ""
    result = subprocess.run(["faraday-cli", "auth", "-f", FARADAY_SERVER, "-u", FARADAY_USER, "-p", FARADAY_PASS], capture_output=True, text=True)
    if "Authenticated" in result.stdout:
        print(result.stdout)    ## debug上で表示される（消しても良い）
        subprocess.run(["faraday-cli", "workspace", "create", FARADAY_WORKSPACE], capture_output=True, text=True)
        result = subprocess.run(["faraday-cli", "workspace", "select", FARADAY_WORKSPACE], capture_output=True, text=True)
        if "Selected" in result.stdout:
            print(result.stdout)    ## debug上で表示される（消しても良い）
            # 何も問題がない場合は空文字列を返す
            return messages
        else:
            # ワークスペース選択誤りの場合
            messages = "ワークスペースの選択時に問題がありました。"
            return messages
    else:
        # 認証に問題があった場合
        messages = "認証に問題がありました。"
        return messages

def import_from_results(dir_path):
    messages = connect_faraday()
    if messages == "":
        dir_list = os.listdir(dir_path)

        for i in range(len(dir_list)):

            if ".xml" == os.path.splitext(dir_list[i])[1]: ## os.path.splitext()[1]で拡張子を取得
                xmlPath = os.path.join(dir_path, dir_list[i])
                print(xmlPath)
                subprocess.run(["faraday-cli", "tool", "report", xmlPath])
        messages = "結果をfaradayにインポートしました。"
    else:
        messages += "\n結果のインポートに失敗しました。"
    return messages

def show_service_list():
    messages = connect_faraday()
    if messages == "":
        result = subprocess.run(["faraday-cli", "service", "list"], capture_output=True, text=True)
        return result.stdout
    else:
        return messages

def show_vuln_list():
    messages = connect_faraday()
    if messages == "":
        result = subprocess.run(["faraday-cli", "vuln", "list"], capture_output=True, text=True)
        return result.stdout
    else:
        return messages

# dir_path = "results/192.168.136.135/scans/xml" 
# import_from_results(dir_path)
