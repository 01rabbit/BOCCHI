import subprocess
import xmltodict

TARGET_NAME = "Suspect Host"
IPADDRESS = "127.0.0.1"
PORT_RANGE = "1-100"
TASK_NAME = "Scan Suspect Host"
CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
TARGET_ID = ""
TASK_ID = ""
REPORT_ID = ""

result = subprocess.run(["gvm-cli", "socket", "--xml",\
                        f"<create_target><name>{TARGET_NAME}</name><hosts>{IPADDRESS}</hosts><port_range>{PORT_RANGE}</port_range></create_target>"], capture_output=True, text=True)
if result.stdout == "":
    exit()
else:
    xml = result.stdout
    print(xml)
    root = xmltodict.parse(xml)
    response = root['create_target_response']
    TARGET_ID = response['@id']
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<create_task><name>{TASK_NAME}</name><target id=\"{TARGET_ID}\"/><config id=\"{CONFIG_ID}\"/><scanner id=\"{SCANNER_ID}\"/></create_task>"], capture_output=True, text=True)
    xml = result.stdout
    print(xml)
    root = xmltodict.parse(xml)
    response = root['create_task_response']
    TASK_ID = response['@id']
    print(TASK_ID)
    result = subprocess.run(["gvm-cli", "socket", "--xml",\
                            f"<start_task task_id=\"{TASK_ID}\"/>"], capture_output=True, text=True)
    xml = result.stdout
    print(xml)
    root = xmltodict.parse(xml)
    response = root['start_task_response']
    REPORT_ID = response['report_id']
    print(REPORT_ID)


