#!/usr/bin/python3

import os
from configparser import ConfigParser

# ---------------------------------------------------------------------
# read_config
# ---------------------------------------------------------------------
def read_config(filename, section):
    """
    指定された設定ファイルから指定されたセクションの設定を読み取るメソッド。

    Parameters:
        filename (str): 設定ファイルのパス
        section (str): 読み取るセクションの名前

    Returns:
        dict: セクション内の設定項目と値を含むディクショナリ
    """
    # パーサーの作成
    parser = ConfigParser()
    
    # 設定ファイルの読み込み
    filename = os.path.join(os.path.dirname(__file__), filename)
    parser.read(filename, encoding='utf-8')

    result = {}

    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            result[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return result

def matter_conf():
    return read_config('service.ini','mattermost')

def faraday_conf():
    return read_config('service.ini','faraday')

def gvm_conf():
    return read_config('service.ini','gvm')

def brutespray_conf():
    return read_config('service.ini','brutespray')

if __name__ == '__main__':
    read_config()