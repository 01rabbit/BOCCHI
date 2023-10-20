from configparser import ConfigParser
import os
import errno

def config(filename, section):
    # create a parser
    parser = ConfigParser()
    # read config file
    filename=os.path.join(os.path.dirname(__file__), filename)
    parser.read(filename, encoding='utf-8')
    result = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            result[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))
    
    return result

def db_conf():
    return config('service.ini','postgresql')

def matter_conf():
    return config('service.ini','mattermost')

def faraday_conf():
    return config('service.ini','faraday')

def gvm_conf():
    return config('service.ini','gvm')

def brutespray_conf():
    return config('service.ini','brutespray')

if __name__ == '__main__':
    config()