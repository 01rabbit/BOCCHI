import json
from flask import Flask, render_template, request
import json
import slackweb

app = Flask(__name__)
mattermost = slackweb.Slack(url="http://127.0.0.1/hooks/bbw4mq7jhbgaumba3mg6ce1grw")

@app.route("/")
def hello():
    return "HelloWorld"

@app.route("/matter", methods=['POST'])
def post():
    date = request.json
    text = date['text']
    _, newtext = text.split(' ')

    text = ''.join(newtext)
    mattermost.notify(text=text)
    print(date)
    return json.dumps(dict())

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)