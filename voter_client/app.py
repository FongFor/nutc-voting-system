from flask import Flask



app = Flask(__name__)



@app.route('/')

def home():

    return "測試 TESTTESTTESTTESTTESTTESTTESTTESTTEST"



if __name__ == '__main__':

    # host='0.0.0.0' 非常重要！這樣 Docker 容器外的電腦才連得進去

    app.run(host='0.0.0.0', port=5000)