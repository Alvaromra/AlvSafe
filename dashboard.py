from flask import Flask
from datetime import datetime

app = Flask(__name__)


@app.route('/')
def home():

    return f'''
    <h1>ALVSafe Dashboard</h1>

    <p>Status: Protegido</p>

    <p>Última atualização:
    {datetime.now()}</p>
    '''


if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )