from flask import Flask, render_template, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_status', methods=['POST'])
def check_status():
    url = request.form['url']
    try:
        response = requests.get(url)
        status_code = response.status_code
        return render_template('result.html', url=url, status_code=status_code)
    except requests.exceptions.RequestException as e:
        return render_template('result.html', url=url, error=str(e))

if __name__ == '__main__':
    app.run(debug=True)
