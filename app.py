from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/InputLink', methods=['POST'])
def InputLink():
        url = request.form['URL']
        return render_template('output.html', data=url)

if __name__ == '__main__':
    app.run(debug=True)
