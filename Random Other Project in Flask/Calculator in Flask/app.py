from flask import Flask, render_template, request

app = Flask(__name__)

# Define arithmetic functions
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

def divide(a, b):
    if b == 0:
        return "Error: Division by zero!"
    return a / b

# Route to render the calculator form
@app.route('/')
def index():
    return render_template('index.html', result=None)

# Route to handle calculation form submission
@app.route('/calculate', methods=['POST'])
def calculate():
    operation = request.form['operation']
    a = float(request.form['num1'])
    b = float(request.form['num2'])

    if operation == 'add':
        result = add(a, b)
        operation_symbol = '+'
    elif operation == 'subtract':
        result = subtract(a, b)
        operation_symbol = '-'
    elif operation == 'multiply':
        result = multiply(a, b)
        operation_symbol = '*'
    elif operation == 'divide':
        result = divide(a, b)
        operation_symbol = '/'
    else:
        result = 'Invalid operation'
        operation_symbol = ''

    return render_template('index.html', num1=a, num2=b, operation=operation_symbol, result=result)

if __name__ == '__main__':
    app.run(debug=True)
