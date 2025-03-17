from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded test credentials
VALID_USERNAME = "admin"
VALID_PASSWORD = "xa"

# Simple login form
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Login Page</title></head>
<body>
    <h2>Test Login</h2>
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <p>{{ message }}</p>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            message = "Login Successful!"
        else:
            message = "Invalid password"
    
    return render_template_string(HTML_TEMPLATE, message=message)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
