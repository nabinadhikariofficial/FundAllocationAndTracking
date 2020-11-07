from flask import Flask, render_template, request, url_for

app = Flask(__name__)


@app.route("/")
def home():
    print(url_for('home'))
    return render_template("homepage.html")


if __name__ == "__main__":

    app.run(debug=True)
