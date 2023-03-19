from flask import Flask, render_template, flash, request, url_for, redirect, session, jsonify, send_file, make_response
import sys

app = Flask(__name__)

@app.route('/')
def homepage():
    return render_template("home.html")

if __name__ == "__main__":
    app.run()
