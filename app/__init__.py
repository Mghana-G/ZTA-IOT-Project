from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "Zero Trust IoT Framework API is up and running! ✅"

    return app
