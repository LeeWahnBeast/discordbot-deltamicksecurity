import os
import threading
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return "Bot is alive!"


def run():
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)


def keep_alive():
    t = threading.Thread(target=run)
    t.daemon = True
    t.start()
