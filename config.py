import os
import random
import string


basedir = os.path.abspath(os.path.dirname(__file__))


import json

# Load the JSON file
with open("settings.json") as f:
    config = json.load(f)

# Recreate variables
DB_HOST = config["database"]["host"]
DB_USER = config["database"]["user"]
DB_PASSWORD = config["database"]["password"]
DB_NAME = config["database"]["name"]
DB_PORT = config["database"]["port"]
CA_URL = config["ca"]["url"]
CA_FINGERPRINT = config["ca"]["fingerprint"]

# You can now use the variables as before
print(DB_HOST, DB_USER, CA_URL)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        SECRET_KEY = "".join(random.choice(string.ascii_lowercase) for i in range(32))
    SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@localhost/{DB_NAME}" or "sqlite:///" + os.path.join(
        basedir, "app.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
