from flask import Flask, render_template, jsonify, request, redirect, flash, url_for,send_file

from libs.db_acme import *
from libs.db_x509 import *
from libs.db_step import *
from libs.stepapi import *
import subprocess
import urllib3
from datetime import datetime
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT, CA_URL
from io import BytesIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

app.secret_key = "super-secret-key" 

CONFIG_PATH = "ca.json"

client = StepCAClient(CA_URL)  # Use the CA URL from config.py

client.revoke("3738333836353636353039343837313132353639383830353435363330383430383536373938")