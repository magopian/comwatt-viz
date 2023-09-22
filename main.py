import hashlib
import os
import requests
from datetime import datetime, timedelta
from flask import Flask, flash, redirect, render_template, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length


DEBUG = False
LOGIN_URL = "https://go.comwatt.com/api/v1/authent"
AUTHENTICATED_URL = "https://go.comwatt.com/api/users/authenticated"
INDEP_BOXES = "https://go.comwatt.com/api/indepboxes"
API_URL = "https://go.comwatt.com/api"
API_PATH = "/aggregations/networkstats"
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24))
PORT = os.environ.get("PORT", 5000)

# Create a session to persist cookies across requests
request_session = requests.Session()
request_session.headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
    'Connection': 'keep-alive',
}

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.route("/")
def home():
    session["foobar"] = "barbaz"
    if "cwt_session" in session:
        request_session.cookies["cwt_session"] = session["cwt_session"]
    else:
        return redirect(url_for("login"))

    box_id = get_box_id()
    if not box_id:
        return render_template("index.html", error="Erreur lors de la récupération de l'ID de la boite")
    response = get_last_hour(box_id)
    if not response:
        return render_template("index.html", error="Erreur lors de la récupération des données")
    data = data_for_highcharts(response.json())
    return render_template("index.html", box_id=box_id, data=data)


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField("Login")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        cwt_session = authenticate(username, password)
        if cwt_session:
            session["cwt_session"] = cwt_session
            session.permanent = True
            return redirect(url_for("home"))
        else:
            session.pop("cwt_session", default=None)
            flash("Login failed. Please check your username and password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.pop("cwt_session", default=None)
    return redirect(url_for("login"))


def data_for_highcharts(json_data):
    data = {
        "entries": [],
        "production": [],
        "consumption": [],
    }
    current_time = datetime.now()
    one_hour_ago = current_time - timedelta(hours=1)

    for i, entry in enumerate(json_data):
        timestamp = one_hour_ago + timedelta(minutes=i*2)
        try:
            data["entries"].append(timestamp)
            data["production"].append(entry["productionFlow"])
            data["consumption"].append(entry["consumptionFlow"])
        except KeyError:
            data["entries"].append("")
            data["production"].append("")
            data["consumption"].append("")
    return data


def hash_password(password):
    salted_password = f"jbjaonfusor_{password}_4acuttbuik9"

    sha256_hash = hashlib.sha256()

    # Update the hash object with the bytes of the string
    sha256_hash.update(salted_password.encode())

    # Get the hexadecimal representation of the hash
    hashed_string = sha256_hash.hexdigest()
    return hashed_string


def authenticate(username, password):
    login_data = {
        "username": username,
        "password": hash_password(password),
    }

    login_response = request_session.post(LOGIN_URL, data=login_data)

    if login_response.status_code == 200 and "cwt_session" in login_response.cookies:
        return login_response.cookies["cwt_session"]
    else:
        print("Login failed.")
        print(login_response.status_code)
        print(login_response.text)
        return False


def get_box_id():
    response = request_session.get(AUTHENTICATED_URL)
    if response.status_code != 200 or "id" not in response.json():
        print("Didn't get the owner id")
        print(response.status_code)
        print(response.json())
        return None

    ownerid = response.json()["id"]

    response = request_session.get(INDEP_BOXES + f"?ownerid={ownerid}")

    if response.status_code != 200 or "content" not in response.json():
        print("Didn't get the owner's boxes")
        print(response.status_code)
        print(response.json())
        return None

    first_box = response.json()["content"][0]
    box_id = first_box["id"]
    print("Got the box id:", box_id)
    return box_id


def get_last_hour(box_id):

    # Get the current time
    current_time = datetime.now()
    one_hour_ago = current_time - timedelta(hours=1)

    start = one_hour_ago.strftime("%Y-%m-%d %H:%M:%S")
    end = current_time.strftime("%Y-%m-%d %H:%M:%S")

    json_url = (
        API_URL
        + API_PATH
        + f"?indepbox_id={box_id}" + "&level=TWO_MINUTES&measure_kind=FLOW"
        + f"&start={start}"
        + f"&end={end}")

    print("json url", json_url)

    response = request_session.get(json_url)

    if response.status_code == 200:
        return response
    else:
        print("failed to get json")
        print(response.status_code)
        print(response.text)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
