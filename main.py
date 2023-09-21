import argparse
import hashlib
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template


DEBUG = False
LOGIN_URL = "https://go.comwatt.com/api/v1/authent"
AUTHENTICATED_URL = "https://go.comwatt.com/api/users/authenticated"
INDEP_BOXES = "https://go.comwatt.com/api/indepboxes"
API_URL = "https://go.comwatt.com/api"
API_PATH = "/aggregations/networkstats"

# Create a session to persist cookies across requests
session = requests.Session()
session.headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
    'Connection': 'keep-alive',
}

app = Flask(__name__)


@app.route('/')
def home():
    if not login(username, password):
        return render_template("index.html", error="Erreur lors du login")
    box_id = get_box_id()
    if not box_id:
        return render_template("index.html", error="Erreur lors de la récupération de l'ID de la boite")
    response = get_last_hour(box_id)
    if not response:
        return render_template("index.html", error="Erreur lors de la récupération des données")
    data = data_for_highcharts(response.json())
    return render_template('index.html', box_id=box_id, data=data)


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


def login(username, password):
    login_data = {
        'username': username,
        'password': hash_password(password),
    }

    login_response = session.post(LOGIN_URL, data=login_data)

    if login_response.status_code == 200 and "cwt_session" in login_response.cookies:
        return True
    else:
        print("Login failed.")
        print(login_response.status_code)
        print(login_response.text)
        return False


def get_box_id():
    response = session.get(AUTHENTICATED_URL)
    if response.status_code != 200 or "id" not in response.json():
        print("Didn't get the owner id")
        print(response.status_code)
        print(response.json())
        return None

    ownerid = response.json()["id"]

    response = session.get(INDEP_BOXES + f"?ownerid={ownerid}")

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

    response = session.get(json_url)

    if response.status_code == 200:
        return response
    else:
        print("failed to get json")
        print(response.status_code)
        print(response.text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Retrieve the last hour of energy consumption and production.
                    Usage example:
                    python main.py --username your_username --password your_password
        """
    )

    # Add command-line arguments for username and password
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--password', required=True, help='Password')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Retrieve the username and password from the parsed arguments
    username = args.username
    password = args.password

    app.run(host="0.0.0.0", port=5000, debug=True)
