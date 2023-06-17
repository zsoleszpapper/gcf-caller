import requests
import time
import jwt
import json
import configparser

"""

Based on:
https://cloud.google.com/functions/docs/securing/authenticating#exchanging_a_self-signed_jwt_for_a_google-signed_id_token

Create config file like:
^^^^^^^^^^^^^^^^^^^^^^^^
[ServiceAccount]
filename = service-accounts/my-service-account.json

[CloudFunction]
location = europe-west1
project_id = my-project-id-123456
function_name = test-funcname

"""

# Hardcoded
google_token_exchange_url = 'https://www.googleapis.com/oauth2/v4/token'

# Generate a JWT token using a service account JSON file
def generate_jwt_service_account(service_account_file: str, function_url: str) -> str:
    expiry_seconds = 3600  # 1 hour
    current_time = int(time.time())

    with open(service_account_file, 'r') as f:
        service_account_info = json.load(f)

    headers = {
        'alg': 'RS256',
        'typ': 'JWT'
    }

    payload = {
        'target_audience': function_url,
        'iss': service_account_info['client_email'],
        'sub': service_account_info['client_email'],
        'iat': current_time,
        'exp': current_time + expiry_seconds,
        'aud': google_token_exchange_url,
    }

    jwt_token = jwt.encode(payload, service_account_info['private_key'], algorithm='RS256', headers=headers)
    return jwt_token

# Exchanging a self-signed JWT for a Google-signed ID token
def exchange_from_jwt_to_google_signed(jwt_token: str) -> str:
    url = google_token_exchange_url
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': jwt_token
    }
    response = requests.post(url=url, data=data, headers=headers)
    if response.status_code == 200:
        print('Exchange executed successfully!')
        response_json = json.loads(response.text)
        return response_json['id_token']
    else:
        print('Error:', response.text)

# Make an authenticated request to the Cloud Function
def make_authenticated_request(id_token: str, function_url: str) -> None:
    headers = {
        'Authorization': f'Bearer {id_token}'
    }
    response = requests.get(function_url, headers=headers)

    if response.status_code == 200:
        print('Function executed successfully!')
        print('Response:', response.text)
    else:
        print('Error:', response.text)


config = configparser.ConfigParser()
config.read('config.ini')

location = config['CloudFunction']['location']
project_id = config['CloudFunction']['project_id']
function_name = config['CloudFunction']['function_name']
function_url = f'https://{location}-{project_id}.cloudfunctions.net/{function_name}'

service_account_file = config['ServiceAccount']['filename']

jwt_token = generate_jwt_service_account(service_account_file, function_url)
id_token = exchange_from_jwt_to_google_signed(jwt_token)

make_authenticated_request(id_token, function_url)
