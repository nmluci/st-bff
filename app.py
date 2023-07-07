from flask import Flask, request, jsonify
from flask.helpers import make_response
from dotenv import load_dotenv
import requests
import os
import json

from resp import MetaResponse
from security import SecuredPayload, encrypt_payload, decrypt_payload

load_dotenv("conf/.env")
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.route(
    "/payment/<path:path>",
    methods=["POST", "GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
def handle_ping(path):
    res = requests.request(
        request.method,
        f"{os.getenv('REMOTE_API')}{path}",
        json=request.get_json(),
    )
    data = encrypt_payload(json.dumps(res.json()))

    resp = make_response(jsonify(data.toJSON()))
    resp.headers.set("X-SECRET-ID", data.key)
    return resp


@app.route("/encrypt", methods=["POST"])
def handle_encrypt():
    data = encrypt_payload(json.dumps(request.get_json()))

    resp = make_response(jsonify(data.toJSON()))
    resp.headers.set("X-SECRET-ID", data.key)
    return resp


@app.route("/decrypt", methods=["POST"])
def handle_decrypt():
    headers = request.headers

    data = decrypt_payload(
        SecuredPayload(
            **request.get_json(),
        ),
    )
    res = make_response(data)
    res.headers.set("content-type", "application/json")
    return res


app.run(host=os.getenv("HOST"), port=int(os.getenv("PORT") or 7780))
