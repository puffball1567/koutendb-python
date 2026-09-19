"""JSONL adapter for the shared core native-driver conformance suite."""
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from koutendb import KoutenClient, KoutenId

client = None
names = {
    "authToken": "auth_token", "secretKey": "secret_key", "tlsCaFile": "tls_ca_file",
    "tlsServerName": "tls_server_name", "tlsInsecureSkipVerify": "tls_insecure_skip_verify",
    "readTimeout": "read_timeout", "writeTimeout": "write_timeout",
    "maxFrameBytes": "max_frame_bytes", "maxRedirects": "max_redirects", "retryReads": "retry_reads",
}

for line in sys.stdin:
    try:
        request = json.loads(line)
        op = request["op"]
        if op == "connect":
            if client:
                client.close()
            options = {"timeout": 1, "read_timeout": 1, "write_timeout": 1}
            options.update({names.get(k, k): v for k, v in request.get("options", {}).items()})
            for key in ("timeout", "readTimeout", "writeTimeout"):
                if key in request:
                    options[names.get(key, key)] = request[key]
            client = KoutenClient.connect(request["peers"], **options)
            client._connection(0)
            result = "connected"
        elif op == "close":
            client.close()
            result = "closed"
        elif op == "debug":
            result = repr(client)
        elif op == "health":
            result = client.health()
        elif op == "put":
            result = str(client.put_codec(request["ring"], base64.b64decode(request["payload"]), request.get("codec", "raw")))
        elif op == "putJson":
            result = str(client.put_json(request["ring"], request["value"]))
        elif op == "get":
            value = client.get_encoded(KoutenId.parse(request["id"]))
            result = None if value is None else {"payload": base64.b64encode(value.payload).decode(), "codec": value.codec}
        elif op == "getJson":
            result = client.get_json(KoutenId.parse(request["id"]))
        elif op == "query":
            result = client.query_json(KoutenId.parse(request["id"]), request["selection"])
        else:
            raise ValueError("Unsupported adapter operation")
        print(json.dumps({"ok": True, "result": result}), flush=True)
    except Exception as error:
        print(json.dumps({"ok": False, "error": type(error).__name__, "message": str(error)}), flush=True)
