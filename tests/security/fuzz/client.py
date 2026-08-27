import json
import urllib.error
import urllib.request


class FuzzClient:
    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def request(self, method, path, data=None, headers=None, auth=False):
        request_headers = dict(headers or {})
        if auth:
            request_headers["X-API-Key"] = self.apikey
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            return 0, ""

    def get_status(self, path):
        status, _ = self.request("GET", path)
        return status

    def post_json(self, path, obj, auth=False):
        data = json.dumps(obj).encode("utf-8")
        return self.request(
            "POST", path, data, {"Content-Type": "application/json"}, auth
        )

    def post_raw(self, path, raw, auth=False):
        return self.request(
            "POST", path, raw, {"Content-Type": "application/json"}, auth
        )
