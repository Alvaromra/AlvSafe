import hashlib
import requests

API_KEY = "SUA_API_KEY"


def check_virustotal(file_path):

    try:

        with open(file_path, "rb") as f:

            file_hash = hashlib.sha256(
                f.read()
            ).hexdigest()

        url = (
            "https://www.virustotal.com/"
            f"api/v3/files/{file_hash}"
        )

        headers = {
            "x-apikey": API_KEY
        }

        response = requests.get(
            url,
            headers=headers
        )

        if response.status_code == 200:

            return response.json()

    except:
        return None