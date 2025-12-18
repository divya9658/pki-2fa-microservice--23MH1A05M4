import requests

STUDENT_ID = "23MH1A05M4"
GITHUB_REPO_URL = "https://github.com/divya9658/pki-2fa-microservice--23MH1A05M4"
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

# 1. Read student public key (keep PEM format)
with open("student_public.pem", "r") as f:
    public_key = f.read()

# 2. Prepare request payload
payload = {
    "student_id": STUDENT_ID,
    "github_repo_url": GITHUB_REPO_URL,
    "public_key": public_key
}

# 3. Send POST request
response = requests.post(
    API_URL,
    json=payload,
    headers={"Content-Type": "application/json"},
    timeout=10
)

# 4. Handle response
if response.status_code != 200:
    raise Exception(f"API Error: {response.text}")

data = response.json()

if "encrypted_seed" not in data:
    raise Exception(f"Invalid response: {data}")

encrypted_seed = data["encrypted_seed"]

# 5. Save encrypted seed (DO NOT COMMIT)
with open("encrypted_seed.txt", "w") as f:
    f.write(encrypted_seed)

print("✅ Encrypted seed saved to encrypted_seed.txt")
