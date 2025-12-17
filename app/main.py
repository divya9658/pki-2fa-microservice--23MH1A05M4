from fastapi import FastAPI, HTTPException
from pathlib import Path
from cryptography.hazmat.primitives import serialization

from scripts.crypto_utils import (
    decrypt_seed,
    generate_totp_code,
    verify_totp_code
)

import time

app = FastAPI()

# Path where seed must be stored (Docker volume)
SEED_FILE = Path("/data/seed.txt")

# Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

@app.post("/decrypt-seed")
def decrypt_seed_api(payload: dict):
    if "encrypted_seed" not in payload:
        raise HTTPException(status_code=400, detail="Missing encrypted_seed")

    try:
        # Decrypt seed
        seed = decrypt_seed(payload["encrypted_seed"], private_key)

        # Ensure directory exists
        SEED_FILE.parent.mkdir(parents=True, exist_ok=True)

        # Save seed persistently
        SEED_FILE.write_text(seed)

        return {"status": "ok"}

    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")

@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed = SEED_FILE.read_text().strip()

    # Generate TOTP code
    code = generate_totp_code(seed)

    # Calculate remaining seconds in 30s window
    valid_for = 30 - (int(time.time()) % 30)

    return {
        "code": code,
        "valid_for": valid_for
    }

@app.post("/verify-2fa")
def verify_2fa(payload: dict):
    if "code" not in payload:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed = SEED_FILE.read_text().strip()

    is_valid = verify_totp_code(seed, payload["code"])

    return {"valid": is_valid}
