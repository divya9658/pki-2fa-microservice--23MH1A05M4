import base64
import pyotp
from datetime import datetime, timezone
from pathlib import Path

SEED_FILE = Path("/data/seed.txt")
OUTPUT_FILE = Path("/cron/last_code.txt")

def generate_totp(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(base32_seed)
    return totp.now()

def main():
    if not SEED_FILE.exists():
        print("Seed file not found")
        return

    seed = SEED_FILE.read_text().strip()
    code = generate_totp(seed)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "a") as f:
        f.write(f"{timestamp} - 2FA Code: {code}\n")

if __name__ == "__main__":
    main()
