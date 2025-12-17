import base64
import re
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256)

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object

    Returns:
        Decrypted 64-character hex seed string
    """

    # 1. Base64 decode
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception:
        raise ValueError("Invalid base64 encrypted seed")

    # 2. RSA OAEP decryption
    try:
        decrypted_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        raise ValueError("RSA decryption failed")

    # 3. Decode to UTF-8 string
    try:
        seed = decrypted_bytes.decode("utf-8")
    except Exception:
        raise ValueError("Decrypted seed is not valid UTF-8")

    # 4. Validate hex seed (64 chars, lowercase hex)
    if not HEX_PATTERN.fullmatch(seed):
        raise ValueError("Decrypted seed is not a valid 64-character hex string")

    # 5. Return valid seed
    return seed
