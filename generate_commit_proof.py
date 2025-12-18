import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---------- CONFIG ----------
COMMIT_HASH = "398a52d605ec0c48f62136a525fdbaaed9390f78"
STUDENT_PRIVATE_KEY = "student_private.pem"
INSTRUCTOR_PUBLIC_KEY = "instructor_public.pem"
# ----------------------------


def sign_message(message: str, private_key) -> bytes:
    return private_key.sign(
        message.encode("utf-8"),  # ASCII bytes (CRITICAL)
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ---- LOAD KEYS ----
with open(STUDENT_PRIVATE_KEY, "rb") as f:
    student_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open(INSTRUCTOR_PUBLIC_KEY, "rb") as f:
    instructor_public_key = serialization.load_pem_public_key(
        f.read()
    )

# ---- SIGN ----
signature = sign_message(COMMIT_HASH, student_private_key)

# ---- ENCRYPT SIGNATURE ----
encrypted_signature = encrypt_with_public_key(
    signature,
    instructor_public_key
)

# ---- BASE64 ENCODE ----
encoded_signature = base64.b64encode(encrypted_signature).decode("utf-8")

print("\n===== COMMIT PROOF =====")
print("Commit Hash:")
print(COMMIT_HASH)
print("\nEncrypted Signature (Base64, single line):")
print(encoded_signature)
