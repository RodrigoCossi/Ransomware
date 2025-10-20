# Server Keys

This folder contains **mock RSA keys** for demonstration and testing purposes only.

## Contents

- `public_key.key` - Mock RSA public key (2048-bit) in PEM format
- `generate_private_key.py` - Script to generate the corresponding private key

## Purpose

These keys are used by the ransomware encryption/decryption scripts for educational and testing purposes. They simulate the server-side keys that would be used in a real ransomware scenario.

**Note:** The private key is NOT included in the repository for security best practices. In a real ransomware scenario, the private key would only exist on the attacker's server. You can generate it locally if needed for testing using the provided script.

## ⚠️ Warning

**These are MOCK keys for demonstration purposes only!**

- **DO NOT** use these keys in any production environment
- **DO NOT** use these keys for any real security applications
- These keys are publicly available in this repository and offer **NO security**
- This project is for educational purposes to understand how ransomware works

## Usage

The `ransom-encrypt.py` script references the public key to encrypt a symmetric key:
```python
with open("server keys/public_key.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
```

The private key would be used on the "attacker's server" to decrypt the symmetric key.

## Generating the Private Key (Optional)

If you need the private key for testing decryption, run:
```bash
python3 "server keys/generate_private_key.py"
```

This will create `private_key.key` locally (not tracked in git).

## Key Generation

These keys were generated using Python's `cryptography` library:
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
```
