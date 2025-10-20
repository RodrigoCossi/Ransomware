#!/usr/bin/env python3
"""
Generate Private Key for Mock Server Keys

This script generates the private key that corresponds to the public key
in this folder. The private key is NOT tracked in git for security best practices.

In a real ransomware scenario, the private key would only exist on the
attacker's server and never be distributed.

For educational/testing purposes, you can run this script to generate
the private key locally.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

def generate_private_key():
    """Generate the private key from the existing public key."""
    
    # Load the public key
    script_dir = os.path.dirname(os.path.abspath(__file__))
    public_key_path = os.path.join(script_dir, "public_key.key")
    private_key_path = os.path.join(script_dir, "private_key.key")
    
    if os.path.exists(private_key_path):
        print(f"⚠️  Private key already exists at: {private_key_path}")
        response = input("Do you want to overwrite it? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Aborted.")
            return
    
    print("ℹ️  Note: This script cannot derive the private key from the public key.")
    print("   Instead, it will generate a NEW key pair.")
    print("   To use the existing public key, you need the original private key.")
    print()
    print("   This will generate a NEW private key that does NOT match the")
    print("   existing public key. The public key will be regenerated as well.")
    print()
    response = input("Continue? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Aborted.")
        return
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    print("\n🔐 Generating new RSA key pair...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write keys to files
    with open(private_key_path, "wb") as f:
        f.write(pem_private)
    print(f"✅ Private key saved to: {private_key_path}")
    
    with open(public_key_path, "wb") as f:
        f.write(pem_public)
    print(f"✅ Public key updated at: {public_key_path}")
    
    print("\n⚠️  SECURITY REMINDER:")
    print("   - These are MOCK keys for EDUCATIONAL purposes only")
    print("   - NEVER use these keys in production")
    print("   - The private key is NOT tracked in git (see .gitignore)")

if __name__ == "__main__":
    generate_private_key()
