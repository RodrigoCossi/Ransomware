# Ransomware Proof of Concept

## ⚠️ IMPORTANT DISCLAIMERS

**FOR EDUCATIONAL PURPOSES ONLY**

This project is a **proof of concept** created solely for educational and research purposes to demonstrate how ransomware operates. This code is intended to help cybersecurity professionals, students, and researchers understand ransomware mechanics for defensive purposes.

### Legal and Ethical Warnings

- **DO NOT USE THIS CODE FOR MALICIOUS PURPOSES**
- Using this code to encrypt files without authorization is **ILLEGAL** and may violate computer crime laws
- The authors are **NOT RESPONSIBLE** for any misuse, damage, or legal consequences resulting from the use of this code
- This software is provided "AS IS" without warranty of any kind
- Users assume full responsibility for compliance with all applicable laws and regulations
- Only use this code in controlled environments (isolated VMs, test systems) with explicit permission

### Intended Audience

This project is designed for:
- Cybersecurity students and professionals
- Security researchers studying malware behavior
- Penetration testers in authorized environments
- Educational institutions teaching cybersecurity concepts

---

## What is Ransomware?

**Ransomware** is a type of malicious software that encrypts a victim's files and demands payment (usually in cryptocurrency) for the decryption key. It's one of the most devastating forms of cybercrime, causing billions of dollars in damages annually.

### How Ransomware Works

1. **Initial Infection**: Malware gains access to the system (phishing, exploits, etc.)
2. **Key Generation**: Creates encryption keys for file encryption
3. **File Discovery**: Scans the system for valuable files to encrypt
4. **Encryption**: Encrypts files using strong cryptographic algorithms
5. **Ransom Demand**: Displays a message demanding payment for decryption
6. **Key Exchange**: Victims must contact attackers to receive decryption keys

### Encryption Methods

Modern ransomware typically uses **hybrid encryption**:
- **Symmetric encryption** (AES/Fernet) for fast file encryption
- **Asymmetric encryption** (RSA) to protect the symmetric keys
- Only attackers possess the private key needed for decryption

---

## Project Structure

This proof of concept demonstrates a simplified ransomware system with two main components:

```
├── ransom-encrypt.py    # Victim-side encryption script
├── ransom-decrypt.py    # Server-side decryption service
├── traverse.py          # File discovery utility
├── r.py                 # Legacy encryption script
└── README.md           # This documentation
```

---

## Code Analysis

### `ransom-encrypt.py` - Encryption Component

This script demonstrates the victim-side encryption process:

#### Key Features:
- **Hybrid Encryption**: Uses Fernet (AES-128) for file encryption and RSA for key protection
- **Key Generation**: Creates a random symmetric key for each execution
- **Public Key Encryption**: Encrypts the symmetric key using RSA-OAEP padding
- **File Encryption**: Overwrites target files with encrypted data

#### Process Flow:
1. Generate a random Fernet symmetric key
2. Load the attacker's public RSA key from file
3. Encrypt the symmetric key using RSA-OAEP
4. Save the encrypted symmetric key to `encryptedSymmertricKey.key`
5. Encrypt target files using the symmetric key
6. Overwrite original files with encrypted versions

#### Code Structure:
```python
# Key generation
symmetricKey = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)

# Public key loading and symmetric key encryption
with open("/path/to/Ransomware/public_key.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())
    
encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,
    padding.OAEP(...)
)

# File encryption
encrypted_data = FernetInstance.encrypt(file_data)
```

### `ransom-decrypt.py` - Decryption Server

This script implements the attacker's decryption server:

#### Components:

1. **TCP Server (`ClientHandler` class)**:
   - Listens on port 8000 for victim connections
   - Receives encrypted symmetric keys from victims
   - Decrypts keys using the private RSA key
   - Returns decrypted symmetric keys to victims

2. **Client Functions**:
   - `sendEncryptedKey()`: Sends encrypted keys to the decryption server
   - `decryptFile()`: Decrypts files using recovered symmetric keys

#### Server Process:
```python
def handle(self):
    encrypted_key = self.request.recv(1024).strip()
    
    # Load private key
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read())
    
    # Decrypt symmetric key
    decrypted_symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(...)
    )
    
    # Send back to victim
    self.request.sendall(decrypted_symmetric_key)
```

### `traverse.py` - File Discovery

A utility script that demonstrates how ransomware discovers files to encrypt:
- Walks through directory structures
- Identifies potential target files
- Currently only prints file paths (demonstration only)

---

## Security Analysis

### Cryptographic Strength

This implementation uses industry-standard cryptographic algorithms:
- **Fernet (AES-128-CBC + HMAC-SHA256)**: Provides authenticated encryption
- **RSA with OAEP padding**: Prevents chosen plaintext attacks
- **SHA-256**: Cryptographically secure hash function

### Potential Vulnerabilities (Educational)

1. **Hardcoded Paths**: Real ransomware would use dynamic path discovery
2. **Key Storage**: Private keys would be stored remotely, not locally
3. **No Persistence**: Lacks mechanisms for system persistence
4. **Limited File Types**: Targets specific files rather than comprehensive encryption
5. **Error Handling**: Detailed error messages could aid in forensic analysis

---

## Testing Environment Setup

### Prerequisites

```bash
pip install cryptography
```

### Safe Testing Guidelines

1. **Use Isolated Environment**: Only test in disconnected virtual machines
2. **Backup Important Data**: Never test on systems with valuable data
3. **Test Files**: Create dummy files specifically for testing
4. **Network Isolation**: Disconnect from all networks during testing
5. **Clean Slate**: Use fresh VM snapshots for each test

### Key Generation (Required for Testing)

Generate RSA key pair for testing:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save private key
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key
public_key = private_key.public_key()
with open("public_key.key", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
```

---

## Defense Strategies

Understanding ransomware helps in developing defenses:

### Prevention
- **Regular Backups**: Maintain offline, immutable backups
- **Patch Management**: Keep systems updated
- **User Training**: Educate about phishing and social engineering
- **Network Segmentation**: Limit lateral movement
- **Endpoint Protection**: Deploy advanced anti-malware solutions

### Detection
- **File System Monitoring**: Watch for rapid file changes
- **Network Traffic Analysis**: Detect C&C communications
- **Behavioral Analysis**: Identify suspicious process behavior
- **Entropy Analysis**: Monitor for high-entropy file creation

### Response
- **Incident Response Plan**: Have a tested response procedure
- **System Isolation**: Quickly isolate infected systems
- **Forensic Analysis**: Preserve evidence for investigation
- **Recovery Procedures**: Execute backup restoration plans

---

## Legal and Compliance Notes

### Regulatory Considerations
- **GDPR**: May require breach notification
- **HIPAA**: Healthcare data requires specific protections
- **SOX**: Financial data has additional compliance requirements
- **State Laws**: Various state-level data breach notification laws

### Law Enforcement
- **FBI IC3**: Report ransomware incidents
- **CISA**: Provides ransomware guidance and resources
- **Local Authorities**: May assist with investigation

---

## Research and Learning Resources

### Academic Papers
- "Ransomware: Evolution, Mitigation and Prevention" - IEEE Papers
- "A Survey on Ransomware: Evolution, Taxonomy, and Defense Solutions"
- NIST Cybersecurity Framework for Ransomware Risk Management

### Training Resources
- SANS Ransomware Defense Courses
- MITRE ATT&CK Framework for Ransomware
- Cybersecurity & Infrastructure Security Agency (CISA) Resources

### Analysis Tools
- **Malware Analysis**: IDA Pro, Ghidra, x64dbg
- **Network Analysis**: Wireshark, Zeek
- **Forensics**: Volatility, Autopsy, YARA

---

## Contributing

This is an educational project. Contributions should focus on:
- Improving documentation and educational value
- Adding defensive analysis capabilities
- Enhancing security research applications
- **NOT** improving attack capabilities

### Guidelines
- All contributions must maintain educational focus
- Include appropriate warnings and disclaimers
- Document security implications
- Follow responsible disclosure principles

---

## License and Liability

This software is provided for educational purposes only. By using this code, you acknowledge:

1. You will only use it for legitimate educational or research purposes
2. You will not use it for malicious activities
3. You understand the legal implications in your jurisdiction
4. The authors bear no responsibility for misuse or damages
5. You will comply with all applicable laws and regulations

**Remember: The goal is to understand ransomware to defend against it, not to become an attacker.**

---

## Contact and Support

This is a proof of concept for educational purposes. For questions about cybersecurity education or defensive strategies, consult:
- Your institution's cybersecurity department
- Professional cybersecurity training organizations
- Legitimate security research communities

**Do not use this code for illegal activities. Report ransomware incidents to appropriate authorities.**