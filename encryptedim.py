import argparse
import select
import socket
import sys
from math import ceil as ceil
from Crypto.Cipher import AES as AES
from Crypto.Hash import HMAC as HMAC
from Crypto.Hash import SHA256 as SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes as randb

# In order for your program to communicate correctly with the autograder, we need to standardize the sending protocol so it works with the autograder. You should begin each communication should have the following form:
# iv + E_k1(len(m))+HMAC_k2(iv + E_k1(len(m))) + E_k1(m)+HMAC_k2(E_k1(m))
# This means you'll begin by sending the IV in the clear, followed by the length of the message (encrypted-the-MACd), then ﬁnally the message (encrypted-then-MACd). You need to send the length of the message ﬁrst so that you can handle an arbitrary-length message.
# As an example, you may run “python3 encryptedIM.py --s --confkey 'FOOBAR' --authkey 'CS114ISAWESOME'” in one terminal window, and then start “python3 encryptedim.py --c 127.0.0.1 --confkey ’FOOBAR’ --authkey 'CS114ISAWESOME'” in another terminal window.
# Note that the instance with the --s option must be started before the other instance.

# Should use CBC mode https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode

def start_server():
    # Create a socket using IPv4 (AF_INET) and TCP (SOCK_STREAM) for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set the socket address to be reusable
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to a tuple of hostname and port - localhost (127.0.0.1), port 9999
    server_socket.bind(('localhost', 9999))
    # Set socket to start listening, allowing at most 1 queued connection
    server_socket.listen(1)
    # Comment out print statements for gradescope
    # print('Server started on localhost (127.0.0.1)')
    # print('Waiting for a connection...')

    # Wait for a connection, and return the client socket and address once a connection is made
    client_socket, client_address = server_socket.accept()
    # print(f'Client connected: {client_address}')
    return client_socket

def start_client(hostname):
    # Create an IPv4 TCP socket for the client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set the socket address to be reusable
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Connect socket to an existing hostname on port 9999, else fail and stop program.
    try:
        client_socket.connect((hostname, 9999))
        # Comment out print statements for gradescope
        # print(f'Connected to server: {hostname}')
    except socket.error as err:
        # Comment out print statements for gradescope
        # print(f"Failed to connect: {err}")
        client_socket.close()
        sys.exit(0)
    return client_socket

    # Encryption example
    # data = b"secret"
    # key = get_random_bytes(16)
    # cipher = AES.new(key, AES.MODE_CBC)
    # ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    # iv = b64encode(cipher.iv).decode('utf-8')
    # ct = b64encode(ct_bytes).decode('utf-8')
    # result = json.dumps({'iv':iv, 'ciphertext':ct})
    # print(result)
    # '{"iv": "bWRHdzkzVDFJbWNBY0EwSmQ1UXFuQT09", "ciphertext": "VDdxQVo3TFFCbXIzcGpYa1lJbFFZQT09"}'

def encode_message(message, K1,K2):
    # iv + E_k1(len(m)) + HMAC_k2(iv + E_k1(len(m))) + E_k1(m) + HMAC_k2(E_k1(m))

    IV = randb(16)

    # Create a 256-bit key for AES encryption/decryption by using the SHA256 hash of the K1 key.
    K1_256 = SHA256.new(K1.encode()).digest()
    # The encode() method turns the string into bytes, needed for the SHA256.new() method.
    # The digest() method returns the final 256 bit hash in binary.

    # Create an HMAC instance by using the SHA256 hash of the K2 key.
    K2_HMAC = HMAC.new(K2.encode(), digestmod=SHA256)
    # Repeat for the message
    K2_HMAC_message = HMAC.new(K2.encode(), digestmod=SHA256)

    # Create an AES instance for encryption/decryption by using the SHA256 hash of the K1 key.
    K1_cipher = AES.new(key=K1_256, mode=AES.MODE_CBC, iv=IV)

    # Create a binary object which is the encryption of the length of the message (padded)
    K1_length = K1_cipher.encrypt(pad(len(message).to_bytes(15,'little'), AES.block_size))
    # Create a binary object which is the encryption of the message (padded)
    K1_message = K1_cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    HMAC_IV_length = K2_HMAC.update(IV + K1_length).digest()
    HMAC_message = K2_HMAC_message.update(K1_message).digest()
    enc_message = IV + K1_length + HMAC_IV_length + K1_message + HMAC_message

    # print("\nmessagelength")
    # print(len(message).to_bytes(32))

    # print("\nIV")
    # print(IV)

    # print("\nK1_length")
    # print(K1_length)

    # print("\nHMAC_IV_length")
    # print(HMAC_IV_length)

    # print("\nK1_message")
    # print(K1_message)

    # print("\nHMAC_message")
    # print(HMAC_message)

    # print("\nFull message")
    # print(enc_message)
    return enc_message

def decode_message(enc_message, K1, K2, sock):
    # Extract the IV
    IV = enc_message[:16]

    # Extract K1_length
    K1_length = enc_message[16:32]  # K1_length is 16 bytes (128 bits)

    # Extract the HMAC of IV + K1_length
    K2_HMAC_IV_K1_length = enc_message[32:64]  # The HMAC used SHA256 so it is 32 bytes (256 bits)

    # Create a 256-bit key for HMAC computation by using the SHA256 hash of the K2 key.
    K2_HMAC = HMAC.new(K2.encode(), digestmod=SHA256)
    HMAC_IV_length = K2_HMAC.update(IV + K1_length).digest()

    # Validate that IV and length are unchanged
    if K2_HMAC.digest() != K2_HMAC_IV_K1_length:
        print("ERROR: HMAC verification failed")
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        sys.exit(0)

    K1_256 = SHA256.new(K1.encode()).digest()
    K1_cipher = AES.new(key=K1_256, mode=AES.MODE_CBC, iv=IV)

    try:
        length = int.from_bytes(unpad(K1_cipher.decrypt(K1_length), AES.block_size),'little')
    except Exception:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        sys.exit(0)

    enc_length = ceil(length/AES.block_size)*AES.block_size

    K1_message = enc_message[64:64+enc_length]
    HMAC_message = enc_message[64+enc_length:96+enc_length]

    K2_HMAC_message_inst = HMAC.new(K2.encode(), digestmod=SHA256)
    K2_HMAC_message = K2_HMAC_message_inst.update(K1_message).digest()

    if K2_HMAC_message != HMAC_message:
        print("ERROR: HMAC verification failed")
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        sys.exit(0)

    message = unpad(K1_cipher.decrypt(K1_message), AES.block_size).decode('utf-8')

    # print("IV:")
    # print(IV)

    # print("\nK1_length")
    # print(K1_length)
    
    # print("\nHMAC_IV_length:")
    # print(HMAC_IV_length)
    
    # print("\nK2_HMAC_IV_K1_length")
    # print(K2_HMAC_IV_K1_length)
    
    # print("\nlength")
    # print(length)
    
    # print(K1_message)
    # print(HMAC_message)

    # print("\nHMAC_message:")
    # print(K2_HMAC_message)
    return message

def main():
    # Create argument parser to handle command line options
    parser = argparse.ArgumentParser(description='Start server or client for P2P IM.')
    # Set it so that only one of server or client options can be selected
    group = parser.add_mutually_exclusive_group(required=True)
    # If server, set arg.s to True
    group.add_argument('--s', action='store_true', help='Start as server')
    # If client, set arg.c to the provided hostname argument
    group.add_argument('--c', metavar='hostname', type=str, help='Start as client and connect to hostname')
    # Add arguments for the confidentiality and authenticity keys
    parser.add_argument('--confkey', metavar='K1', type=str, help='Confidentiality key for encryption/decryption',required=True)   
    parser.add_argument('--authkey', metavar='K2', type=str, help='Authenticity key for HMAC computation', required=True)    
    # Parse inputs from the command line when the script was called
    args = parser.parse_args()

    if args.s:
        # Start the server
        sock = start_server()
    else:
        # Start the client and connect to the hostname provided as an argument
        sock = start_client(args.c)
    
    K1 = args.confkey
    K2 = args.authkey
    
    try:
        # Loop communication until the connection is closed
        while True:
            # Wait until either the stdin or the socket have a message - both are in the incoming data list and so select waits until either is populated.
            readable, _, _ = select.select([sys.stdin, sock], [], [])
            # Iterate over each readable source to manage if both stdin and the socket have new messages at the same time.
            for source in readable:
                if source == sock:
                    # Read message from socket
                    enc_message = sock.recv(4096)
                    # If message is empty it means the connection is closed, so close socket and exit the console
                    # print(enc_message)
                    if not enc_message:
                        print('Connection closed')
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                        sys.exit(0)

                    message = decode_message(enc_message, K1, K2, sock)


                    # Otherwise decode the message from bytes to a string and print to console WITHOUT adding a new line \n character
                    print(message, end='')
                    # Flush the output to prevent issues with gradescope
                    sys.stdout.flush()

                    # Decryption Example
                    # We assume that the key was securely shared beforehand
                    # try:
                    #     b64 = json.loads(json_input)
                    #     iv = b64decode(b64['iv'])
                    #     ct = b64decode(b64['ciphertext'])
                    #     cipher = AES.new(key, AES.MODE_CBC, iv)
                    #     pt = unpad(cipher.decrypt(ct), AES.block_size)
                    #     print("The message was: ", pt)
                    # except (ValueError, KeyError):
                    #     print("Incorrect decryption")
                else:
                    # Read message from stdin
                    message = sys.stdin.readline()
                    # Encrypt message
                    enc_message = encode_message(message = message, K1=K1, K2=K2)
                    # Encode the message to bytes and send it to the socket
                    sock.sendall(enc_message)

    except KeyboardInterrupt:
        # Console will show ^C
        print(' received - closing connection')
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        sys.exit(0)
        
if __name__ == "__main__":
    main()