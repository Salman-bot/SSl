import binascii
import socket
import ssl
from time import sleep


HOST = '10.157.9.133'
PORT = 4433
counter = 1
while True:
    with open("file2048.dat", "rb") as f:
        while (stored_hash :=f.read(32)) :
            if not stored_hash:
                f.close()
                print("Error")
            else :
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(1);
                #print("Starting Connection")
                sock.connect((HOST, PORT))
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.load_cert_chain(certfile="client.pem", keyfile="client.key")
                if ssl.HAS_SNI:
                    secure_sock = context.wrap_socket(sock, server_side=False, server_hostname=HOST)
                else:
                    secure_sock = context.wrap_socket(sock, server_side=False)
                cert = secure_sock.getpeercert()
                #print("Sending")
                secure_sock.write(b'a2bc886')
                #print("Receiving")
                data = secure_sock.read(32)
                print("[+] Receiving hash of block (",counter,"/ 512)")
                counter = counter + 1
                if stored_hash == bytes(data):
                    print("[+] Comparison successful")
                else:
                    print("[+] Comparison Failed! possible attack!")
                #print(stored_hash)
                #print(bytes(data))
                #print("Closing Connection")
            secure_sock.close()
            sock.close()
