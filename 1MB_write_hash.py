import binascii
import socket
import ssl

HOST = '10.157.9.133'
PORT = 4433

while True:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(1);
    sock.connect((HOST, PORT))

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile="client.pem", keyfile="client.key")

    if ssl.HAS_SNI:
        secure_sock = context.wrap_socket(sock, server_side=False, server_hostname=HOST)
    else:
        secure_sock = context.wrap_socket(sock, server_side=False)

    cert = secure_sock.getpeercert()
    # print(cert)

    # verify server
    #  if not cert or ('commonName', 'test') not in cert['subject'][3]: raise Exception("ERROR")
    secure_sock.write(b'a2bc886')
    f = open("file16384.dat", "ab+")
    data = secure_sock.read(32)
    print(len(data))
    f.write(bytes(data))
    print(bytes(data))
    secure_sock.close()
    sock.close()
