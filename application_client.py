import binascii
import socket
import ssl


HOST = '10.157.9.133'
PORT = 4433
while True:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(1);
    print("Starting Connection")
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
    print("Sending")
    secure_sock.write(b'a2bc886')
    print("Receiving")

    data = secure_sock.read(32)
    f = open("file.dat", "rb")
    stored_hash = f.readline()
    f.close()

    if stored_hash == data:
        print("comparison successful")
    else:
        print("comparison Failed")
    print(stored_hash)
    print(data)
    print("Closing Connection")
    secure_sock.close()
    sock.close()
