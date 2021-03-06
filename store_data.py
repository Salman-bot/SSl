import binascii
import socket
import ssl

if __name__ == '__main__':

    HOST = '10.157.9.133'
    PORT = 4433

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
    secure_sock.write(b'hello')
    print("Writing hash to storage")

    data = secure_sock.read(32)

    f = open("file.dat", "w")
    f.write('')
    f.close()
    f = open("file.dat", "wb")
    f.write(data)
    print (data)
    f.close()
    secure_sock.close()
    sock.close()
