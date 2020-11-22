import socket
import ssl
import pprint
if __name__ == '__main__':

    HOST = '127.0.0.1'
    PORT = 1234

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    print("Hi")
    server_socket.listen(10)
    print("Hi")
    client, fromaddr = server_socket.accept()
    print("Hi")
    secure_sock = ssl.wrap_socket(client, server_side=True, ca_certs = "client.pem", certfile="server.pem", keyfile="server.key", cert_reqs=ssl.CERT_REQUIRED,
                           ssl_version=ssl.PROTOCOL_TLSv1_2)

    secure_sock.getpeername()
    secure_sock.cipher()
    secure_sock.getpeercert()
    cert = secure_sock.getpeercert()
   # print(cert)

    # verify client
   # if not cert or ('commonName', 'test') not in cert['subject'][3]: raise Exception("ERROR")
    secure_sock.send(b'Helllo')
    d = secure_sock.read(1024)
    print(d)
    #try:
    #    data = secure_sock.read(1024)
    #    secure_sock.write(data)
    #finally:
    secure_sock.close()
    server_socket.close()