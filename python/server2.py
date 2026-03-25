import socket

server_socket = socket.socket() #by default it is socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 9999))  #IP: "0.0.0.0" → listen on all interfaces
server_socket.listen(1) #1 = backlog (max queued connections)

client_socket, client_address = server_socket.accept()
print(client_socket.recv(1024).decode())
client_socket.send(b"OK bro !") #TCP ONLY SENDS BYTES, strings must be encoded
client_socket.close()