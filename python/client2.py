import socket

client_socket = socket.socket() #by default it is socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 9999))

client_socket.send(b"Hi bro !") #No protocol → just raw data , Server decides how to interpret it
print(client_socket.recv(1024).decode()) 
client_socket.close()