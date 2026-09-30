import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 5000))
s.sendall(b"TEST_BLOCK_DATA")
print(s.recv(1024))
s.close()
