import socket

HOST = '127.0.0.1'
PORT = 8000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))

print('Listening...')
s.listen(1)

conn, addr = s.accept()
print 'Connection from ', addr
conn.close()
