import socket 
import struct 
import time 
def main():
     # 创建UDP 
    socket sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    # 绑定到本地50002端口 
    sock.bind(('0.0.0.0', 50002)) 
    try: 
        while True: 
            data, addr = sock.recvfrom(1024) 
            # 接收数据和发送者地址 
            if len(data) >= 4: 
                # 确保数据包长度足够 
                opcode = struct.unpack('!I', data[:4])[0] 
                # 假设opcode是前4个字节，大端格式 
                if opcode == 3: 
                    print(f"Received packet with opcode 3 at {time.strftime('%Y-%m-%d %H:%M:%S')}") 
    finally: sock.close() 

if __name__ == "__main__": main()