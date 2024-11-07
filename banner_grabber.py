# The script is based on The Complete Python Hacking Course on O'Reilly platform,
# but rewritten in Python 3 and enhanced.

# This program grabs a banner for a specific IP/URL and port.

import socket

def return_banner(ip,port):
    try:
        # Set the timeout to 2 sec.
        socket.setdefaulttimeout(2)
        # Create a socket object.
        s = socket.socket()
        # Connect to the IP and the port.
        s.connect((ip,int(port)))
        # Specify what a banner is - the 1024 bytes returnwd after the connection is established.
        banner = s.recv(1024).decode()
        return banner
    except:
        return None

def main():
    ip = input("\nWrite the IP address or URL of the host: ") # 192.168.172.135
    port = input("Write the port number: ")
    # Take the outcome of the "return_banner" function as the banner.
    banner = return_banner(ip,port)

    if banner:
        print(f"\n{ip}: {banner}\n" )
    else:
        print(f"\n[!] No response from {ip}.")

main()