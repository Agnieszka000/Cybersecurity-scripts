# Inspired by "The Complete Python Hacking Course" on the O'Reilly platform,
# but re-scpited in Python 3 and restituted the deprecated module optparse with argparse.
#!/usr/bin/python

from socket import *
import argparse
from threading import Thread


def connection_scan(tgt_host, tgt_port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((tgt_host, tgt_port))  # Corrected to tuple (host, port)
        print(f"{tgt_port}/tcp is open.")
    except:
        print(f"{tgt_port}/tcp is closed.")
    finally:
        sock.close()


def port_scan(tgt_host, tgt_ports):
    try:
        tgt_IP = gethostbyname(tgt_host)
    except:
        print(f"[-] {tgt_host} - invalid host!")
        return

    try:
        tgt_name = gethostbyaddr(tgt_IP)
        print(f"Scan results for {tgt_name[0]}: ")
    except:
        print(f"Scan results for {tgt_IP}: ")

    setdefaulttimeout(1)

    threads = []
    for tgt_port in tgt_ports:
        t = Thread(target=connection_scan, args=(tgt_host, int(tgt_port)))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()  # Wait for all threads to complete


def main():
    parser = argparse.ArgumentParser(
        usage="Usage of program: -H <target host IP address or URL> -p <target port(s)>")
    parser.add_argument("-H", "--host", dest="tgt_host", type=str, help="Specify target host.")
    # -p argumet should expect a str so that we can scan multiple ports, in case I spedify it as int, it'll be expecring only one int value
    # The ports mus be added as string, and then split by commas to get a list of ports.
    parser.add_argument("-p", "--port", dest="tgt_port", type=str, help="Specify target ports separated by comma.")
    parameters = parser.parse_args()

    tgt_host = parameters.tgt_host
    if not tgt_host:
        print(parser.usage)
        exit(0)

    if not parameters.tgt_port:
        print("[-] Please specify at least one port to scan.")
        exit(0)

    tgt_ports = parameters.tgt_port.split(",")
    port_scan(tgt_host, tgt_ports)


if __name__ == "__main__":
    main()
