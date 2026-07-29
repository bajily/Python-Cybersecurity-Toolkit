import socket

domain = input("Enter the domain: ")

subdomains = [
    "www",
    "mail",
    "api",
    "vpn",
    "dev",
    "admin"
]

for sub in subdomains:
    host = f"{sub}.{domain}"

    try:
        ip = socket.gethostbyname(host)
        print(f"[+] {host} -> {ip}")
    except socket.gaierror:
        pass
