import requests

url = input("Enter the full URL: ")

try:
    response = requests.get(url, timeout=5)

    print(response.status_code)
except requests.RequestException:
    print("Offline")
