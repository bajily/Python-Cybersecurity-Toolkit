import dns.resolver

try:
    answers = dns.resolver.resolve(input("Enter the full Domain (with subdomain): "), "A")

    for answer in answers:
        print(answer)
except Exception:
    print("Not Found")
