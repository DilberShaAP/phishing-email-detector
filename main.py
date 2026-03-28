
import re
import tldextract
from colorama import Fore,Style,init
init(autoreset=True)
print(Fore.BLUE + """
========================================
  SOC PHISHING ANALYZER v1.0
  CREATED BY: Dilber Sha
========================================
""")
print(Fore.CYAN + "=== Phishing Email Detection Tool (SOC) ===\n")
print("Paste your email:")
lines=[]
while True:
   line=input()
   if line=="":
       break
   lines.append(line)
email_text="\n".join(lines)
urls=re.findall(r'(https?://\S+)',email_text)
suspicious_keywords=[
   "urgent","verify your account","click here",
   "login now","password reset","bank","security alert"
]
found_keywords=[]
for word in suspicious_keywords:
   if word.lower() in email_text.lower():
       found_keywords.append(word)
suspicious_domains=["bit.ly","tinyurl.com"]
bad_domains=[]
for url in urls:
   domain=tldextract.extract(url).registered_domain
   if domain in suspicious_domains:
       bad_domains.append(domain)
ip_links=[]
for url in urls:
   if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+',url):
       ip_links.append(url)
score=0
score+=len(found_keywords)
score+=len(bad_domains)*2
score+=len(ip_links)*2
if score==0:
   risk="Low"
   color=Fore.GREEN
elif score<=3:
   risk="Medium"
   color=Fore.YELLOW
else:
   risk="High"
   color=Fore.RED
print(Fore.CYAN+"\n=== Analysis Result ===")
print(Fore.WHITE+"URLs found:",urls)
print(Fore.YELLOW+"Suspicious keywords:",found_keywords)
print(Fore.MAGENTA+"Suspicious domains:",bad_domains)
print(Fore.RED+"IP-based URLs:",ip_links)
print(color+"\nRisk Level:",risk)
