import re
import tldextract
import tkinter as tk
from tkinter import scrolledtext
def analyze_email():
   email_text=input_box.get("1.0",tk.END)
   urls=re.findall(r'(https?://\S+)',email_text)
   suspicious_keywords=["urgent","verify your account","click here","login now","password reset","bank","security alert"]
   found_keywords=[w for w in suspicious_keywords if w in email_text.lower()]
   suspicious_domains=["bit.ly","tinyurl.com"]
   bad_domains=[]
   for url in urls:
       domain=tldextract.extract(url).registered_domain
       if domain in suspicious_domains:
           bad_domains.append(domain)
   ip_links=[url for url in urls if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+',url)]
   score=len(found_keywords)+len(bad_domains)*2+len(ip_links)*2
   if score==0:
       risk="LOW"
   elif score<=3:
       risk="MEDIUM"
   else:
       risk="HIGH"
   result=f"""
=== ANALYSIS RESULT ===
URLs:{urls}
Keywords:{found_keywords}
Suspicious Domains:{bad_domains}
IP URLs:{ip_links}
RISK LEVEL:{risk}
"""
   output_box.delete("1.0",tk.END)
   output_box.insert(tk.END,result)
app=tk.Tk()
app.title("SOC Phishing Analyzer")
app.geometry("600x500")
# Input
input_box=scrolledtext.ScrolledText(app,height=10)
input_box.pack(pady=10)
analyze_btn=tk.Button(app,text="Analyze Email",command=analyze_email)
analyze_btn.pack(pady=5)
output_box=scrolledtext.ScrolledText(app,height=15)
output_box.pack(pady=10)
app.mainloop()