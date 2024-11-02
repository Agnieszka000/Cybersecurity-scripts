# Find all subdomains for the domain in question using the site: crt.sh.

import requests
from bs4 import BeautifulSoup
import openpyxl

domain = input("Enter the domain name you want to check: ")
print("Hold on, I'm working...")

website = 'https://crt.sh/?q='
r = requests.get(website + domain)
soup = BeautifulSoup(r.text, "html.parser")

# Find all <TD> tags:
all_td = soup.find_all('td') 

# Create a set of unique subdomains:
seen = set()  
for td in all_td:
    content = td.text.strip()
    for line in content.splitlines():
        domain_name = line.strip()
        # Check if an item in the set ends with the domain name:
        if domain_name.endswith(domain):
            seen.add(domain_name)

# Create a new workbook and select the active worksheet:
workbook = openpyxl.Workbook()
worksheet = workbook.active

# Write the set items to the worksheet:
for index, item in enumerate(seen, start=1):
    worksheet.cell(row=index, column=1, value=item)
    
# Save the workbook to a file
workbook.save("subdomains.xlsx")
