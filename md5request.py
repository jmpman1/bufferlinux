#!/usr/bin/env python3

import requests, hashlib
from bs4 import BeautifulSoup

url = ''
s = requests.Session()

html = requests.get(url).content
soup = BeautifulSoup(html, 'html.parser')
sitehash = soup.find("h3").string

md5 = hashlib.md5(sitehash.encode('utf8')).hexdigest()

response = requests.post(url, data={"data":md5})

print(BeautifulSoup(response.content, 'html.parser').prettify())