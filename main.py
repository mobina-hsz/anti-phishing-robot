import urllib.parse
url = "https://golestan.iust.ac.ir/forms/authenticateuser/main.htm"
p = urllib.parse.urlsplit(url)
print(p)