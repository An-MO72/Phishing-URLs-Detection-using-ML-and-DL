from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests


class DETECTION:
    # listing shortening services
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"

    # 1.Domain of the URL (Domain)
    def getDomain(self, url):
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]  # Remove 'www.' if present
        return domain

    # 2.Checks for IP address in URL (Have_IP)
    def havingIP(self, url):
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        return 1 if re.search(ip_pattern, url) else 0

    # 3.Checks the presence of @ in URL (Have_At)
    def haveAtSign(self, url):
        if "@" in url:
            at = 1
        else:
            at = 0
        return at

    # 4.Finding the length of URL and categorizing (URL_Length)
    def getLength(self, url):
        if len(url) < 54:
            length = 0
        else:
            length = 1
        return length

    # 5.Gives number of '/' in URL (URL_Depth)
    def getDepth(self, url):
        path_segments = urlparse(url).path.split('/')
        depth = 0
        for segment in path_segments:
            if segment:
                depth += 1
        return depth

    # 6.Checking for redirection '//' in the url (Redirection)
    def redirection(self, url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

    # 7.Existence of “HTTPS” or "HTTP" Token in the Domain Part of the URL (https_Domain)
    def httpDomain(self, url):
        domain = urlparse(url).netloc
        if 'https' in domain or 'http' in domain:
            return 1
        else:
            return 0

    # 8. Checking for Shortening Services in URL (Tiny_URL)
    def tinyURL(self, url):
        match = re.search(self.shortening_services, url)
        if match:
            return 1
        else:
            return 0

    # 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
    def prefixSuffix(self, url):
        if '-' in urlparse(url).netloc or '_' in urlparse(url).netloc:
            return 1
        else:
            return 0

            # def get_ipython():

    #     pass
    # get_ipython().system('pip install python-whois')

    def web_traffic(self, url):
        try:
            # Fetch the webpage
            url = self.getDomain(url)
            response = requests.get(f'https://www.semrush.com/website/{url}/overview/')
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find the global rank element
            rank_element = soup.find('div', {'class': 'rank-card__SCWrap-sc-2sba91-6 guXRlv'})
            rank_text = rank_element.find('b', class_='rank-card__SCRank-sc-2sba91-8')

            rank_value = rank_text.text.strip()

            # Extract the rank number
            rank_value = int(rank_value.replace(',', ''))  # Remove commas and convert to int
            if rank_value < 100000:
                return 0
            else:
                return 1
        except Exception as e:
            return 1

    # 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
    def domainAge(self, domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, str) or isinstance(expiration_date, str):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None) or (creation_date is None):
            return 1
        elif (type(expiration_date) is list) or (type(creation_date) is list):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if (ageofdomain / 30) < 12:
                age = 1
            else:
                age = 0
        return age

    def domainEnd(self, domain_name):
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if expiration_date is None:
            return 1
        elif type(expiration_date) is list:
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if (end / 30) < 6:
                end = 1
            else:
                end = 0
        return end

    # 15. IFrame Redirection (iFrame)
    def iframe(self, response):
        if response == "":
            return 1
        else:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                return 0
            else:
                return 1

    # 16.Checks the effect of mouse over on status bar (Mouse_Over)
    def mouseOver(self, response):
        if response == "":
            return 1
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return 0

    # 17.Checks the status of the right click attribute (Right_Click)
    def rightClick(self, response):
        if response == "":
            return 1
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return 1
            else:
                return 0

    # 18.Checks the number of forwardings (Web_Forwards)
    def forwarding(self, response):
        if response == "":
            return 1
        else:
            if len(response.history) <= 2:
                return 0
            else:
                return 1

    # Function to extract features
    # There are 17 features extracted from the dataset
    def featureExtractions(self, url):
        global domain_name
        detection = DETECTION()
        features = [detection.havingIP(url), detection.haveAtSign(url),
                    detection.getLength(url), detection.getDepth(url), detection.redirection(url),
                    detection.httpDomain(url), detection.prefixSuffix(url), detection.tinyURL(url)]
        # Address bar based features (9)

        # Domain based features (4)
        dns = 0
        try:
            domain_name = whois.whois(urlparse(detection.getDomain(url)).netloc)
        except:
            dns = 1

        features.append(dns)
        features.append(detection.web_traffic(url))
        features.append(1 if dns == 1 else detection.domainAge(domain_name))
        features.append(1 if dns == 1 else detection.domainEnd(domain_name))

        # HTML & Javascript based features (4)
        try:
            response = requests.get(url)
        except:
            response = ""
        features.append(detection.iframe(response))
        features.append(detection.mouseOver(response))
        features.append(detection.rightClick(response))
        features.append(detection.forwarding(response))
        # features.append(label)

        return features
        # bob = featureExtractions('http://www.facebook.com/home/service')
        # print(bob)
