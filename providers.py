import json
import re

import requests

from colors import Colors


# from builtins import function
# from builtins import function


class Providers:

    def __init__(self, apis, ports_passive, max_response):
        self.apis = apis
        self.max_response = max_response
        self.ports_passive = ports_passive

    # noinspection PyMethodMayBeStatic
    def run_alien_vault(self, domain: str, f):
        print("{0}\n[!] Searching in{1} AlienVault :".format(Colors.B, Colors.W))
        r = requests.get("https://otx.alienvault.com/api/v1/indicators/domain/{0}/passive_dns".format(domain))
        d = json.loads(r.text)
        for i in range(len(d["passive_dns"])):
            if domain in d["passive_dns"][i]["hostname"]:
                f(d["passive_dns"][i]["hostname"])

    # noinspection PyMethodMayBeStatic
    def run_site_dossier(self, domain: str, f):
        print("{0}\n[!] Searching in{1} Sitedossier :".format(Colors.B, Colors.W))
        data = ""
        page = 1
        while "No data currently available." not in data:
            r = requests.get("http://www.sitedossier.com/parentdomain/{0}/{1}".format(domain, str(page)))
            if "your IP has been blacklisted" in r.text:
                print("{0}[-] Your IP has been blacklisted".format(Colors.R))
                return
            page = page + 100
            data = r.text
            split = domain.split('.')
            pattern = '(?!2?F)[a-zA-Z0-9\\-\\.]*\\.{0}\\.{1}'.format(str(split[0]), str(split[1]))
            for domain in re.findall(pattern, r.text):
                f(domain)

    # noinspection PyMethodMayBeStatic
    def run_binary_edge(self, domain: str, f):
        print("{0}\n[!] Searching in{1} BinaryEdge :".format(Colors.B, Colors.W))
        header = {"X-Key": self.apis["BINARYEDGE"]}
        r = requests.get("https://api.binaryedge.io/v2/user/subscription", headers=header)
        d = json.loads(r.text)
        msg = "{0}[!] {1}{2}{3} requests available of {4}{5}{6} (per month)\n"
        print(
            msg.format(Colors.G, Colors.W, str(d["requests_left"]), Colors.G, Colors.W, str(d["requests_plan"]),
                       Colors.G))
        if d["requests_left"] == 0:
            print("{0}[-] No API requests left this month{1}".format(Colors.R, Colors.B))
            return
        flag = True
        page = 1
        while flag:
            url = "https://api.binaryedge.io/v2/query/domains/subdomain/{0}?page={1}"
            r = requests.get(url.format(domain, str(page)), headers=header)
            d = json.loads(r.text)
            if len(r.text) > self.max_response:
                print(
                    "{0}[-] HTTP response to high to grep. Length is {1}{2}{3} and max_response is {4}{5}{6}. Add --max-response-size [NUMBER] to increase maximum response size".format(
                        Colors.W, Colors.R, str(len(r.text)), Colors.W, Colors.R, str(self.max_response), Colors.W))
            else:
                for subdomain in d["events"]:
                    f(subdomain)
            if page * 100 > d["total"]:
                flag = False
            page = page + 1

    # noinspection PyMethodMayBeStatic
    def run_shodan(self, domain: str, f):
        print("{0}\n[!] Searching in{1} Shodan :".format(Colors.B, Colors.W))
        apis_shodan: str = self.apis["SHODAN"]
        r = requests.get('https://api.shodan.io/dns/domain/{0}?key={1}'.format(domain, apis_shodan))
        d = json.loads(r.text)
        for i in range(len(d["data"])):
            subd = str(d["data"][i]["subdomain"])
            if subd != '' and '*' not in subd:
                if "ports" in d["data"][i].keys():
                    self.ports_passive["{0}.{1}".format(subd, domain)] = d["data"][i]["ports"]
                f("{0}.{1}".format(subd, domain))

    # noinspection PyMethodMayBeStatic
    def run_cert_spotter(self, domain: str, f):
        print(
            "{0}\n[!] Searching in{1} CertSpotter:\n{2}[!] Free 100/queries per hour".format(Colors.B, Colors.W,
                                                                                             Colors.G))
        header = {}
        if self.apis:
            for apiengines in self.apis.keys():
                if apiengines == "CERTSPOTTER":
                    print(Colors.G + "[+] CertSpotter API Key found\n")
                    apis_certspotter = str(self.apis["CERTSPOTTER"])
                    header = dict(Authorization="Bearer {0}".format(apis_certspotter))
        r = requests.get(
            "https://api.certspotter.com/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert".format(
                domain), headers=header)
        if "You have exceeded the domain" in r.text:
            print("{0}\n[-] Rate exceeded. Wait some minutes".format(Colors.R))
            return
        if len(r.text) > self.max_response:
            print(
                "{0}[-] HTTP response to high to grep. Length is {1}{2}{3} and max_response is {4}{5}{6}. Add --max-response-size [NUMBER] to increase maximum response size".format(
                    Colors.W, Colors.R, str(len(r.text)), Colors.W, Colors.R, str(self.max_response), Colors.W))
        else:
            pattern = '(?!2?F)[a-zA-Z0-9\\-\\.]*\\.{0}\\.{1}'.format(str(domain.split('.')[0]),
                                                                     str(domain.split('.')[1]))
            for domain in re.findall(pattern, r.text):
                f(domain)

    # noinspection PyMethodMayBeStatic
    def run_spyse(self, domain: str, f):
        print("{0}\n[!] Searching in{1} Spyse :".format(Colors.B, Colors.W))
        apis_spyse = str(self.apis["SPYSE"])
        header = dict(Authorization="Bearer {0}".format(apis_spyse), Accept="application/json")
        r = requests.get("https://api.spyse.com/v4/data/account/quota", headers=header)
        d = json.loads(r.text)
        req_remaining = d["data"]["items"][0]["api_requests_remaining"]
        limit = d["data"]["items"][0]["api_requests_limit"]
        print("{0}[!] {1}{2}{3} requests available of {4} (per month)".format(Colors.G, Colors.W, str(req_remaining),
                                                                              Colors.G, str(limit)))
        if req_remaining == 0:
            print("{0}[-] No API requests left this month".format(Colors.R))
            return
        data = "{\"search_params\":[{\"name\":{\"operator\":\"ends\",\"value\":\".{0}\"}}],\"limit\":100}".format(
            domain)
        r = requests.post("https://api.spyse.com/v4/data/domain/search", headers=header, data=data)
        if len(r.text) > self.max_response:
            print(
                "{0}[-] HTTP response to high to grep. Length is {1}{2}{3} and max_response is {4}{5}{6}. Add --max-response-size [NUMBER] to increase maximum response size".format(
                    Colors.W, Colors.R, str(len(r.text)), Colors.W, Colors.R, str(self.max_response), Colors.W))
        else:
            pattern = '(?!2?F)[a-zA-Z0-9\\-\\.]*\\.{0}\\.{1}'.format(str(domain.split('.')[0]),
                                                                     str(domain.split('.')[1]))
            for domain in re.findall(pattern, r.text):
                f(domain)

    # noinspection PyMethodMayBeStatic
    def run_security_trails(self, domain: str, f):
        print("{0}\n[!] Searching in{1} SecurityTrails :".format(Colors.B, Colors.W))
        apis_securitytrails = str(self.apis["SECURITYTRAILS"])
        r = requests.get(
            "https://api.securitytrails.com/v1/domain/{0}/subdomains?apikey={1}".format(domain, apis_securitytrails))
        if r.status_code == 429:
            print("{0}\n[-] API Limit exceeded. Free API only have 50 requests/month".format(Colors.R))
            return
        if "subdomains" not in r.text:
            print(
                "{0}\n[-] Error with API. Free API only have 50 requests/month. Response: {1}".format(Colors.R, r.text))
            return
        d = json.loads(r.text)
        for subdomain in d["subdomains"]:
            f("{0}.{1}".format(str(subdomain), domain))

    # noinspection PyMethodMayBeStatic
    def run_crt(self, domain: str, f):
        print("{0}\n[!] Searching in{1} Crt.sh :".format(Colors.B, Colors.W))
        print("{0}[+] Downloading data".format(Colors.G))
        r = requests.get("https://crt.sh/?q={0}&output=json".format(domain))
        print(
            "{0}[+] Downloaded data for {1}{2} ({3}MB)".format(Colors.G, Colors.W, domain, str(len(r.text) / 1000000)))
        if len(r.text) > self.max_response:
            print(
                "{0}[-] HTTP response to high to grep. Length is {1}{2}{3} and max_response is {4}{5}{6}. Add --max-response-size [NUMBER] to increase maximum response size".format(
                    Colors.W, Colors.R, str(
                        len(r.text)), Colors.W, Colors.R, str(
                        self.max_response), Colors.W))
        else:
            pattern = '\"[a-zA-Z0-9\\-\\.]*\\.{0}\\.{1}'.format(str(domain.split('.')[0]), str(domain.split('.')[1]))
            for domain in re.findall(pattern, r.text):
                f(domain.split("\"")[1])  # we send to check domain to verify it still exists

    # noinspection PyMethodMayBeStatic
    def run_web_archive(self, domain: str, f):
        print(
            "{0}\n[!] Searching in{1} Web Archive: {2}this web page can take longer to load".format(Colors.B, Colors.W,
                                                                                                    Colors.B))
        print("{0}[+] Downloading data".format(Colors.G))
        # noinspection PyBroadException
        try:
            r = requests.get(
                "https://web.archive.org/cdx/search/cdx?url=*.{0}&output=txt&fl=original&collapse=urlkey&page=".format(
                    domain), timeout=10)
        except:
            print("Timeout exceeded. Exiting")
            return
        print(
            "{0}[+] Downloaded data for {1}{2} ({3}MB)".format(Colors.G, Colors.W, domain, str(len(r.text) / 1000000)))
        len_res = len(r.text)
        if len_res > self.max_response:
            print(
                "{0}[-] HTTP response to high to grep. Length is {1}{2}{3} and max_response is {4}{5}{6}. Add --max-response-size [NUMBER] to increase maximum response size".format(
                    Colors.W, Colors.R, str(len(r.text)), Colors.W, Colors.R, str(self.max_response), Colors.W))
        else:
            pattern = '(?!2?F)[a-zA-Z0-9\\-\\.]*\\.{0}\\.{1}'.format(str(domain.split('.')[0]),
                                                                     str(domain.split('.')[1]))
            if len_res > 5000000:
                print("{0}[+] Greping file. This can take a while\n".format(Colors.G))
            for domain in re.findall(pattern, r.text):
                f(domain)

    # noinspection PyMethodMayBeStatic
    def run_passive_total(self, domain: str, f):
        print("{0}\n[!] Searching in{1} PassiveTotal :".format(Colors.B, Colors.W))
        auth = (self.apis["PASSIVETOTAL_USERNAME"], self.apis["PASSIVETOTAL"])
        r = requests.get("https://api.riskiq.net/pt/v2/account/quota", auth=auth)
        d = json.loads(r.text)
        req = d["user"]["licenseCounts"]["searchApi"]
        limit = d["user"]["licenseLimits"]["searchApi"]
        print("{0}[!] {1}{2}{3} requests available of {4} (per month)\n".format(Colors.G, Colors.W, str(limit - req),
                                                                                Colors.G, str(limit)))
        if req == limit:
            print("{0}[-] No API requests left this month".format(Colors.R))
            return
        r = requests.get("https://api.passivetotal.org/v2/enrichment/subdomains?query={0}".format(domain), auth=auth)
        d = json.loads(r.text)
        for subdomain in d["subdomains"]:
            f(subdomain + "." + domain)
