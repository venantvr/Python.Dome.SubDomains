#!/usr/bin/env python3


# Created by Vadi (github.com/v4d1)
# Contact me at vadi@securihub.com


from __future__ import print_function  # Python2 compatibility for prints

import argparse
import json
import os
import random
import re
import socket
import string
import sys
import time
import uuid
# from builtins import function
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from datetime import datetime
from itertools import product

import pyfiglet as pyfiglet
import requests
from dns import resolver

from colors import Colors
from ports import topWebports, top100ports, top1000ports
from providers import Providers
from tools import parser_error, output

subdomains_found = {}
subdomains_found_ports = {}
subdomains_found_list = []
wildcardsDicc = {}
wildcard = False
mode = "passive"
apis = {}
portsPassive = {}
noExists = []
count = 0
countToChange = 0
# isWebArchive = False
res = resolver.Resolver()

resolvers = ['1.1.1.1', '9.9.9.9', '8.8.8.8', '1.0.0.1', '208.67.222.222', '8.8.4.4', '149.112.112.11']


def change_dns():
    # Not used right now
    global resolvers
    global res
    resolvers.append(resolvers.pop(0))
    # First resolver is now the last
    res.nameservers = [resolvers[0]]


def banner():
    # print(pyfiglet.figlet_format("Dome"))
    print(pyfiglet.figlet_format("Dome", font="doh", width=200))
    print("Version 1.1")


def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[
        0] + " -m active -d hackerone.com -w subdomains-5000.txt -p 80,443,8080 -o")
    # noinspection PyProtectedMember
    parser._optionals.title = "OPTIONS"
    parser.error = parser_error
    parser.add_argument('-m', '--mode', help="Scan mode. Active or passive", required=True)
    parser.add_argument('-d', '--domain', help="Domains name to enumerate subdomains (Separated by commas)",
                        required=True)
    parser.add_argument('-w', '--wordlist', help='Wordlist containing subdomain prefix to bruteforce')
    parser.add_argument('-p', '--ports', help='Scan the subdomains found against specified tcp ports.')
    parser.add_argument('-i', '--ip', help='When a subdomain is found, show the ip too', action='store_true')
    parser.add_argument('-nb', '--no-bruteforce', help='Dont make pure bruteforce up to 3 letters', action='store_true')
    parser.add_argument('--top-100-ports', help='Scan the top 100 ports of the subdomain.', action='store_true')
    parser.add_argument('--top-1000-ports', help='Scan the top 1000 ports of the subdomain.', action='store_true')
    parser.add_argument('--top-web-ports', help='Scan the top web ports of the subdomain.', action='store_true')
    parser.add_argument('-s', '--silent', help='Silent mode. No output in terminal', action='store_false')
    parser.add_argument('--no-color', help='Dont print colored output', action='store_true')
    parser.add_argument('-t', '--threads', help='Number of threads to use', type=int, default=25)
    parser.add_argument('-o', '--output', help='Save the results to txt, json and html files', action='store_true')
    parser.add_argument('--max-response-size', help='Maximun length for HTTP response', type=int, default=5000000)
    parser.add_argument('--no-passive', help='Do not use OSINT techniques to obtain valid subdomains',
                        action='store_false')
    parser.add_argument('-r', '--resolvers', help='Textfile with DNS resolvers to use. One per line')
    parser.add_argument('--version', help='Show dome version and exit', action='store_true')
    parser.add_argument('-v', '--verbose', help='Show more information during execution', action='store_true')
    return parser.parse_args()


def check_domain(domain: str):
    if domain.startswith((".", "*", "_")):
        return
    if domain in noExists:
        # This is used to avoid overload in web archive (Web Archive can extract same domain thousands of times)
        return
    # If the subdomain was tested before, it wont be scanned again. This is critical to reduce overload
    if domain not in subdomains_found_list:
        rootdomain = domain.split('.')[-2] + "." + domain.split('.')[-1]
        # DONT WORK WITH DOMAINS LIKE domain.gov.uk
        if domain == rootdomain:
            # We dont test de domain itself
            return
        # If passive mode is selected, we dont have ip info so we use "no_ip_because_of_passive_mode"
        ips = ["no_ip_because_of_passive_mode"]
        start = time.time()
        # In active mode, the subdomain is tested to determine if it is alive or not
        if mode.lower() == "active":
            # noinspection PyBroadException
            try:
                global count
                count = count + 1
                res.timeout = 1
                res.lifetime = 1
                answers = res.resolve(domain)
                ip_result = answers[0].address
                ips = []
                for rdata in answers:
                    ips.append(rdata.address)
                # We check if ip correspond to a wildcard DNS
                if wildcardsDicc:
                    for d in wildcardsDicc.keys():
                        if d == rootdomain and ip_result in wildcardsDicc[rootdomain]:
                            return
            except:
                if len(resolvers) > 1:
                    # If we are using a list of resolvers, the queue will change every 50 requests of >5 secs
                    global countToChange
                    end = time.time()
                    if end - start > 5:
                        countToChange = countToChange + 1
                    if countToChange > 50 and res.nameservers[0] == resolvers[0]:
                        # If 50 subdomains take longer than 5 secs to resolve, we call change_dns to change the ip of DNS resolver
                        change_dns()
                        countToChange = 0
                # if isWebArchive:
                # noExists.append(domain)
                # We need to storage when a domain doesn't exists in order to not overload the server (web archive module can make so much requests with same domain)
                return
            # If no exception is given, the ip exists so we create the dictionary as follows {"1.1.1.1": ["subdomain1", "subdomain2"]}
            if show_ip and mode.lower() == "active":
                print("{0}[+] Found new: {1} at {2}{3}\n".format(Colors.G, domain, Colors.W, ', '.join(ips)), end='\r')
            else:
                print("{0}[+] Found new: {1}".format(Colors.G, domain))
        for singleip in ips:
            found = False
            if rootdomain not in list(subdomains_found.keys()):
                subdomains_found[rootdomain] = [{singleip: [domain]}]
            # If domain dont exists, it creates {"domain": [{"ip":["subdomain1",...]}, ...]}
            else:
                j = 0
                for i in range(len(subdomains_found[rootdomain])):
                    # If ip is in diccionary
                    j = j + 1
                    if singleip in list(subdomains_found[rootdomain][i].keys()):
                        # First time = assing, next times = append
                        if domain not in subdomains_found[rootdomain][i][singleip]:
                            subdomains_found[rootdomain][i][singleip].append(domain)
                            found = True
                            break
                if j == len(subdomains_found[rootdomain]) and not found:
                    # If ip doesnt exists...
                    subdomains_found[rootdomain].append({singleip: [domain]})
        subdomains_found_list.append(domain)
        return True


def brute(list_of_domains: list[str], list_of_entries: list[str], option: int, f):
    for domain in list_of_domains:
        for entry in list_of_entries:
            subdomain = "{0}.{1}".format(entry.strip(), domain)
            f(subdomain)
            if option != 1:
                print('\u001B[1K\r{0}        '.format(subdomain), end='\r')
    return


# noinspection PyBroadException
def open_ports(ips: list, ports_list: list, timeout):
    found_domains = {}
    for ip in ips:
        port_open = []
        for port in ports_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, port))
                port_open.append(port)
            except:
                pass
            finally:
                s.close()
        for domain in list(subdomains_found.keys()):
            found_domain = subdomains_found[domain]
            for i in range(len(found_domain)):
                if ip == list(found_domain[i].keys())[0]:
                    if len(port_open) > 0:
                        print("{0}{1} {2} {3}{4}".format(Colors.G, str(ip), str(found_domain[i][ip]), Colors.Y,
                                                         str(port_open)))
                    # If we found the ip, we append the open ports
                    else:
                        print(
                            "{0}{1} {2} {3}No open ports".format(Colors.G, str(ip), str(found_domain[i][ip]), Colors.Y))
                    # If we found the ip, we append the open ports
                    found_domain[i][ip].append(port_open)
            found_domains[domain] = found_domain
    return found_domains


def run_pure_brute(domains_list: list[str], threads_number: int):
    combinations = []
    tmp = []
    for i in range(1, 4):
        tmp += product(string.ascii_lowercase, repeat=i)
    [combinations.append(''.join(i)) for i in tmp]
    print(
        "{0}[!] Bruteforcing from {1}{2}{3} to{4} {5}: ".format(Colors.B, Colors.W, combinations[0], Colors.B, Colors.W,
                                                                combinations[-1]))
    x = int(len(combinations) / threads_number) + 1
    splited_list = [combinations[i:i + x] for i in range(0, len(combinations), x)]
    executor = ThreadPoolExecutor(max_workers=threads_number)
    futures = [executor.submit(brute, domains_list, splited_list[i], 1) for i in range(len(splited_list))]
    wait(futures)


def run_wordlist_brute(domains_list: list[str], entries_list: list, threads_number: int):
    print(Colors.B + "[!] Bruteforcing with wordlist: " + Colors.W + wordlist_name + Colors.G)
    x = int(len(entries_list) / threads_number) + 1
    splited_list = [entries_list[i:i + x] for i in range(0, len(entries_list), x)]
    executor = ThreadPoolExecutor(max_workers=threads_number)
    futures = [executor.submit(brute, domains_list, splited_list[i], 2) for i in range(len(splited_list))]
    wait(futures)


def check_common_prefix(found_list: list[str], f):
    for c in ['-staging', '-testing', '-pre', '-sts', '-test', '-stage']:
        for subdomain in found_list:
            idx = subdomain.index(".")
            new = "{0}{1}{2}".format(subdomain[:idx], c, subdomain[idx:])
            f(new)


def run_open_ports(threads_number: int, ports_list: list[int]):
    timeout = 1  # 0.25
    # Increase if the hosts take longer to respond
    ips_to_scan = []
    for key in list(subdomains_found.keys()):
        for i in range(len(subdomains_found[key])):
            ips_to_scan.append(list(subdomains_found[key][i].keys())[0])
    # This iterates all dicc extracting all ip addresses
    if len(ips_to_scan) == 0:
        return
    print("{0}[!] Checking open ports: ".format(Colors.B))

    return open_ports(ips_to_scan, ports_list, timeout)

    # executor = ThreadPoolExecutor(max_workers=threads_number)
    # if len(ips_to_scan) < threads_number:
    #     splited_list = [ips_to_scan[i:i + 1] for i in range(0, len(ips_to_scan), 1)]
    #     futures = [executor.submit(open_ports, splited_list[i], ports_list, timeout) for i in range(len(ips_to_scan))]
    # else:
    #     x = int(len(ips_to_scan) / threads_number) + 1
    #     splited_list = [ips_to_scan[i:i + x] for i in range(0, len(ips_to_scan), x)]
    #     futures = [executor.submit(open_ports, splited_list[i], ports_list, timeout) for i in range(len(splited_list))]
    # wait(futures)


def run_open_ports_passive(passive_ports: dict):
    print("{0}\n[!] Checking open ports passively: ".format(Colors.B))
    for i in range(len(list(passive_ports.keys()))):
        subdomain = list(passive_ports.keys())[i]
        print("{0}{1} {2}{3}".format(Colors.G, str(subdomain), Colors.Y, str(passive_ports[subdomain])))


# This function is used as template. Makes request method and grep
def default_run(name, request, domain, f):
    # noinspection PyBroadException
    try:
        print("{0}\n[!] Searching in{1} {2} :".format(Colors.B, Colors.W, name))
        r = requests.get(request)
        if name == "VirusTotal" and r.status_code == 429:
            print(
                "{0}\n[-] API Limit exceeded. The Public API is limited to 500 requests per day and a rate of 4 requests per minute.{1}".format(
                    Colors.R, Colors.B))
            return
        if len(r.text) > max_response:
            print(
                "{0}[-] HTTP response to high to grep. Length is {1}{2}{3} and max_response is {4}{5}{6}. Add --max-response-size [NUMBER] to increase maximum response size".format(
                    Colors.W, Colors.R, str(
                        len(r.text)), Colors.W, Colors.R, str(
                        max_response), Colors.W))
        else:
            pattern = '(?!2?F)[a-zA-Z0-9\\-\\.]*\\.{0}\\.{1}'.format(str(domain.split('.')[0]),
                                                                     str(domain.split('.')[1]))
            for domain in re.findall(pattern, r.text):
                f(domain)  # we send to check domain to verify it still exists
    except:
        pass


def run_passive(domains_list: list[str]):
    print("{0}[+] Running passive mode :".format(Colors.B))
    import_apis()
    # noinspection PyBroadException
    try:
        providers = Providers(apis, portsPassive, max_response)
        if not apis:
            print("{0}[!] No API Tokens detected. Running free OSINT engines...".format(Colors.Y))
        for domain in domains_list:
            default_run("Sonar", "https://sonar.omnisint.io/subdomains/{0}?page=".format(domain), domain, check_domain)
            default_run("Hunt.io", "https://fullhunt.io/api/v1/domain/{0}/details".format(domain), domain, check_domain)
            default_run("Anubis-DB", "https://jonlu.ca/anubis/subdomains/{0}".format(domain), domain, check_domain)
            default_run("ThreatCrowd",
                        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={0}".format(domain), domain,
                        check_domain)
            default_run("HackerTarget", "https://api.hackertarget.com/hostsearch/?q={0}".format(domain), domain,
                        check_domain)
            default_run("RapidDNS", "https://rapiddns.io/subdomain/{0}?full=1&down=1".format(domain), domain,
                        check_domain)
            default_run("ThreatMiner", "https://api.threatminer.org/v2/domain.php?q={0}&rt=5".format(domain), domain,
                        check_domain)
            default_run("UrlScan.io", "https://urlscan.io/api/v1/search/?q={0}".format(domain), domain, check_domain)
            default_run("BufferOverflow", "https://dns.bufferover.run/dns?q={0}".format(domain), domain, check_domain)
            default_run("DNS Repo", "https://dnsrepo.noc.org/?search=.{0}".format(domain), domain, check_domain)

            providers.run_site_dossier(domain, check_domain)
            providers.run_alien_vault(domain, check_domain)
            # global isWebArchive
            providers.run_web_archive(domain, check_domain)
            # We use flag to tell function check_domain to store the non existing subdomains due to high overload
            providers.run_cert_spotter(domain, check_domain)
            # CertSpotter can be used with api or without, so we make the condition inside the function
            providers.run_crt(domain, check_domain)
            if apis:
                for api in apis.keys():
                    if api == "VIRUSTOTAL":
                        default_run("VirusTotal", "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + apis[
                            "VIRUSTOTAL"] + "&domain=" + domain, domain, check_domain)
                    elif api == "SHODAN":
                        providers.run_shodan(domain, check_domain)
                    elif api == "SPYSE":
                        providers.run_spyse(domain, check_domain)
                    elif api == "SECURITYTRAILS":
                        providers.run_security_trails(domain, check_domain)
                    elif api == "PASSIVETOTAL":
                        providers.run_passive_total(domain, check_domain)
                    elif api == "BINARYEDGE":
                        providers.run_binary_edge(domain, check_domain)
    except:
        pass


def run_active(domains_list: list[str], entries_list: list, threads_number: int, no_bruteforce: bool):
    print("{0}\n[+] Running active mode: ".format(Colors.B))
    if not no_bruteforce:
        run_pure_brute(domains_list, threads_number)
    if len(entries_list) > 0:
        run_wordlist_brute(domains_list, entries_list, threads_number)
    else:
        print("{0}\n\n[-] No wordlist provided. ".format(Colors.R))
    check_common_prefix(subdomains_found_list, check_domain)


def check_wildcard(domains_list: list[str]):
    ips = []
    for domain in domains_list:
        print("{0}\n[!] Checking if {1}{2}{3} has wildcard enable".format(Colors.B, Colors.W, domain, Colors.B))
        i = 0
        # We generate 10 random and non existing subdomains and we test if they are marked as up.
        # If all subdomains "exists", the domain has wildcard enable
        for i in range(5):
            # noinspection PyBroadException
            try:
                x = uuid.uuid4().hex[0:random.randint(6, 32)]
                # ip = socket.gethostbyname(x +"."+ domain)
                answers = res.resolve("{0}.{1}".format(x, domain))
                ip = answers[0].address
                if ip not in ips:
                    ips.append(ip)
                i = i + 1
            except:
                pass

        if i == 5:
            msg = "{0}\n[-] Alert: Wildcard enable for domain {1}. Omiting subdomains that resolve for {2}"
            print(msg.format(Colors.R, domain, str(ips)))
            wildcardsDicc[domain] = ips  # Store the ip to discard subdomains with this ip
        else:
            print("{0}[+] No wildcard enable for {1}{2}".format(Colors.G, Colors.W, domain))


def import_apis():
    if not os.path.exists('config.api'):
        print("{0}\n[!] File config.api not found in current directory".format(Colors.Y))
        return
    with open("config.api", "r") as _:
        for line in _.readlines():
            if not line.startswith('#'):
                line = line.strip()
                if line != '':
                    line.split("=")
                    if line.split("=")[1] != '""':
                        apis[line.split("=")[0]] = line.split("=")[1].replace('"', '')


if __name__ == "__main__":
    args = parse_args()
    version = "1.1"
    # TO BE IMPLEMENTED AUTO UPDATE
    global max_response
    global wordlist_name
    global show_ip
    # global G, Y, B, R, W
    printOutputV = args.silent and args.verbose
    outputFlag = args.output
    Colors.color(args.no_color)
    banner()
    if args.version:
        print("{0}[+] Current version: {1}{2}".format(Colors.G, Colors.Y, version))
        exit()
    # noinspection PyBroadException
    try:
        socket.gethostbyname('google.com')
    except:
        print("{0}[-] No internet connection".format(Colors.R))
        exit()
    wordlist_name = args.wordlist
    if wordlist_name and not os.path.exists(wordlist_name):
        print(
            "{0}Wordlist file \'{1}\' does not exists. Create it or run without -w, --wordlist to do not perform wordlist based attack".format(
                Colors.R, str(wordlist_name)))
        exit()
    max_response = args.max_response_size
    domains = args.domain.split(',')
    threads = args.threads
    mode = args.mode.lower()
    show_ip = args.ip
    if args.resolvers:
        if not os.path.exists(args.resolvers):
            text = "{0}Resolvers file \'{1}\' does not exists. Create it or run without -r, --resolvers flags"
            print(text.format(Colors.R, str(args.resolvers)))
            exit()
        file = open(args.resolvers, 'r')
        res.nameservers = file.read().splitlines()
        file.close()
    else:
        res.nameservers = resolvers
    if mode != "passive" and mode != "active":
        print("{0}\n[-] Error mode. Mode argument only accepts \'active\' or \'passive\'".format(Colors.R))
        exit()
    if args.ports:
        ports = args.ports.split(',')
    else:
        ports = None
    print("{0}ATTACK INFORMATION :".format(Colors.B))
    print("{0}Target: {1}{2}".format(Colors.B, Colors.W, ', '.join(domains)))
    print("{0}Mode: {1}{2}".format(Colors.B, Colors.W, str(mode)))
    if args.top_web_ports:
        print("{0}Check ports: {1}top_web_ports".format(Colors.B, Colors.W))
    elif args.top_100_ports:
        print("{0}Check ports: {1}top_100_ports".format(Colors.B, Colors.W))
    elif args.top_1000_ports:
        print("{0}Check ports: {1}top_1000_ports".format(Colors.B, Colors.W))
    elif args.ports:
        print("{0}Check ports: {1}{2}".format(Colors.B, Colors.W, str(ports)))
    print("{0}Threads: {1}{2}".format(Colors.B, Colors.W, str(threads)))
    print("{0}Resolvers: {1}{2}".format(Colors.B, Colors.W, ', '.join(res.nameservers)))
    print("{0}Scan started: {1}{2}".format(Colors.B, Colors.W, datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    print("{0}\n[!] NOTE: Only new subdomains will be printed. No output from engine != no results".format(Colors.Y))
    if sys.version_info.major != 3:
        print("{0}\n[!] You are using Python2. Python3 is recommended for better user experience".format(Colors.Y))
    if mode.lower() == "passive":
        print(
            "{0}\n[!] You selected passive mode. The subdomain will NOT be tested to ensure they are still available".format(
                Colors.R))
        run_passive(domains)
        if portsPassive:  # If we got ports from a passive engine...
            run_open_ports_passive(portsPassive)
    elif mode.lower() == "active":
        entries = []
        if args.wordlist:
            wl = open(args.wordlist, 'r')
            entries = wl.readlines()
            wl.close()
        check_wildcard(domains)
        run_active(domains, entries, threads, args.no_bruteforce)
        if args.no_passive:
            run_passive(domains)
        if args.top_web_ports:
            subdomains_found_ports = run_open_ports(threads, topWebports)
        elif args.top_100_ports:
            subdomains_found_ports = run_open_ports(threads, top100ports)
        elif args.top_1000_ports:
            subdomains_found_ports = run_open_ports(threads, top1000ports)
        elif args.ports:
            subdomains_found_ports = run_open_ports(threads, [int(i) for i in ports])
        else:
            print("{0}\n[-] No ports provided so scan will not be made".format(Colors.R))
    else:
        print(
            "{0}\n[-] No mode selected. Mode available: active, passive\n\n[!] Example: python Dome.py -m passive -d domain.com".format(
                Colors.R))
        exit()
    if outputFlag:
        output(subdomains_found, subdomains_found_list, subdomains_found_ports, mode, Colors.B, Colors.W)
    print("\n{0}{1}".format(Colors.Y, json.dumps(subdomains_found, sort_keys=False, indent=4)))
    print("{0}\n[+] {1}{2} unique subdomains found\n".format(Colors.W, str(len(subdomains_found_list)), Colors.B))
    print("[+] Program finished at {0}".format(datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
