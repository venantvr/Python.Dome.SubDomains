# noinspection PyBroadException
import json
import os
import sys

# noinspection PyBroadException
from jinja2 import Template

from colors import Colors


def parser_error(errmsg: str):
    Colors.color(True)
    print("Usage: python3 {0} [Options] use -h for help".format(sys.argv[0]))
    print("{0}Error: {1}{2}".format(Colors.R, errmsg, Colors.W))
    sys.exit()


def output(subdomains_found, subdomains_found_list, subdomains_found_ports, mode: str, b, w):
    print("{0}[+] Writing output in {1}results folder".format(b, w))

    results = './results'
    if not os.path.exists(results):
        os.mkdir(results)

    active = './results/active'
    if not os.path.exists(active):
        os.mkdir(active)

    passive = './results/passive'
    if not os.path.exists(passive):
        os.mkdir(passive)

    with open('view_html_01.j2') as f:
        tree = str(subdomains_found).replace("'", '"')
        rendered = Template(f.read()).render(tree=tree)

    with open("results/results_all_last_scan.html", "w") as _:
        _.write(rendered)

    with open("results/results_all_last_scan.json", "w") as _:
        _.write(json.dumps(subdomains_found, sort_keys=False, indent=4))

    with open("results/subdomains_last_scan.txt", "w") as _:
        _.write("\n".join(subdomains_found_list))

    for domain in list(subdomains_found.keys()):
        domain_without_extension = str(domain.split(".")[0])

        assert isinstance(domain, str)
        if not os.path.exists("./results/{0}/{1}".format(mode, domain)):
            os.mkdir("./results/{0}/{1}".format(mode, domain))

        with open('view_html_02.j2') as f:
            tree = str(subdomains_found).replace("'", '"')
            rendered = Template(f.read()).render(domain=domain, tree=tree)

        with open("results/{0}/{1}/results_{2}.html".format(mode, domain, domain_without_extension), "w") as _:
            _.write(rendered)

        with open("results/{0}/{1}/subdomains.txt".format(mode, domain), "w") as _:
            for i in range(len(subdomains_found_list)):
                if domain in subdomains_found_list[i]:
                    _.write(subdomains_found_list[i] + "\n")

        # passive_ports serait mieux ? subdomains_found est le mauvais array...
        with open("results/{0}/{1}/subdomains_ports.json".format(mode, domain), "w") as _:
            if domain in subdomains_found_ports:
                json.dump(subdomains_found_ports[domain], _, indent=2)
