from colorama import Fore
from tabulate import tabulate


def print_risk_report(ip, score):

    if score >= 80:
        colour = Fore.RED
        status = "CRÍTICO"

    elif score >= 50:
        colour = Fore.YELLOW
        status = "MÉDIO"

    else:
        colour = Fore.GREEN
        status = "BAIXO"

    table = [
        ["IP", ip],
        ["Score", score],
        ["Estado", status]
    ]

    print(colour)
    print(tabulate(table))