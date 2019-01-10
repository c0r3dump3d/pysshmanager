#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

__license__="""

pySSHManager

Version 0.1

A simple Python3 script to manage SSH connection.

Author(s):

        c0r3dump3d | coredump<@>autistici.org

pySSHManager project site: https://github.com/c0r3dump3d/pysshmanager

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
The authors disclaims all responsibility in the use of this tool.
"""

import socket
import csv
import time
import subprocess
from subprocess import check_output
from subprocess import DEVNULL
import os
import sys
import hashlib
import string
import warnings

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.shortcuts import ProgressBar
    from prompt_toolkit.shortcuts import prompt, CompleteStyle
    from prompt_toolkit.completion import WordCompleter

except ImportError:
    print("You need to install Python Prompt Toolkit module. pip install prompt_toolkit")
    exit(1)

try:
    from beautifultable import BeautifulTable

except ImportError:
    print("You need to install Beautiful Table python  module. pip install beautifultable")
    exit(1)

try:
    import configparser

except ImportError:
    print("You need to install configparser python  module. pip install configparser")
    exit(1)

from subprocess import DEVNULL
import warnings


try:
    from IPy import IP
except ImportError:
    print("You need to install IPy module. pip install IPy.")
    exit(1)


def welcome():
    print("""
             ____ ____  _   _ __  __
 _ __  _   _/ ___/ ___|| | | |  \/  | __ _ _ __   __ _  __ _  ___ _ __
| '_ \| | | \___ \___ \| |_| | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
| |_) | |_| |___) |__) |  _  | |  | | (_| | | | | (_| | (_| |  __/ |
| .__/ \__, |____/____/|_| |_|_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|
|_|    |___/                                           |___/

    """)
    print()
    print("\t.... Manage your SSH connection with Python ....")
    print()
    print()

def help():
    print("[+] Available commands: ")
    print()
    print("[*] scan: Scan a single Ip or Network -- scan 192.168.14, scan 192.168.1.0/24")
    print("[*] list host: List host(s) available.")
    print("[*] reset: Reset pySSHManager deleting all host(s).")
    print("[*] save:  Save all host(s) in a csv file specified in configuration.")
    print("[*] show:  Show the values of differents options.")
    print("[*] set: Set some options during script execution.")
    print("""
                -- port: Set TCP Port for ssh connection. 
                -- user: Set user for the ssh connection. 
                -- terminal: Set terminal. 
                -- group: Set default group.
                -- default: Read again the configuration file.
            """)
    print("[*] connect: Connect with host(s): ")
    print("""
                -- by ID(s): connect $ID
                -- range ID(s): connect $ID(1)/$ID(2)
                -- several ID(s): connect $ID(1),$ID(3)
                -- search and connect by string: connect "string" 
            """)
    print("[*] delete: Delete host(s): ")
    print(""" 
                -- by ID: delete $ID
                -- range ID: delete $ID(1)/$ID(2)
                -- several ID: delete $ID(1),$ID(3)
                -- search and connect by string: connect "string" 
            """)

def searchALL(term):
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "GROUP"]
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    for val in hosts_id_hash:

        if term in hosts_present_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_dns_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_group_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

    print(table)

def showValues():
    print("++++++++++++++++++++++++++++")
    print("+      Options values      +")
    print("++++++++++++++++++++++++++++")
    print()
    print("[+] TCP Port: {0}".format(port))
    print("[+] User: {0}".format(user))
    print("[+] Default group: {0}".format(group))
    print("[+] Hosts file: {0}".format(hostfile))
    print("[+] Terminal: {0}".format(terminal))
    print("++++++++++++++++++++++++++++")

def searchConnect(term):
    hosts_found = []
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "GROUP"]
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    for val in hosts_id_hash:

        if term in hosts_present_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_dns_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_group_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_port_hash[val]:
            hosts_found.append(hosts_present_hash[val])

    if not hosts_found:
        print("[-] No result in the search.")
        return

    else:
        print(table)
        message = "Are you sure to connect to this host(s)? (Y/n) "
        action = yes_or_no(message)
        if action:
            connection(hosts_found)

        else:
            pass


def showHOSTS():
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "GROUP"]
    for i in hosts_present_hash:
        table.append_row([hosts_id_hash[i], str(hosts_present_hash[i]), str(
            hosts_port_hash[i]), str(hosts_dns_hash[i]), 
            str(hosts_group_hash[i])])
    print(table)


def loadCSV():
    if not os.path.exists(hostfile):
        open(hostfile, 'w+').close()
    if os.stat(hostfile).st_size == 0:
        print(
            "[-] The " +
            hostfile +
            " file is empty. To add some hosts run \'scan\' command.")
        return

    with open(hostfile) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            hash_object = hashlib.sha256(row[1].encode('utf-8'))
            hash_ip = hash_object.hexdigest()
            hosts_present_hash[hash_ip] = row[1]
            hosts_dns_hash[hash_ip] = row[3]
            hosts_group_hash[hash_ip] = row[4]
            hosts_id_hash[hash_ip] = row[0]
            hosts_port_hash[hash_ip] = row[2]


def writeCSV():
    with open(hostfile, 'a') as csvfile:
        csvfilewrite = csv.writer(
            csvfile,
            delimiter=',',
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL)
        for i in hosts_present_hash:
            ip = hosts_present_hash[i]
            dns = hosts_dns_hash[i]
            id = hosts_id_hash[i]
            group = hosts_group_hash[i]
            tcpport = hosts_port_hash[i]
            csvfilewrite.writerow([id, ip, tcpport, dns, group])


def connScan(hosts, port, group):
    warnings.simplefilter("ignore", ResourceWarning)
    numhost = len(hosts)
    lastkey = list(hosts_id_hash.items())
    try:
        id = int(lastkey[-1][1])
    except IndexError:
        id = 0
    check = 0
    print("[+] Scanning %d host(s) ..." % numhost)
    with ProgressBar() as pb:
        for ip in pb(hosts):
            hash_object = hashlib.sha256(ip.encode('utf-8'))
            hash_ip = hash_object.hexdigest()
            connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connSkt.settimeout(1)
            try:
                result = connSkt.connect_ex((ip, int(port)))
            except BaseException:
                print("[-] Unable to connect.")
                break
            if result == 0:
                if hash_ip not in hosts_present_hash:
                    id = id + 1
                    try:
                        revers = socket.gethostbyaddr(ip)[0]
                    except BaseException:
                        revers = ""
                    hosts_present_hash[hash_ip] = ip
                    hosts_dns_hash[hash_ip] = revers
                    hosts_id_hash[hash_ip] = id
                    hosts_group_hash[hash_ip] = group
                    hosts_port_hash[hash_ip] = port
                    check = 1
            connSkt.close()
    return check


def connection(hosts_connect):
    warnings.simplefilter("ignore", ResourceWarning)

    fj = " " + user + "@"

    # Special case to avoid the noisy gnome-terminal
    if "gnome" in terminal:
        try:
            termi = (str(check_output(["/usr/sbin/which",
                                       terminal],
                                      universal_newlines=True,
                                      stderr=subprocess.PIPE))).split("\n")[0]
        except subprocess.CalledProcessError:
            print("[-] Unable to open the terminal. Please check the terminal application.")
            return
        if sync == 1:
            command = termi + " -q -e \'/usr/sbin/xpanes -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"
            print(command)
        else:
            command = termi + " -q -e \'/usr/sbin/xpanes -d -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"

    else:
        try:
            termi = (str(check_output(["/usr/sbin/which",
                                       terminal],
                                      universal_newlines=True,
                                      stderr=subprocess.PIPE))).split("\n")[0]
        except subprocess.CalledProcessError:
            print("[-] Unable to open the terminal. Please the terminal application.")
            return

        if sync == 1:
            command = termi + " -e \'/usr/sbin/xpanes -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"
        else:
            command = termi + " -e \'/usr/sbin/xpanes -d -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"
    try:
        proc = subprocess.Popen(command, shell=True, stdout=DEVNULL)

    except BaseException as e:
        print("[-] Unable to connect: {0}".format(e))

def deleteHosts(hosts_delete):
    for val2 in hosts_delete:
        hosts_present_hash.pop(val2)
        hosts_dns_hash.pop(val2)
        hosts_id_hash.pop(val2)
        hosts_port_hash.pop(val2)
        hosts_group_hash.pop(val2)

def searchDelete(term):
    hosts_found = []
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "GROUP"]
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    for val in hosts_id_hash:

        if term in hosts_present_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_dns_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_group_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_port_hash[val]:
            hosts_found.append(val)

    if not hosts_found:
        print("[-] No result in the search.")
        return

    else:
        print(table)
        message = "Are you sure to delete? (Y/n) "
        action = yes_or_no(message)
        if action:
            deleteHosts(hosts_found)

        else:
            pass




def yes_or_no(message):

    while True:
        yes = {'yes', 'y', 'ye', ''}
        no = {'no', 'n'}
        choice = input(message).lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'\n")

def readConfig():

    warnings.simplefilter("ignore", ResourceWarning)
    global hostfile
    global terminal
    global port
    global user
    global group

    print("[+] Reading the config file ...")
    config = configparser.ConfigParser()
    config.read_file(open(r'pySSHManager.conf'))
    terminal = config.get('config', 'terminal')
    hostfile = config.get('config', 'hostfile')
    port = config.get('config', 'port')
    user = config.get('config', 'user')
    group = config.get('config', 'group')


if __name__ == '__main__':

    warnings.simplefilter("ignore", ResourceWarning)
    hosts_present_hash = {}
    hosts_dns_hash = {}
    hosts_id_hash = {}
    hosts_group_hash = {}
    hosts_port_hash = {}
    chk = 1

    # Read the configuration file
    welcome()
    print(
        "[+] Starting pySSHManager v0.1 (https://github.com/c0r3dump3d/pysshmanager) at " +
        time.strftime("%x") +
        " " +
        time.strftime("%X") +
        " - for legal purposes only.")
    print()
    readConfig()

    print("[+] Reading for previous host(s) ...")
    loadCSV()

    our_history = FileHistory('.history-commands')
    numhost = 0
    sync = 0
    session = PromptSession(history=our_history)
    options = WordCompleter(['scan','\'list hosts\'','help','?',
        'connect','reset','search','delete','save','set','show',
        ],ignore_case=True)

    while True:
        table = BeautifulTable(max_width=100)
        table.default_alignment = BeautifulTable.ALIGN_CENTER
        table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
        table.column_headers = ["ID", "IP", "PORT", "FQDN", "GROUP"]
        answer = session.prompt('pysshmgr> ', completer=options,
                complete_style=CompleteStyle.READLINE_LIKE)
        if answer.split(" ")[0] == "scan":
            hosts = []
            target = answer.split(" ")[1]

            try:
                if answer.split(" ")[2] == "port":
                    port = answer.split(" ")[3]
                else:
                    group = answer.split(" ")[2]

                if answer.split(" ")[3] == "port":
                    port = answer.split(" ")[4]

            except IndexError:
                pass

            if "/" in target:
                try:
                    for ip in IP(target):
                        hosts.append(str(ip))
                    del hosts[0]
                    del hosts[-1]
                except ValueError:
                    print("[-] Invalid network address.")
                    chk = 0
                except IndexError:
                    print("[-] Invalid network address.")
                    chk = 0
            else:
                try:
                    IP(target)
                except ValueError:
                    print("[-] Invalid host address.")
                    chk = 0
                hosts.append(target)

            if chk != 0:
                start_time = time.time()
                check = connScan(hosts, port, group)
                print(
                    "[+] Scan finished in",
                    time.time() -
                    start_time,
                    "seconds.")
                print("[+] Updating hostfile.csv file ...")
                os.remove('hostfile.csv')
                writeCSV()

                if check == 0:
                    print("[-] No host added.")
                else:
                    print(
                        "[+] Some hosts were found ... (check with \'list hosts\' command.)")

        elif answer.split(" ")[0] == "list":
            if answer.split(" ")[1] == "hosts":
                showHOSTS()
            else:
                print("[-] Option not found.")

        elif answer.split(" ")[0] == "search":
            term = answer.split(" ")[1]
            searchALL(term)

        elif answer.split(" ")[0] == "connect":
            string = answer.split(" ")[1]
            try:
                if answer.split(" ")[2] == "sync":
                    sync = 1
            except BaseException:
                pass

            hosts_connect = []
            if "/" in string:
                value1 = int(string.split("/")[0])
                value2 = int(string.split("/")[1])

                for i in list(range(value1, value2 + 1)):
                    for j in hosts_id_hash:
                        if str(hosts_id_hash[j]) == str(i):
                            ip = hosts_present_hash[j]
                            hosts_connect.append(ip)
                            table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                str(hosts_group_hash[j])])
                            break
                print(table)
                message = "Are you sure to connect to this host(s)? (Y/n) "
                action = yes_or_no(message)
                if action:
                    connection(hosts_connect)
                    del table
                else:
                    pass

            elif "," in string:
                lst = string.split(",")
                stringcount = len(lst)
                for value1 in lst:
                    for j in hosts_id_hash:
                        if str(hosts_id_hash[j]) == str(value1):
                            ip = hosts_present_hash[j]
                            hosts_connect.append(ip)
                            table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                str(hosts_group_hash[j])])
                            break
                print(table)
                message = "Are you sure to connect to this host(s)? (Y/n) "
                action = yes_or_no(message)
                if action:
                    connection(hosts_connect)
                    del table
                else:
                    pass

            elif string.isdigit():
                for j in hosts_id_hash:
                    if str(hosts_id_hash[j]) == str(string):
                        ip = hosts_present_hash[j]
                        hosts_connect.append(ip)
                        table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                            hosts_port_hash[j]), str(hosts_dns_hash[j]), str(hosts_group_hash[j])])
                        break

                print(table)
                message = "Are you sure to connect to this host(s)? (Y/n) "
                action = yes_or_no(message)
                if action:
                    connection(hosts_connect)
                    del table
                else:
                    pass

            else:
                searchConnect(string)

        elif answer.split(" ")[0] == "delete":
            string = answer.split(" ")[1]
            hosts_delete=[]
            if "/" in string:
                value1 = int(string.split("/")[0])
                value2 = int(string.split("/")[1])

                for i in list(range(value1, value2 + 1)):
                    for j in hosts_id_hash:
                        if str(hosts_id_hash[j]) == str(i):
                            table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                str(hosts_group_hash[j])])
                            hosts_delete.append(j)
                            break

                print(table)
                message = "Are you sure to delete this host(s)? (Y/n) "
                action = yes_or_no(message)
                if action:
                     deleteHosts(hosts_delete)
                     del table

            elif "," in string:
                lst = string.split(",")
                stringcount = len(lst)
                for value1 in lst:
                    for j in hosts_id_hash:
                        if str(hosts_id_hash[j]) == str(value1):
                            table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                str(hosts_group_hash[j])])
                            hosts_delete.append(j)
                            break

                print(table)
                message = "Are you sure to delete this host(s)? (Y/n) "
                action = yes_or_no(message)
                if action:
                    deleteHosts(hosts_delete)
                    del table

            elif string.isdigit():
                for j in hosts_id_hash:
                    if str(hosts_id_hash[j]) == str(string):
                        table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                             hosts_port_hash[j]), str(hosts_dns_hash[j]),
                             str(hosts_group_hash[j])])
                        hosts_delete.append(j)
                        break
                print(table)
                message = "Are you sure to delete this host(s)? (Y/n) "
                action = yes_or_no(message)
                if action:
                    deleteHosts(hosts_delete)
                    del table
            
            else:
                searchDelete(string)

        elif answer.split(" ")[0] == "reset":
            message = "Are you sure to reset pySSHManager? (Y/n) "
            action = yes_or_no(message)
            if action:
                os.remove('hostfile.csv')
                hosts_present_hash = {}
                hosts_dns_hash = {}
                hosts_id_hash = {}
                loadCSV()
            else:
                pass

        elif answer.split(" ")[0] == "set":

            if answer.split(" ")[1] == "port":
                port = answer.split(" ")[2] 
                print("[+] Port defined to vale {0}".format(port))

            elif answer.split(" ")[1] == "user":
                user = answer.split(" ")[2] 
                print("[+] User defined to vale {0}".format(user))

            elif answer.split(" ")[1] == "terminal":
                terminal = answer.split(" ")[2] 
                print("[+] Terminal defined to vale {0}".format(terminal))

            elif answer.split(" ")[1] == "group":
                group = answer.split(" ")[2] 
                print("[+] Default group defined to vale {0}".format(group))

            elif answer.split(" ")[1] == "default":
                readConfig()

            else:
                print("[-] Option not defined.")


        elif answer.split(" ")[0] == "help":
            help()

        elif answer.split(" ")[0] == "?":
            help()

        elif answer.split(" ")[0] == "show":
            showValues()

        elif answer.split(" ")[0] == "save":
            print("[+] Updating hostfile.csv file ...")
            os.remove('hostfile.csv')
            writeCSV()

        elif answer.split(" ")[0] == "exit":
            print("[+] Updating hostfile.csv file ...")
            os.remove('hostfile.csv')
            writeCSV()

            print("[+] Have a nice day !!")
            exit(0)

        elif answer.split(" ")[0] == "":
            pass

        else:
            print("[-] Command not found.")

