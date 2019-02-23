#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

__license__="""

pySSHManager

Version 0.2.0

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
import signal
import ipaddress


try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.shortcuts import ProgressBar
    from prompt_toolkit.shortcuts import prompt, CompleteStyle
    from prompt_toolkit.completion import WordCompleter

except ImportError:
    print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] You need to install Python Prompt Toolkit module. pip install prompt_toolkit")
    exit(1)

try:
    from beautifultable import BeautifulTable

except ImportError:
    print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] You need to install Beautiful Table python  module. pip install beautifultable")
    exit(1)

try:
    import configparser

except ImportError:
    print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] You need to install configparser python  module. pip install configparser")
    exit(1)

try:
    import psutil 

except ImportError:
    print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] You need to install psutil python  module. pip install psutil")
    exit(1)

from subprocess import DEVNULL
import warnings


try:
    from IPy import IP
except ImportError:
    print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] You need to install IPy module. pip install IPy.")
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
    print("\t.... Manage your SSH connections with Python ....")
    print()
    print()

def help():
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Available commands: ")
    print()
    print("[*] scan: Scan a single Ip or Network -- scan 192.168.14, scan 192.168.1.0/24")
    print("[*] list: List available host(s).")
    print("[*] reset: Reset pySSHManager deleting all host(s).")
    print("[*] save:  Save all host(s) in a csv file specified in configuration.")
    print("[*] options:  Show the values of differents options.")
    print("[*] networks: Show networks.")
    print("[*] addnet: Add network.")
    print("[*] delnet: Delete a network.")
    print("[*] procs: Show PID of terminal sessions process.")
    print("[*] kill: Kill terminal sessions process.")
    print("""
                -- all: Kill all terminal sessions process.
                -- PID: Kill process with PID. 
            """)
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
                -- range ID(s): connect $ID(1)-$ID(2)
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

            sys.stdout.write("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Please respond with 'yes' or 'no'\n")

class bcolors:

    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def searchALL(term):
    table = BeautifulTable(max_width=150)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "NETWORK", "GROUP"]
    table.width_exceed_policy = BeautifulTable.WEP_WRAP
    for val in hosts_id_hash:

        if term in hosts_present_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_dns_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_group_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_net_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_port_hash[val]:
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

    print(table)

def showValues():
    print("----------------------------")
    print("-----  Options values  -----")
    print("----------------------------")
    print()
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] TCP Port: {0}".format(port))
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] User: {0}".format(user))
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Default group: {0}".format(group))
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Hosts file: {0}".format(hostfile))
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Terminal: {0}".format(terminal))
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Timeout: {0}".format(timeout))
    print("----------------------------")

def searchConnect(term):
    hosts_found = []
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "NETWORK", "GROUP"]
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    for val in hosts_id_hash:

        if term in hosts_present_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_dns_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_group_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_net_hash[val]:
            hosts_found.append(hosts_present_hash[val])
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]), 
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_port_hash[val]:
            hosts_found.append(hosts_present_hash[val])

    if not hosts_found:
        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] No host(s) found.")
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
    table = BeautifulTable(max_width=150)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.width_exceed_policy = BeautifulTable.WEP_WRAP
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "NETWORK", "GROUP"]
    for i in hosts_present_hash:
        table.append_row([hosts_id_hash[i], str(hosts_present_hash[i]), str(
            hosts_port_hash[i]), str(hosts_dns_hash[i]), str(hosts_net_hash[i]), 
            str(hosts_group_hash[i])])
    print(table)


def loadCSV():
    if not os.path.exists(hostfile):
        open(hostfile, 'w+').close()
    if os.stat(hostfile).st_size == 0:
        print(
            "[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] The " +
            hostfile +
            " file is empty. To add some hosts first add a network with \'addnet\' command, and then scan with \'scan\' command.")

        netInterface()
        return

    with open(hostfile) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            hash_object = hashlib.sha256(row[1].encode('utf-8'))
            hash_ip = hash_object.hexdigest()
            hosts_present_hash[hash_ip] = row[1]
            hosts_dns_hash[hash_ip] = row[3]
            hosts_net_hash[hash_ip] = row[4]
            hosts_group_hash[hash_ip] = row[5]
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
            network = hosts_net_hash[i]
            csvfilewrite.writerow([id, ip, tcpport, dns, network, group])

def killProc(pid):
     
    if str(pid) in process:
        print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Killing terminal session with PID " + str(pid))
        p = psutil.Process(int(pid))
        for child in p.children(recursive=True):
            if child.status() == psutil.STATUS_ZOMBIE:
                print ("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] The process " + child + " it's zombie.")
            else:
                try:
                    child.kill()
                except:
                    pass
                try:
                    p.kill()
                except:
                    pass
    else:
        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] This process doesn't exist.")

def killAll():

    for sess in process:
        killProc(sess)
    del process[:]

def validIPV4(address):

    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error: 
            return False 
        return address.count('.') == 3 
    except socket.error:  # not a valid address 
        return False 
    return True
 
def netInterface():

    for nic, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if validIPV4(addr.address):
                if addr.address !='127.0.0.1':
                    if addr.netmask:
                        net = str(ipaddress.ip_network(addr.address + "/" + addr.netmask, strict=False))
                        print ("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Network detected " + net + "... ", end='') 
                        message="Do you want to add this network (Y/n)? "
                        action = yes_or_no(message)

                        if action:
                            grp=input("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Please assign a name for this network [default]: ")
                            if grp:
                                networks.append(net)
                                groups.append(grp)

                            else:

                                networks.append(net)
                                groups.append(group)

def listProcs():
    
    print("----------------------------------------")
    print("--- List of PID of terminal sessions ---")
    print("----------------------------------------")
    print()
    for i in process:
        print ("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] " + str(i))

def connScan(hosts, port, group, net):
    warnings.simplefilter("ignore", ResourceWarning)
    numhost = len(hosts)
    lastkey = list(hosts_id_hash.items())
    try:
        id = int(lastkey[-1][1])
    except IndexError:
        id = 0
    check = 0
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Scanning %d host(s) ..." % numhost)
    with ProgressBar() as pb:
        for ip in pb(hosts):
            hash_object = hashlib.sha256(ip.encode('utf-8'))
            hash_ip = hash_object.hexdigest()
            connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connSkt.settimeout(float(timeout))
            try:
                result = connSkt.connect_ex((ip, int(port)))
            except BaseException:
                print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Unable to connect.")
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
                    hosts_net_hash[hash_ip] = net 
                    check = 1
            connSkt.close()
    return check


def connection(hosts_connect):
    warnings.simplefilter("ignore", ResourceWarning)

    fj = " " + user + "@"

    # Special case to avoid the noisy gnome-terminal
    if "gnome" in terminal:
        try:
            termi = (str(check_output(["/usr/bin/which",
                                       terminal],
                                      universal_newlines=True,
                                      stderr=subprocess.PIPE))).split("\n")[0]
        except subprocess.CalledProcessError:
            print("[-] Unable to open the terminal. Please check the terminal application.")
            return
        if sync == 1:
            command = termi + " -q -e \'" + xpan + " -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"
            print(command)
        else:
            command = termi + " -q -e \'" + xpan + " -d -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"

    else:
        try:
            termi = (str(check_output(["/usr/bin/which",
                                       terminal],
                                      universal_newlines=True,
                                      stderr=subprocess.PIPE))).split("\n")[0]
        except subprocess.CalledProcessError:
            print("[✗] Unable to open the terminal. Please the terminal application.")
            return

        if sync == 1:
            command = termi + " -e \'" + xpan + " -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"
        else:
            command = termi + " -e \'" + xpan + " -d -c \"ssh -p " + \
                port + " {}\" " + user + "@" + fj.join(hosts_connect) + "\'"  
    
    try:
        proc = subprocess.Popen(command, shell=True, stdout=DEVNULL, stderr=DEVNULL)
        print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Open terminal with PID " + str(proc.pid))
        process.append(str(proc.pid))

    except BaseException as e:
        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Unable to connect: {0}".format(e))


def deleteHosts(hosts_delete):
    for val2 in hosts_delete:
        hosts_present_hash.pop(val2)
        hosts_dns_hash.pop(val2)
        hosts_id_hash.pop(val2)
        hosts_port_hash.pop(val2)
        hosts_group_hash.pop(val2)

def showNetworks():
    
    i = 0
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID","NETWORKS","GROUPS"]
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    for net in networks:
        table.append_row([i+1,net,groups[i]])
        i = i + 1
    print(table) 

def delNetwork(netk):

    del networks[netk]
    del groups[netk]


def delHostGroup(term):
    hosts_found = []
    for val in hosts_id_hash:
        if term in hosts_group_hash[val]:
            hosts_found.append(val)


    if not hosts_found:
        return

    else:
        deleteHosts(hosts_found)



def searchDelete(term):
    hosts_found = []
    table = BeautifulTable(max_width=100)
    table.default_alignment = BeautifulTable.ALIGN_CENTER
    table.column_headers = ["ID", "IP", "PORT", "FQDN", "NETWORK", "GROUP"]
    table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
    for val in hosts_id_hash:

        if term in hosts_present_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_dns_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_group_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_net_hash[val]:
            hosts_found.append(val)
            table.append_row([hosts_id_hash[val], str(hosts_present_hash[val]),
                              str(hosts_port_hash[val]),
                              str(hosts_dns_hash[val]),
                              str(hosts_net_hash[val]),
                              str(hosts_group_hash[val])])

        elif term in hosts_port_hash[val]:
            hosts_found.append(val)

    if not hosts_found:
        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] No host(s) found.")
        return

    else:
        print(table)
        message = "Are you sure to delete? (Y/n) "
        action = yes_or_no(message)
        if action:
            deleteHosts(hosts_found)

        else:
            pass


def extracNet(target):
    global chk
    hosts[:] = []
    try:
        for ip in IP(target):
            hosts.append(str(ip))
    except ValueError:
          print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Invalid network address.")
          chk = 0
          return
    except IndexError:
          print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Invalid network address.")
          chk = 0
          return

    if len(hosts) > 1:
        del hosts[0]
        del hosts[-1]

def checkNet(target):

    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Checking network address... ", end='') 

    try:
        for ip in IP(target):
            hosts.append(str(ip))
    except ValueError:
          print("Fail!!")
          print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Not valid network address.")
          return 1

    print("Ok!!")
    return 0

def readCgroup():

    warnings.simplefilter("ignore", ResourceWarning)
    global group
    config = configparser.ConfigParser()
    config.read_file(open(r'pySSHManager.conf'))
    group = config.get('config', 'group')

def checKS():
    global xpan
    terms = ['konsole','termite','xterm',
            'mate-terminal', 'gnome-terminal',
            'terminator']


    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Checking if xpanes is present in the system...", end='')
    try:
        xpan = (str(check_output(["/usr/bin/which",
                                     "xpanes"],
                                     universal_newlines=True,
                                     stderr=subprocess.PIPE))).split("\n")[0]
        print(" Ok!!")

    except subprocess.CalledProcessError:

         print()
         print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Unable to find xpanes. You need to install xpanes (https://github.com/greymd/tmux-xpanes/wiki/Installation).")
         exit(1)

    for termis in terms:

        print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Checking if " + termis + " terminal it's present in the system...", end='')
        try:
            check_output(["/usr/bin/which",
                            termis],
                            universal_newlines=True,
                                     stderr=subprocess.PIPE)
            print(" " + bcolors.OKGREEN + "Ok!" + bcolors.ENDC)

        except subprocess.CalledProcessError:
            print (" " + bcolors.FAIL + "NOT present." + bcolors.ENDC)

def readConfig():

    warnings.simplefilter("ignore", ResourceWarning)
    global hostfile
    global terminal
    global port
    global user
    global timeout
    
    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Reading the config file ...")
    config = configparser.ConfigParser()
    config.read_file(open(r'pySSHManager.conf'))
    terminal = config.get('config', 'terminal')
    hostfile = config.get('config', 'hostfile')
    port = config.get('config', 'port')
    user = config.get('config', 'user')
    timeout = config.get('config', 'timeout')


if __name__ == '__main__':

    warnings.simplefilter("ignore", ResourceWarning)
    hosts_present_hash = {}
    hosts_dns_hash = {}
    hosts_id_hash = {}
    hosts_group_hash = {}
    hosts_port_hash = {}
    hosts_net_hash = {}
    
    global chk
    global hosts
    global process
    global networks
    global groups
    process = []
    networks = []
    groups = []
    hosts = []
    chk = 1

    # Read the configuration file
    welcome()
    print(
        "[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Starting pySSHManager v0.2.0 (https://github.com/c0r3dump3d/pysshmanager) at " +
        time.strftime("%x") +
        " " +
        time.strftime("%X") +
        " - for legal purposes only.")
    print()
    
    checKS()
    readConfig()
    readCgroup()

    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Reading for previous host(s) ...")
    loadCSV()

    for ip in hosts_net_hash:
        if hosts_net_hash[ip] not in networks:
            networks.append(hosts_net_hash[ip])
            groups.append(hosts_group_hash[ip])

    our_history = FileHistory('.history-commands')
    numhost = 0
    session = PromptSession(history=our_history)
    options = WordCompleter(['scan','list','help','?',
        'connect','reset','search','delete','save','set','options',
        'networks','addnet','delnet','kill','procs'],ignore_case=True)

    while True:
        sync = 0
        readCgroup()
        table = BeautifulTable(max_width=100)
        table.default_alignment = BeautifulTable.ALIGN_CENTER
        table.width_exceed_policy = BeautifulTable.WEP_ELLIPSIS
        table.column_headers = ["ID", "IP", "PORT", "FQDN", "NETWORK", "GROUP"]
        answer = session.prompt('pysshmgr> ', completer=options,
                complete_style=CompleteStyle.READLINE_LIKE)
        if answer.split(" ")[0] == "scan":

            try:
                test = answer.split(" ")[1] 

            except IndexError:
                test = "none"
                pass

            if test == "all":
                k2 = 0
                hosts_present_hash = {}
                hosts_dns_hash = {}
                hosts_id_hash = {}
                hosts_net_hash = {}
                hosts_group_hash = {}
                for k in networks:
                    target = k
                    print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Scanning network " + target)
                    group = groups[k2]
                    delHostGroup(group)
                    k2 = k2 + 1
                    extracNet(target)
                    if chk != 0:
                        start_time = time.time()
                        check = connScan(hosts, port, group, target)
                        print(
                            "[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Scan finished in",
                            time.time() -
                            start_time,
                            "seconds.")
                        print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Updating hostfile.csv file ...")
                        os.remove('hostfile.csv')
                        writeCSV()
                        print(
                          "[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Some hosts were found ... (check with \'list\' command.)")

                    else:
                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] No host added.")

            else:
                showNetworks()
                try:
                    num = int(input("Choose network to scan: "))
                    num = num - 1
                    try:
                        target = networks[num]
                        group = groups[num]
                        delHostGroup(group)
                        extracNet(target)

                        if chk != 0:
                            start_time = time.time()
                            check = connScan(hosts, port, group,target)
                            print(
                                "[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Scan finished in",
                                time.time() -
                                start_time,
                                "seconds.")
                            print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Updating hostfile.csv file ...")
                            os.remove('hostfile.csv')
                            writeCSV()
                            print(
                            "[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Some hosts were found ... (check with \'list\' command.)")

                        else:
                            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] No host added.")

                    except IndexError:
                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Network number not found.")

                except ValueError:
                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Network number not found.")


        elif answer.split(" ")[0] == "list":

            showHOSTS()

        elif answer.split(" ")[0] == "addnet":
    
            try:
                if "/" not in answer.split(" ")[1]:

                    test=checkNet(answer.split(" ")[1])
                    if test == 0:
                        if ((answer.split(" ")[1]+"/32")) not in networks:
                            networks.append(answer.split(" ")[1]+"/32")
                            try:
                                groups.append(answer.split(" ")[2])
                                group = answer.split(" ")[2]

                            except IndexError:

                                groups.append(group)
                                pass
                        else:
                            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] We have seen this network before!")
                    else:
                        pass
                
                else:

                    test=checkNet(answer.split(" ")[1])
                    if test == 0:
                        if (answer.split(" ")[1]) not in networks:
                            networks.append(answer.split(" ")[1])
                            try:
                                groups.append(answer.split(" ")[2])
                                group = answer.split(" ")[2]

                            except IndexError:

                                groups.append(group)
                                pass
                        else:
                            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] We have seen this network before!")
                    else:
                        pass

            except IndexError:
                print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Please, you need to especified a network CIDR.")
                pass

        elif answer.split(" ")[0] == "delnet":

            showNetworks()
            num = int(input("Choose network to delete: "))
            num = num - 1

            try:
                searchDelete(networks[num])
                delNetwork(num)

            except IndexError:
                print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Invalid network number")

        elif answer.split(" ")[0] == "search":
            term = answer.split(" ")[1]
            searchALL(term)

        elif answer.split(" ")[0] == "connect":

            lastkey = list(hosts_id_hash.items())
            id = int(lastkey[-1][1])

            try:

                string = answer.split(" ")[1]
                hosts_connect = []

                if "-" in string:
                    try:
                        value1 = int(string.split("-")[0])
                        value2 = int(string.split("-")[1])
                    
                        if value1 <= int(id) and value2 <= int(id):
                            for i in list(range(value1, value2 + 1)):
                                for j in hosts_id_hash:
                                    if str(hosts_id_hash[j]) == str(i):
                                        ip = hosts_present_hash[j]
                                        hosts_connect.append(ip)
                                        table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                            hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                            str(hosts_net_hash[j]),str(hosts_group_hash[j])])
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
                            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Out of range.")

                    except ValueError:

                            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Value error.")

                elif "," in string:
                    lst = string.split(",")
                    stringcount = len(lst)
                    for value1 in lst:
                        try:
                            if int(value1) <= int(id):
                                for j in hosts_id_hash:
                                    if str(hosts_id_hash[j]) == str(value1):
                                        ip = hosts_present_hash[j]
                                        hosts_connect.append(ip)
                                        table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                            hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                            str(hosts_net_hash[j]), str(hosts_group_hash[j])])
                                        break
                            else:
                                print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] The host " + value1 + " doesn't exist.")

                        except ValueError:
                            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Value error.")

                    print(table)
                    message = "Are you sure to connect to this host(s)? (Y/n) "
                    action = yes_or_no(message)

                    if action:
                        connection(hosts_connect)
                        del table

                    else:
                        pass

                elif string.isdigit():
                    lastkey = list(hosts_id_hash.items())
                    id = int(lastkey[-1][1])
                    if int(string) <= int(id):
                        for j in hosts_id_hash:
                            if str(hosts_id_hash[j]) == str(string):
                                ip = hosts_present_hash[j]
                                hosts_connect.append(ip)
                                table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                    hosts_port_hash[j]), str(hosts_dns_hash[j]), str(hosts_net_hash[j]), str(hosts_group_hash[j])])
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
                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] This hosts doesn't exist.")

                else:
                    searchConnect(string)

            except IndexError:

                print ("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] You need to specified something ...") 
                pass 

                try:
                    if answer.split(" ")[2] == "sync":
                        sync = 1
                except BaseException:
                    pass

        elif answer.split(" ")[0] == "delete":
            lastkey = list(hosts_id_hash.items())
            id = int(lastkey[-1][1])
            string = answer.split(" ")[1]
            hosts_delete=[]
            if "-" in string:
                try:
                    value1 = int(string.split("-")[0])
                    value2 = int(string.split("-")[1])

                    if value1 <= int(id) and value2 <= int(id):

                        for i in list(range(value1, value2 + 1)):
                            for j in hosts_id_hash:
                                if str(hosts_id_hash[j]) == str(i):
                                    table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                        hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                        str(hosts_net_hash[j]), str(hosts_group_hash[j])])
                                    hosts_delete.append(j)
                                    break

                        print(table)
                        message = "Are you sure to delete this host(s)? (Y/n) "
                        action = yes_or_no(message)
                        if action:
                            deleteHosts(hosts_delete)
                            del table

                    else:
                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Out of range.")

                except ValueError:

                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Error value.")

            elif "," in string:
                lst = string.split(",")
                stringcount = len(lst)
                for value1 in lst:
                    if value1 <= int(id):
                        for j in hosts_id_hash:
                            if str(hosts_id_hash[j]) == str(value1):
                                table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                    hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                    str(hosts_net_hash[j]), str(hosts_group_hash[j])])
                                hosts_delete.append(j)
                                break

                    print(table)
                    message = "Are you sure to delete this host(s)? (Y/n) "
                    action = yes_or_no(message)
                    if action:
                        deleteHosts(hosts_delete)
                        del table

                    else:
                        print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] This hosts doesn't exist.")

            elif string.isdigit():

                if int(string) <= int(id):
                    for j in hosts_id_hash:
                        if str(hosts_id_hash[j]) == str(string):
                            table.append_row([hosts_id_hash[j], str(hosts_present_hash[j]), str(
                                hosts_port_hash[j]), str(hosts_dns_hash[j]),
                                str(hosts_net_hash[j]),str(hosts_group_hash[j])])
                            hosts_delete.append(j)
                            break
                    print(table)
                    message = "Are you sure to delete this host(s)? (Y/n) "
                    action = yes_or_no(message)
                    if action:
                        deleteHosts(hosts_delete)
                        del table
            
                else:
                    print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] This hosts doesn't exist.")

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
                hosts_net_hash = {}
                hosts_group_hash = {}
                networks[:] = []
                groups[:] = []
                loadCSV()
            else:
                pass

        elif answer.split(" ")[0] == "set":

            if answer.split(" ")[1] == "port":
                port = answer.split(" ")[2] 
                print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Port defined to vale {0}".format(port))

            elif answer.split(" ")[1] == "user":
                user = answer.split(" ")[2] 
                print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] User defined to vale {0}".format(user))

            elif answer.split(" ")[1] == "terminal":
                terminal = answer.split(" ")[2] 
                print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Terminal defined to vale {0}".format(terminal))

            elif answer.split(" ")[1] == "group":
                group = answer.split(" ")[2] 
                print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Default group defined to vale {0}".format(group))

            elif answer.split(" ")[1] == "default":
                readConfig()
                readCgroup()

            else:
                print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Option not defined.")


        elif answer.split(" ")[0] == "kill":
             
            if answer.split(" ")[1] == "all":
                killAll()

            elif answer.split(" ")[1].isdigit():
                pid = answer.split(" ")[1]
                killProc(pid)

            else:
                print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Command not found.")



        elif answer.split(" ")[0] == "procs":
            listProcs()

        elif answer.split(" ")[0] == "help":
            help()

        elif answer.split(" ")[0] == "?":
            help()

        elif answer.split(" ")[0] == "options":
            showValues()

        elif answer.split(" ")[0] == "networks":
            showNetworks()

        elif answer.split(" ")[0] == "save":
            print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Updating hostfile.csv file ...")
            os.remove('hostfile.csv')
            writeCSV()

        elif answer.split(" ")[0] == "exit":

            print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Updating hostfile.csv file ...")
            os.remove('hostfile.csv')
            writeCSV()

            print("[" + bcolors.OKGREEN+ "✓"+ bcolors.ENDC+"] Have a nice day !!")
            exit(0)

        elif answer.split(" ")[0] == "":
            pass

        else:
            print("[" + bcolors.FAIL + "✗" + bcolors.ENDC + "] Command not found.")

