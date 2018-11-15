import argparse
import getpass
import json
import os
import subprocess
import time
import sys
import ipdb

from colorama import init, Fore, Style
from napalm import get_network_driver
from netmiko import ConnectHandler

debug = True

telco = ['vf','telefonica', '-dc']

def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            pprint('ran for %2.2f ms' % ((te - ts) * 1000), 'info')
        return result

    return timed


def display_time(seconds, granularity=5):
    result = []
    intervals = (
        ('weeks', 604800),
        ('days', 86400),
        ('hours', 3600),
        ('minutes', 60),
        ('seconds', 1),
    )
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{} {}".format(value, name))
    return ', '.join(result[:granularity])


def coloured(content, colour='blue'):
    if colour == 'green':
        return '{}{}{}{}'.format(Fore.GREEN, Style.BRIGHT, content, Style.RESET_ALL)
    elif colour == 'red':
        return '{}{}{}{}'.format(Fore.RED, Style.BRIGHT, content, Style.RESET_ALL)
    else:
        return '{}{}{}{}'.format(Fore.CYAN, Style.BRIGHT, content, Style.RESET_ALL)


def pprint(content, level="info", debug_header=""):
    if type(content) is dict:
        content = json.dumps(content, indent=3, sort_keys=True)
    if level == "info":
        print('[{}{}info{}] {}'.format(Fore.CYAN, Style.BRIGHT, Style.RESET_ALL, content))
    elif level == "error":
        print('\n[{}{}error{}] {}'.format(Fore.RED, Style.BRIGHT, Style.RESET_ALL, content))
    elif level == "output":
        print('[{}{}output{}] {}'.format(Fore.GREEN, Style.BRIGHT, Style.RESET_ALL, content))
    elif level == "debug":
        print(
            '\n[{}{}debug{}] {}\n{}\n[{}{}debug{}]\n'.format(
                Fore.YELLOW, Style.BRIGHT, Style.RESET_ALL, debug_header, content, Fore.YELLOW,
                Style.BRIGHT, Style.RESET_ALL))
    else:
        print(content)


def run_shell(command):
    return subprocess.call(command)

def ssh_nsa(command):
    output = ""
    try:
        print (command)
        net_connect = ConnectHandler(device_type='linux', ip='163.185.18.93', username='omneswan', password='MujHe3!a')
        output = net_connect.send_command(command)
        net_connect.disconnect()
    except Exception as e:
        pprint(str(e), "error")
    return output
def ssh(ip, creds, command):
    output = ""
    try:
        net_connect = ConnectHandler(device_type='cisco_ios', ip=ip, username=creds[0], password=creds[1])
        output = net_connect.send_command(command)
        net_connect.disconnect()
    except Exception as e:
        pprint(str(e), "error")
    return output

def last_reach1(host, name, ipaddr, credent):
    ######THIS METHOD IS FOR LOGS FROM THE ACTIVE ROUTER######

    output = ssh(name, credent, 'show ip arp | i {}'.format(ipaddr))
    pprint('\nshow ip arp | i ' + ipaddr + '\n\n' + str(output), 'output')

    output = ssh(name, credent, 'clear arp')
    pprint('\nclear arp\n\n' + str(output), 'output')

    output = ssh(name, credent, 'ping {}'.format(host))
    pprint('\nping ' + host + '\n\n' + str(output), 'output')

    output = ssh(name, credent, 'show ip arp | i {}'.format(ipaddr))
    pprint('\nshow ip arp | i ' + ipaddr + '\n\n' + str(output), 'output')

    output = ssh(name, credent, 'show clock')
    pprint('\nshow clock\n\n' + str(output), 'output')


def last_reach(host, name, ipaddr,number, credent):
    ######THIS METHOD IS FOR LAST REACH OF LAN DOWN######
    i = 0
    f = 0
    k = 0
    j = 0
    stop = 0
    switch = 0
    output = ssh(name, credent, 'show cdp neighbors')
    pprint('\nshow cdp neighbors\n\n' + str(output), 'output')
    array = output.splitlines()

    for x in array:
        if  host in x:
            num = i
            j = 1
            p = array[num + 1].split()
            newstr = str(p[0] + p[1])
        else:
            j = 0
        i = i + 1

    if j==1:
        output = ssh(name, credent, 'show int {}'.format(newstr))
        pprint('\nshow int '+newstr+'\n\n' + str(output), 'output')
        output = ssh(name, credent, 'show run int {}'.format(newstr))
        pprint('\nshow run int ' + newstr + '\n\n' + str(output), 'output')
    output_test = ssh(name, credent, 'show version | i up')
    test = output_test.split()
    get_name = test[0]
    if '-cs' not in get_name:
        file = open("pings.txt", mode='r')
        array = file.read().splitlines()
        while number >=0:
            if stop == 0:
                if '-cs' in array[number]:
                    router_num = number
                    stop = 1
            number = number - 1

        outp = array[router_num]
        file.close()

        array1 = outp.split()
        cs_name = array1[7]


        last_reach1(host,cs_name, ipaddr, credent)
    else:
        last_reach1(host, name, ipaddr, credent)



def check_ping_LAN(host, credent):
    ######THIS METHOD IS FOR SWITCH (LAN) DOWN######
    res_print = run_shell("ping {}".format(host))
    res1_print = run_shell("tracert -w 600 {}".format(host))
    print()
    testing = ipdb.set_trace()
    print(testing)
    pprint('Hold On... Gathering Information...\n')
    response = os.system("ping {} >pings.txt".format(host))
    response1 = os.system("tracert -h 20 {} >>pings.txt".format(host))
    j = 0
    k = 0
    i = 0
    end = 0
    counting = 0
    file = open("pings.txt", mode='r')
    array = file.read().splitlines()
    for x in array:

        if 'Destination host unreachable' in x or 'Request timed out' in x:
            j = 1
        if 'Ping statistics for' in x:
            ipadd = x
        if k == 0:
            if '*        *        *     Request timed out.' in x:
                counting = counting + 1
                if counting == 3:
                    num = i - 2
                    num = num -1
                    k = 1
            else:
                counting = 0
        i = i + 1

    if j == 1:
        output = ssh_nsa('ping -c 5 {}'.format(host))
        pprint('\nPinging from NSA\n\n'+ str(output), 'output')
        output = ssh_nsa('traceroute -m 18 {}'.format(host))
        pprint('\nTracing from NSA\n\n'+ str(output), 'output')
        if any(word in array[num] for word in telco):
            end = 1
            pprint('Check for WAN outage', 'debug')
        else:
            if '.slb.net' in array[num]:
                outp = array[num]
            else:
                end = 1
            file.close()
            if end == 0:
                array = outp.split()
                name1 = array[8]
                name = ''.join((ch if ch in '0123456789.' else '') for ch in name1)

                ipaddr = ipadd.split()[3]
                newipadd = ''.join((ch if ch in '0123456789.' else '') for ch in ipaddr)

                last_reach(host, name, newipadd, num, credent)


        pingstatus = "Device is Unreachable!!!"
    else:
        output = ssh_nsa('ping -c 5 {}'.format(host))
        pprint('\n'+ str(output), 'output')
        output = ssh_nsa('traceroute -m 18 {}'.format(host))
        pprint('\n'+ str(output), 'output')
        output = ssh(host, credent, 'show version | i up')
        pprint('\nshow version | i up\n\n' + str(output), 'output')
        output = ssh(host, credent, 'show ip bgp summary')
        pprint('\nshow ip bgp summary\n\n' + str(output), 'output')
        output = ssh(host, credent, 'show clock')
        pprint('\nshow clock\n\n' + str(output), 'output')
        pingstatus = "Device is Reachable!!!"

    return pingstatus



def check_ping(host, credent):
    ######THIS METHOD IS FOR ROUTER (WAN) DOWN######
    res_print = run_shell("ping {}".format(host))
    res1_print = run_shell("tracert -w 600 {}".format(host))
    print()
    pprint('Hold On... Gathering Information...\n')
    response = os.system("ping {} >pings.txt".format(host))
    response1 = os.system("tracert -h 15 {} >>pings.txt".format(host))
    file = open("pings.txt", mode='r')
    array = file.read().splitlines()
    j = 0
    for x in array:

        if 'Destination host unreachable' in x or 'Request timed out' in x:
            j = 1

    file.close()
    if j == 0:
        output = ssh_nsa('ping -c 5 {}'.format(host))
        pprint('\nPing from NSA\n\n'+ str(output), 'output')
        output = ssh_nsa('traceroute -m 18 {}'.format(host))
        pprint('\nTrace from NSA\n\n'+ str(output), 'output')

        output = ssh(host, credent, 'show version | i up'.format(host))
        pprint('\nshow version | i up\n\n' + str(output), 'output')
        output = ssh(host, credent, 'show ip bgp summary'.format(host))
        pprint('\nshow ip bgp summary\n\n' + str(output), 'output')
        output = ssh(host, credent, 'show clock')
        pprint('\nshow clock\n\n' + str(output), 'output')
        pingstatus = "Device is Reachable!!!"
    else:
        output = ssh_nsa('ping -c 5 {}'.format(host))
        pprint('\n'+ str(output), 'output')
        output = ssh_nsa('traceroute -m 18 {}'.format(host))
        pprint('\n'+ str(output), 'output')
        pingstatus = "Device is Unreachable!!!"

    return pingstatus
@timeit
def main(args):
    if os.environ.get('scriptldap') is not None:
        pprint("using env set credentials {}".format(os.environ.get('scriptldap')))
        username = os.environ.get('scriptldap')
        password = os.environ.get('scripttacacspass')
    else:
        username = input("Username: ")
        password = getpass.getpass("Password: ")
    for host in args.hostname:
        #driver = get_network_driver('ios')
        #pprint('connecting to {}..'.format(host))
        credent = [username, password]
        try:
            if debug:
                # name = 'om0030-core-sw1.mgmt.slb.net'
                # last_reach(host, name, '172.30.195.19', 20)
                pprint('Pinging and tracing {}... Please Wait...'.format(host))
                if 'cs.mgmt.slb.net' not in host:
                    output = check_ping_LAN(host, credent)
                else:
                    output = check_ping(host, credent)
                pprint(str(output), 'debug')



        except Exception as e:
            pprint(str(e), 'error')

if __name__ == '__main__':
    try:
        init()
        parser = argparse.ArgumentParser(description="Script to be used by EMC Analyst handling 'DEVICE NOT RESPONDING' Tickets")
        parser.add_argument("hostname", nargs='+', help="Device hostname")
        parser.add_argument("--debug", help="Enable Debug, will show API call details", action='store_true',
                            default=False)
        args = parser.parse_args()
        debug = args.debug
        main(args)
    except KeyboardInterrupt:
        print("\n")
        pprint("user cancel (Ctrl+C) received, exiting..", "info")
    except Exception as e:
        pprint(str(e), "error")
    print("\n\n")
