import argparse
import getpass
import json
import os
import subprocess
import time

from colorama import init, Fore, Style
from napalm import get_network_driver
from netmiko import ConnectHandler

debug = True
proctor_list = ['81.109.160.116', '184.71.54.118']
exception_list = ['Dialer']

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

def ssh(ip, creds, command):
    output = ""
    try:
        net_connect = ConnectHandler(device_type='cisco_ios', ip=ip, username=creds[0], password=creds[1])
        output = net_connect.send_command(command)
        net_connect.disconnect()
    except Exception as e:
        pprint(str(e), "error")
    return output

def get_info(host, credent, ipadd, ipaddnochg, summary):
    #####GET INFO FOR THE NO DIRECTLY CONNECTED#####
    flag = 0
    flaggy = 0
    skip = 0
    output = ssh(host, credent, 'show run | i {}'.format(ipadd))
    pprint('\nshow run | i ' + ipadd + '\n\n' + str(output), 'output')
    array = output.splitlines()
    ####CHECKING WHETHER THE INTERFACE IS SHUTDOWN AND EXTRACT INFO FROM DESCRIPTION####
    for x in array :
        if 'shutdown' not in x:
            if 'description' in x:
                outpt = x.split()
                flag = 1
        else:
            pprint('\n\nLink is shutdown','output')

    if flag == 1:
        ####CHECKING THE INTERFACE IS NOT MONITORED####
        for x in outpt:
            if 'NOTMONITORED' in x:
                pprint('\n\nLink is NOT MONITORED', 'output')
                flaggy = 1
                skip = 2
        if flaggy == 0:
            ####TO CHECK THE AND COMPARE THE DESCRIPTION OBTAINED WITH *SHOW INT DESC*####
            name = outpt[3]
            output = ssh(host, credent, 'show int desc')
            pprint('\nshow int description\n\n' + str(output), 'output')
            array = output.splitlines()
            for m in array:
                if name in m:
                    source = m.split()[0]
                    skip = 1
        if skip == 1:
            if 'Tu' in source:
                tunnel_check(host, credent, source, ipaddnochg, summary)
            else:
                bsc_check(host, credent, source, ipaddnochg, summary)
        if skip == 0:
            pprint('\n\nNot found in "show int description"\n')


def proctor_check(host, credent, ipadd, ipaddnochg, summary):
    flag = 0
    output = ssh(host, credent, 'show run | i {}'.format(ipadd))
    pprint('\nshow run | i ' + ipadd + '\n\n' + str(output), 'output')
    array = output.splitlines()
    for x in array:
        if 'ip route' in x:
            store = x.split()[4]
            flag = 1

    if flag == 1:
        bgp_down(host, credent, store, ipaddnochg, summary)
    else:
        get_info(host, credent, store, ipaddnochg, summary)

def tunnel_check(host, credent, source, ipaddnochg, summary):
    ######THIS METHOD IS USED WHEN THE BGP IS CONNECTED TO A TUNNEL#####
    if "Tu" in source:
        output = ssh(host, credent, 'show int {}'.format(source))
        pprint('\nshow int ' + source + '\n\n' + str(output), 'output')
        array = output.splitlines()
        summ1 = 'Tunnel is ( ' + array[0] + ')'
        summary.append(summ1)
        output = ssh(host, credent, 'show run int {}'.format(source))
        pprint('\nshow run int ' + source + '\n\n' + str(output), 'output')
        array = output.splitlines()
        ####TO EXTRACT PHYSICAL INTERFACE####
        for x in array:
            if 'tunnel source' in x:
                print('test')
                output = x.split()
                intt = output[2]
                bsc_check(host, credent, intt, ipaddnochg, summary)

    else:
        bsc_check(host, credent, source, ipaddnochg, summary)


def bsc_check(host, credent, source, ipaddnochg, summary):
    ######TO DO ALL BASIC CHECKS######
    skip = 0
    count_down = 0
    count_up = 0
    check = 0
    ip_check = 0
    summ2 = ''
    output = ssh(host, credent, 'show int {}'.format(source))
    pprint('\nshow int ' + source + '\n\n' + str(output), 'output')
    array = output.splitlines()
    summ1 = 'Link is ( ' + array[0] + ')'
    summary.append(summ1)

    output = ssh(host, credent, 'show run int {}'.format(source))
    pprint('\nshow run int ' + source + '\n\n' + str(output), 'output')
    array = output.splitlines()
    if any(name in source for name in exception_list):
        skip = 0
    else:
        for x in array:
            ####TO EXTRACT THE IP ADDRESS####
            if 'ip address' in x:
                if 'dhcp' not in x:
                    tempout = x.split()
                    newipadd = tempout[2]
                    ip_check = 1
                # print(newipadd)
            ####TO EXTRACT VRF INFORMATION####
            if 'ip vrf forwarding' in x:
                output = x
                array = output.split()
                vrf = array[3]
                skip = 1
        if skip == 1:
            output = ssh(host, credent, 'ping vrf ' + vrf + ' ' + newipadd)
            pprint('\nping vrf ' + vrf + ' ' + newipadd + '\n\n' + str(output), 'output')
        else:
            if ip_check == 1:
                output = ssh(host, credent, 'ping {}'.format(newipadd))
                pprint('\nping ' + newipadd + '\n\n' + str(output), 'output')

    output = ssh(host, credent, 'ping {}'.format(ipaddnochg))
    pprint('\nping ' + ipaddnochg + '\n\n' + str(output), 'output')

    output = ssh(host, credent, 'show log | i {}'.format(ipaddnochg))
    pprint('\nshow log | i ' + ipaddnochg + '\n\n' + str(output), 'output')
    array = output.splitlines()
    if not len(array) == 0:
        testing = array[len(array) - 1].split()
        current_month = testing[0]
        current_day = testing[1]
    for x in array:
        if 'Down' in x and ipaddnochg in x:
            tem = x.split()
            summ2 = 'BGP went down on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
            if check == 1:
                if current_day in tem and current_month in tem:
                    count_down = count_down + 1
        if 'Up' in x and ipaddnochg in x:
            tem = x.split()
            summ2 = 'BGP came up on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
            if check == 1:
                if current_day in tem and current_month in tem:
                    count_up = count_up + 1

    output = ssh(host, credent, 'show clock')
    pprint('\nshow clock\n\n' + str(output), 'output')
    summary.append(summ2)
    if count_down > 6 or count_up > 6:
        summ = 'The link ' + ipaddnochg + ' is flapping'
        summary.append(summ)
    return summary


def bgp_down(host, credent, ipadd, ipaddnochg, summary):
    ######THIS METHOD IS USED WHEN THERE IS BGP DOWN######)
    flag = 0
    output = ssh(host, credent, 'show ip route {}'.format(ipadd))
    pprint('\nshow ip route ' + ipadd + '\n\n' + str(output), 'output')
    array = output.splitlines()
    ####TO CHECK WHETHER THE DIRECTLY CONNECTED HAS PHYSICAL INTERFACE CONNECTED####
    for x in array:
        if "directly connected" in x:
            output = x
            array = output.split(" ")
            source = array[6]
            flag = 1

    if flag == 1:
        tunnel_check(host, credent, source, ipaddnochg, summary)
    else:
        get_info(host, credent, ipadd, ipaddnochg, summary)


def no_bgp_down(host, credent, ip_recent_up, summary):
    ######THIS METHOD IS USED WHEN THERE IS NO BGP DOWN######
    count_down = 0
    count_up = 0
    check = 0
    output = ssh(host, credent, 'show log | i {}'.format(ip_recent_up))
    pprint('\nshow log | i '+ip_recent_up+'\n\n' + str(output), 'output')
    array = output.splitlines()
    if not len(array) == 0:
        testing = array[len(array)-1].split()
        current_month = testing [0]
        current_day = testing [1]
        check = 1
    for x in array:
        if 'Down' in x and ip_recent_up in x:
            tem = x.split()
            summ1 = 'Link went down on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
            if check == 1:
                if current_day in tem and current_month in tem:
                    count_down = count_down + 1
        if 'Up' in x and ip_recent_up in x:
            tem = x.split()
            summ1 = 'BGP came up on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
            if check == 1:
                if current_day in tem and current_month in tem:
                    count_up = count_up + 1

    summary.append(summ1)
    output = ssh(host, credent, 'show clock')
    pprint('\nshow clock\n\n' + str(output), 'output')
    if count_down > 6 or count_up > 6:
        summ = 'The link ' + ip_recent_up + ' is flapping'
        summary.append(summ)


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
        driver = get_network_driver('ios')
        pprint('connecting to {}..'.format(host))
        try:
            device = driver(host, username, password)
            device.open()
            credent = [username, password]
            if debug:
                count = 0
                counting = 0
                ct = 0
                array1 = []
                summary = []
                summary_final = ''
                bgp_ip = input("Peer IP (Enter '-' for automatic processing): ")
                if '-' not in bgp_ip:
                    output = ssh(host, credent, 'show ip bgp summary | i {}'.format(bgp_ip))
                    pprint('\nshow ip bgp summary | i '+bgp_ip+'\n\n' + str(output), 'output')
                    array = output.split()
                    for m in array:
                        if 'Idle' in m or 'Active' in m:
                            if "(Admin)" not in m:
                                summary.append('BGP peer ' + bgp_ip + ' is down')
                                count = 1
                    if count == 0:
                        summary.append('BGP peer '+bgp_ip+' is up for '+array[8])

                    bgp_down(host, credent, bgp_ip, bgp_ip, summary)

                else:
                    output = ssh(host, credent, 'show ip bgp summary')
                    pprint('\nshow ip bgp summary\n\n'+str(output), 'output')
                    array = output.splitlines()

                    ####TO EXTRACT IP THAT JUST CAME UP WHEN ALL BGP IS UP####
                    i = 0
                    for x in array:
                        i = i + 1
                        if 'Up/Down' in x:
                            num = i

                    while num < len(array):
                        array1.append(array[num])
                        num = num+1

                    for y in array1:
                        # if not any(ip in y for ip in proctor_list):
                            w = y.split()
                            if 'y' not in w[8] or 'w' not in w[8] or 'd' not in w[8] or 'h' not in w[8]:
                                ip_recent_up = w[0]
                                time_up = w[8]

                    ####TO CHECK WHICH BGP PEERING IS DOWN####
                    for m in array:
                        if 'Idle' in m or 'Active' in m:
                            if "(Admin)" not in m:
                                count = 1

                    if count == 1:

                        output = ssh(host, credent, 'show ip bgp summary | i Idle|Active')
                        pprint(str(output), 'debug')
                        array = output.splitlines()
                        not_p = ''

                        for x in array:
                            if not any(ip in x for ip in proctor_list):
                                if "(Admin)" not in x:
                                    not_p = x.split()[0]
                                    ipadd = not_p
                                    ipaddnochg = not_p
                                    summary.append('BGP peer ' + ipaddnochg + ' is down')
                                    bgp_down(host, credent, ipadd, ipaddnochg, summary)
                                    counting = 1
                        #####PROCTOR CHECKS#####
                        if counting == 0:
                            addr = array[0].split()[0]
                            proctor_check(host, credent, addr, addr, summary)
                            addr = array[1].split()[0]
                            proctor_check(host, credent, addr, addr, summary)


                    if count ==0 :
                        summary.append('All BGP is up')
                        summary.append('BGP Peer '+ip_recent_up+' is up for '+ time_up)
                        no_bgp_down(host, credent, ip_recent_up, summary)

                pprint("\n\n##### SUMMARY #####\n")
                b = 0
                while b < len(summary):
                    summary_final = summary_final + summary[b] + '\n'
                    b= b+1

                print(summary_final)
                print()
                print('###################')

        except Exception as e:
            pprint(str(e), 'error')


if __name__ == '__main__':
    try:
        init()
        parser = argparse.ArgumentParser(description="Script to be used by EMC Analyst handling 'BGP DOWN' Tickets")
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
