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

def tunnel(host, credent, interface):
    ######THIS METHOD IS FOR TUNNEL LINK######
    output = ssh(host, credent, 'show int {}'.format(interface))
    pprint('\nshow int ' + interface + '\n\n' + str(output), 'output')

    output = ssh(host, credent, 'show run int {}'.format(interface))
    pprint('\nshow run int ' + interface + '\n\n' + str(output), 'output')
    array = output.splitlines()
    for x in array:
        if 'tunnel source' in x:
            output = x.split()
            test = output[2]

    return test

def contr(host, credent, interface):
    ######THIS METHOD IS FOR CONTROLLER LINK######
    output = ssh(host, credent, 'show controller {} brief'.format(interface))
    pprint('\nshow controller '+interface+' brief\n\n' + str(output), 'output')
    array = output.split()
    temp = array[1]

    output = ssh(host, credent, 'show run | i {}'.format(temp))
    pprint('\nshow run | i ' + temp + '\n\n' + str(output), 'output')
    array = output.splitlines()
    for x in array:
        if 'interface' in x:
            output = x
            array = output.split()
            test = array[1]

    return test

def multi(host, credent, interface):
    ######THIS METHOD IS FOR MULTILINK LINK######
    output = ssh(host, credent, 'show ppp multilink')
    pprint('\nshow ppp multilink\n\n' + str(output), 'output')
    array = output.splitlines()
    for x in array:
        if '(Active)' in x:
            output = x.split()
            test = output[0]

    return test

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
                flag = 0
                check = 0
                count_up = 0
                count_down = 0
                nstr = ''
                summ = ''
                interface = input ("Interface: ")
                ret_int = interface
                newstr = ''.join((ch if ch in '0123456789/.' else '')for ch in ret_int)
                ###IF THE INTERFACE IS CONTROLLER###
                if 'E1' in interface or 'E3' in interface or 'T1' in interface:
                    temp = interface.split()[1]
                    ret_int = contr(host, credent, interface)
                ###IF THE INTERFACE IS MULTILINK###
                if 'Mu' in interface:
                    ret_int = multi(host, credent, interface)
                ###IF THE INTERFACE IS TUNNEL###
                if 'Tu' in interface:
                    ret_int = tunnel(host, credent, interface)

                ####BASIC CHECKS####
                output = ssh(host, credent, 'show int {}'.format(ret_int))
                pprint('\nshow int ' + ret_int + '\n\n' + str(output), 'output')
                array = output.splitlines()
                summ1 = 'Link is ( ' + array[0] + ')'

                output = ssh(host, credent, 'show run int {}'.format(ret_int))
                pprint('\nshow run int ' + ret_int + '\n\n' + str(output), 'output')
                array = output.splitlines()
                ####IF THE PHYSICAL INTERFACE IS INTEGRATED IN MULTILINK####
                for x in array:
                    if 'ppp multilink' in x:
                        flag = 1
                if flag == 1:
                    output = ssh(host, credent, 'show ppp multilink')
                    pprint('\nshow ppp multilink\n\n' + str(output), 'output')
                ####ONLY WILL BE PERFORMED WHEN IT IS A ROUTER####
                if 'cs.mgmt.slb.net' in host:
                    output = ssh(host, credent, 'show ip bgp summary')
                    pprint('\nshow ip bgp summary\n\n' + str(output), 'output')

                if 'E1' in interface or 'E3' in interface or 'T1' in interface:
                    output = ssh(host, credent, 'show log | i {}'.format(temp))
                    pprint('\nshow log | i ' + temp + '\n\n' + str(output), 'output')
                    array = output.splitlines()
                    if not len(array) == 0:
                        testing = array[len(array) - 1].split()
                        current_month = testing[0]
                        current_day = testing[1]
                    for x in array:
                        if 'down' in x and temp in x:
                            tem = x.split()
                            if '00' in tem[0]:
                                nstr = 'Link last came up on ' + tem[1] + ' ' + tem[2] + ' at ' + tem[3]
                            else:
                                nstr = 'Link last came up on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
                            if check == 1:
                                if current_day in tem and current_month in tem:
                                    count_down = count_down + 1
                        if 'up' in x and temp in x:
                            tem = x.split()
                            if '00' in tem[0]:
                                nstr = 'Link last came up on ' + tem[1] + ' ' + tem[2] + ' at ' + tem[3]
                            else:
                                nstr = 'Link last came up on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
                            if check == 1:
                                if current_day in tem and current_month in tem:
                                    count_up = count_up + 1
                else:
                    output = ssh(host, credent, 'show log | i {}'.format(newstr))
                    pprint('\nshow log | i ' + newstr + '\n\n' + str(output), 'output')
                    array = output.splitlines()
                    if not len(array) == 0:
                        testing = array[len(array) - 1].split()
                        current_month = testing[0]
                        current_day = testing[1]
                        check = 1
                    for x in array :
                        if 'down' in x and newstr in x:
                            tem = x.split()
                            if '00' in tem[0]:
                                nstr = 'Link last came up on ' + tem[1] + ' ' + tem[2] + ' at ' + tem[3]
                            else:
                                nstr = 'Link last came up on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
                            if check == 1:
                                if current_day in tem and current_month in tem:
                                    count_down = count_down + 1
                        if 'up' in x and newstr in x:
                            tem = x.split()
                            if '00' in tem[0]:
                                nstr = 'Link last came up on ' + tem[1] + ' ' + tem[2] + ' at ' + tem[3]
                            else:
                                nstr = 'Link last came up on ' + tem[0] + ' ' + tem[1] + ' at ' + tem[2]
                            if check == 1:
                                if current_day in tem and current_month in tem:
                                    count_up = count_up + 1

                output = ssh(host, credent, 'show clock')
                pprint('\nshow clock\n\n' + str(output), 'output')

                if count_down > 6 or count_up > 6:
                    summ = 'The link '+ret_int+' is flapping'

                pprint("\n\n##### SUMMARY #####\n")
                print(summ1)
                print(nstr)
                print(summ)
                print()
                print('###################')

        except Exception as e:
            pprint(str(e), 'error')


if __name__ == '__main__':
    try:
        init()
        parser = argparse.ArgumentParser(description="Script to be used by EMC Analyst handling 'BAD LINK DETECTED' Tickets")
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