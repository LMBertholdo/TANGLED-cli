#!/usr/bin/env python
# coding: utf-8
###############################################################################
# Testbed CLI - interface for exabgpcli
# Apr Fri 24 21:51:33 BST 2020
# @copyright sand-project.nl - Joao Ceron - ceron@botlog.org
# @copyright paaddos.nl - Leandro Bertholdo - leandro.bertholdo@gmail.com
###############################################################################
# 24Apr20 v0.20 - Included br-gru-anycast01
# 01Aug20 v0.21 - Included nl-ams-anycast01
###############################################################################

###############################################################################
### Python modules
import paramiko
import re
from argparse import RawTextHelpFormatter
import logging
import os
import sys
import argparse
from os import linesep
#import imp
import importlib
###############################################################################
### Program settings

verbose = False
version = 0.19
program_name = sys.argv[0][:-3]

### TESTBED NODES
nodes = {
          "au-syd-anycast01" : "108.61.185.44",
          "br-gru-anycast01" : "200.136.41.30",
          "br-poa-anycast01" : "177.184.254.162",
          "dk-cop-anycast01" : "193.163.102.207",
          "fr-par-anycast01" : "45.32.151.68",
          "jp-hnd-anycast01" : "203.178.148.30",
          "nl-arn-anycast01" : "193.176.144.173",
          "nl-ens-anycast02" : "192.87.172.193",
          "nl-ams-anycast01" : "136.244.104.73",
          "uk-lnd-anycast02" : "108.61.172.212",
          "us-mia-anycast01" : "198.32.252.97",
          "us-was-anycast01" : "128.9.63.135",
          "us-los-anycast01" : "128.9.160.80",
}

###############################################################################
### Subrotines

#------------------------------------------------------------------------------
def connect(node):
    """ create the handler to connect to the SSH sections
        :param: 
                node - string that is mapped to an IP address
    """

    user  = args.user
    ip = nodes.get(node)
    if not ip:
        print ("node: {}, not found!".format(node))
        print ("check available nodes")
     
    key = args.key
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=user)

    except Exception as inst:
        print ("Could not connect in node {}".format(node.upper()))
        print ("Ignoring node {}".format(node.upper()))
        print(inst)   
        return (None)

    return (ssh)

#------------------------------------------------------------------------------
def run_cmd(node,cmd):
    """ Run a cmd using the stablished SSH session
        param node: name (string) that represent the node (see dic)
        return: array of lines
    """

    ssh = connect(node)
    if (not ssh):
        return (None)

    shell = ssh.invoke_shell()
    shell.settimeout(3)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    opt = stdout.readlines()
    ssh.close()
    return(opt)

#------------------------------------------------------------------------------
def parse_routes(output):
    """ Parse the output from the command show neighbor adj-out
        param: output
        return: dictionary of peer and respective status
    """ 
    peer = []
    status = []
    for line in (output):
        route_search = re.search('neighbor\s+(.*)\s+local-ip+.*in-open ipv\d\sunicast\s+(.*)', line, re.IGNORECASE)
        result = {
            "ip": route_search.group(1),
            "cmd" : "withdraw route "+route_search.group(2)
        }
        peer.append(result)

    return (peer)

#------------------------------------------------------------------------------
def parse_peers(output):
    """ Parse the output from the command show neighbor summary
        param: output
        return: dictionary of peer and respective status
    """ 
    peer = []
    status = []
    
    # ignore first line
    output = output[1:]
    for line in (output):
        status = re.findall(r"established", line)
        if not status:
            status.append("\033[1mnot established\033[0m")
        result = {
            "ip": line.split()[0],
            "status" : status[0],
        }
        peer.append(result)

    return (peer)

#------------------------------------------------------------------------------
def set_log_level(log_level=logging.INFO):
    """Sets the log level of the notebook. Per default this is 'INFO' but
    can be changed.
    :param level: level to be passed to logging (defaults to 'INFO')
    :type level: str
    """
    imp.reload(logging)
    logging.basicConfig(
            level=log_level,
            format='%(asctime)s.%(msecs)03d %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
    )

    
#------------------------------------------------------------------------------
def parser_args ():

    #parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]', formatter_class=RawTextHelpFormatter)
    parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]')
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-d","--debug", help="print debug messages", action="store_true")
    parser.add_argument("-v", help="print verbose messages", action="store_true",dest="verbose")
    parser.add_argument("-4", help="working on IPv4 neighbor", action="store_true",dest="v4")
    parser.add_argument("-6", help="working on IPv6 neighbor", action="store_true",dest="v6")
    parser.add_argument("--status", help="status of neighbor", action="store_true")
    parser.add_argument("--csv", help="CSV output", action="store_true")
    parser.add_argument("-a","--announces", help="active announces", action="store_true")
    parser.add_argument('-t','--target', nargs='?', help="target [node|all]")
    parser.add_argument('-c','--cmd', nargs='?', help="cmd to be executed")
    parser.add_argument('-A', help="add specific route to peers",action="store_true",dest="add")
    parser.add_argument('-P', nargs='?', help="number of prepends",dest="prepend")
    parser.add_argument('-r', nargs='?', help="BGP route to be added",dest="route")
    parser.add_argument('--key', nargs='?', help="SSH key present on the testbed",dest="key", default= "~/.ssh/id_ed25519")
    parser.add_argument('--user', nargs='?', help="SSH user used to login on the testbed",dest="user", default="testbed")
    parser.add_argument("-w", help="withdraw all routes for that peer", action="store_true",dest="withdraw")
    parser.add_argument("--nodes-with-announces", help="list the name of nodes with active prefix announcement", action="store_true",dest="listnodesannounce")
    return parser

#------------------------------------------------------------------------------
# check parameters
def evaluate_args():
    parser = parser_args()
    args = parser.parse_args()

    if (args.debug):
        set_log_level('DEBUG')
        logging.debug(args)

    if (args.verbose):
        set_log_level()
        logging.debug(args)

    if (args.version):
        print (version)
        sys.exit(0)

    # you should provide the route to be add
    if (args.add and not args.route):
        print ("you should specify the route: ex. 145.100.118.0/23")
        parser.print_help()
        sys.exit(0)

    if (args.status or args.announces or args.withdraw or args.add or args.listnodesannounce):
        # for status assume target = all as default
        if (not args.target):
            args.target = "all" 

    # run cmd
    elif (not args.cmd):
        print ("you should enter the exabgp cmd to be executed in the exabgpcli")
        print ("neighbor 193.176.144.162 announce route 145.90.8.0/24 next-hop self community 100:667")
        parser.print_help()
        sys.exit(0)

    # check target node
    if (not args.target):
        parser.print_help()
        print ("you should enter the target [all|node]")
        print ("\t available nodes: {}".format(list(nodes.keys())))
        sys.exit(0)
    else:

        if (args.target == "all"):
            args.target = list(nodes.keys())
            logging.debug(args.target)
        else:
            for node in list(nodes.keys()):
                if (args.target==node):
                    args.target = node.split()
                    return (args)
            parser.print_help()
            print ("you should enter the target [node]")
            print ("\t available nodes: {}".format(list(nodes.keys())))
            sys.exit(0)
    return (args)

###############################################################################
### Main Process

try:
    available_nodes = list(nodes.keys())
    args = evaluate_args()
    logging.debug(args)
    
    if (args.status):
        # check status
        
        for node in args.target:
            #print ("working on {}".format(node))
            cmd = "exabgpcli show neighbor summary"
            output = run_cmd(node,cmd)
            if (not output):
                continue;
            output = parse_peers(output)
            logging.debug(output)
            #print ("#testbed node: {}".format(node.upper()))
            for neighbor in output:
                #print ("\t{} - {} - {} ".format(node, neighbor['ip'], neighbor['status']))
                print ("{},{},{}".format(node, neighbor['ip'], neighbor['status']))
    
    elif (args.withdraw):
    
        for node in args.target:
            cmd = " exabgpcli show adj-rib out extensive"
            output_ = run_cmd(node,cmd)
            output = parse_routes(output_)
            if not output:
                logging.info("there is nothing announced in {}".format(node))
            else:
                if (args.v4):
                    print ("IPv4 withdraw... done!")
                elif (args.v6):
                    print ("IPv6 withdraw... done!")
                else:
                    print ("withdraw... done!")
    
            # announce found
            for announces in output:
                cmd = "exabgpcli neighbor {} {} ".format(announces['ip'],announces['cmd'])
                if (args.v4):
                    if (':' not in announces['ip']):
                        print ("IPv4 withdraw... done!")
                        output = run_cmd(node,cmd)
                        logging.info(output)
                elif (args.v6):
                    print ("IPv6 withdraw... done!")
                    if (':' in announces['ip']):
                        output = run_cmd(node,cmd)
                        logging.info(output)
    
                # run for both
                else:
                    output = run_cmd(node,cmd)
                    logging.info(output)
    
    # check all the announces for specific nodes
    elif (args.announces):
        for node in args.target:
            cmd = " exabgpcli show adj-rib out extensive"
            output = run_cmd(node,cmd)
            if (not output):
                continue;
            if (len(output)==0):
                print ("== {}".format(node))
                print ("No announcement")
                next
    
            if (not args.v4 and not args.v6):
                print ("== {}".format(node)) if not (args.csv) else False
                    

            if (args.v4):
                if any("in-open ipv4" in s for s in output):
                    print ("== {}".format(node)) if not (args.csv) else False
    
            if (args.v6):
                if any("in-open ipv6" in s for s in output):
                    print ("== {}".format(node)) if not (args.csv) else False
             
            for line in (output):
    
                if  (args.v4):
                    if (" in-open ipv4" in line):
                        route_search = re.search('neighbor\s+(.*)\s+local-ip+.*in-open ipv\d\sunicast\s+(.*?)\s+next-hop self\s+(.*)',line,re.IGNORECASE)
                        if (args.csv):
                            print ("{},{},{}".format(node,route_search.group(2),route_search.group(3)))
                        else:
                            print ("neighbor {} prefix {} {} ".format(route_search.group(1),route_search.group(2),route_search.group(3)))

                if  (args.v6):
                    if (" in-open ipv6" in line):
                        route_search = re.search('neighbor\s+(.*)\s+local-ip+.*in-open ipv\d\sunicast\s+(.*?)\s+next-hop self\s+(.*)',line,re.IGNORECASE)
                        if (args.csv):
                            print ("{},{},{}".format(node,route_search.group(2),route_search.group(3)))
                        else:
                            print ("neighbor {} prefix {} {} ".format(route_search.group(1),route_search.group(2),route_search.group(3)))

                        
                if (not args.v4 and not args.v6):
                        route_search = re.search('neighbor\s+(.*)\s+local-ip+.*in-open ipv\d\sunicast\s+(.*?)\s+next-hop self\s+(.*)',line,re.IGNORECASE)
                        if (args.csv):
                            print ("{},{},{}".format(node,route_search.group(2),route_search.group(3)))
                        else:
                            print ("neighbor {} prefix {} {} ".format(route_search.group(1),route_search.group(2),route_search.group(3)))


    # add route (prefix) in BGP
    elif (args.add):
        for node in args.target:
            logging.info("finding neighbor for {}".format(node))
            cmd = "exabgpcli show neighbor summary"
            output = run_cmd(node,cmd)
            if (not output):
                continue;
    
            output = parse_peers(output)
            neighbor_list = [neighbor['ip'] for neighbor in output]
            
            if (":" in args.route and not args.v6):
                print ("route IPv6 will be added to IPv4 PEERS")

            if (args.v4):
               neighbor_list = [ip for ip in neighbor_list  if ':' not in ip]
    
            elif (args.v6):
               neighbor_list = [ip for ip in neighbor_list  if ':'  in ip]
    
            logging.info(neighbor_list)
            # prepare the cmd
            cmd = "announce route {} next-hop self".format(args.route)
    
            # prepend - if prepend is set update the exabgpcli cmd
            if (args.prepend):
                n_preprend = int(args.prepend)
                n_preprend = n_preprend + 1
                prepend = "1149 "
                prepend=prepend*n_preprend
                cmd = "announce route {} next-hop self as-path [{}]".format(args.route,prepend)
        
            # run command in each neighbor
            for neighbor in neighbor_list:
                cmd_exec = "exabgpcli neighbor {} ".format(neighbor)
                cmd_exec = cmd_exec+" " + cmd
                print ("CMD={}".format(cmd_exec))
                logging.info(cmd_exec)
                output = run_cmd(node,cmd_exec)
    
    elif (args.cmd):
    
        for node in args.target:
            logging.info("finding neighbor for {}".format(node))
            cmd = "exabgpcli show neighbor summary"
            output = run_cmd(node,cmd)
            if (not output):
                continue;
    
            output = parse_peers(output)
            neighbor_list = [neighbor['ip'] for neighbor in output]
            
            #if (args.v4):
            #   neighbor_list = [ip for ip in neighbor_list  if ':' not in ip]
    
            # default apply to IPv4
            if (args.v6):
               neighbor_list = [ip for ip in neighbor_list  if ':'  in ip]
            else:
               neighbor_list = [ip for ip in neighbor_list  if ':' not in ip]
    
    
            logging.info(neighbor_list)
    
            #cmd = "announce route 145.90.8.0/24 next-hop self community 100:667"
        
            # run command in each neighbor
            for neighbor in neighbor_list:
                cmd_exec = "exabgpcli neighbor {} ".format(neighbor)
                cmd_exec = cmd_exec+" " + args.cmd
                print ("CMD={}".format(cmd_exec))
                logging.info(cmd_exec)
                output = run_cmd(node,cmd_exec)
    
    elif (args.listnodesannounce):
        if args.debug: print  ("list nodes") 
        result_array = []
        for node in args.target:
            cmd = " exabgpcli show adj-rib out extensive"
            output = run_cmd(node,cmd)
            if (not output):
                continue;
    
            if (len(output)==0):
                print ("No announces")
                next
            for line in (output):
                route_search = re.search('neighbor\s+(.*)\s+local-ip+.*in-open ipv\d\sunicast\s+(.*?)\s+.*',line,re.IGNORECASE)
                result = {
                    "neighbor": route_search.group(1),
                    "prefix" :  route_search.group(2),
                    "node"   : node
                }
                result_array.append(result)
    
        # build list with all the results
        sites = []
        for route in result_array:
    
            if (args.v4):
                if ":" not in (route['prefix']):
                    sites.append(route['node'])
            elif (args.v6):
                if ":" in (route['prefix']):
                    sites.append(route['node'])
            else:
                sites.append(route['node'])
    
        label = "#ipv4+ipv6,"
        if (args.v4):
            label = "#ipv4,"
        if (args.v6):
            label = "#ipv6,"
        lst = ",".join(list(set(sites)))
        print (label+lst)
except KeyboardInterrupt:   
    print('Interrupted')
sys.exit(0)
