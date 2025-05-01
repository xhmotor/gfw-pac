#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import urllib.request, urllib.error, urllib.parse
from argparse import ArgumentParser
import ipaddress

def parse_args():
    parser = ArgumentParser()
    ./gfw-pac.py -f gfw.pac \
             -p "PROXY 192.168.1.200:3128; DIRECT" \
             --proxy-domains=proxy-domains.txt \
             --direct-domains=direct-domains.txt \
             --localtld-domains=local-tlds.txt \
             --ip-file=cidrs-cn.txt
    return parser.parse_args()

def convert_cidr(cidr):
    if '/' in cidr:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        network_address = int(network.network_address) >> (network.max_prefixlen - network.prefixlen)
    else:
        network = ipaddress.ip_address(cidr.strip())
        network_address = network
    return hex(int(network_address))[2:]

def longest_common_prefix(str1, str2):
    min_length = min(len(str1), len(str2))
    for i in range(min_length):
        if str1[i] != str2[i]:
            return str1[:i]
    return str1[:min_length]

def generate_cnip_cidrs():
    """ 从文件中读取CIDR地址 """
    args = parse_args()
    with open(args.ip_file, 'r') as file:
        cidrs = file.read().splitlines()
        converted_cidrs = []
        for cidr in cidrs:
            converted_cidrs.append(convert_cidr(cidr))

    converted_cidrs.sort(key=lambda x: (len(x), x), reverse=False)
    converted_cidrs_clone = converted_cidrs[:]
    
    lastFullCidr = ''
    for i in range(len(converted_cidrs)):
        prevCidr = converted_cidrs_clone[i-1] if i > 0 else ''
        currentCidr = converted_cidrs[i]
        if len(prevCidr) != len(currentCidr):
            lastFullCidr = currentCidr
            continue
        prefix = longest_common_prefix(lastFullCidr, currentCidr)
        if len(prefix) < len(lastFullCidr)//1.2:
            lastFullCidr = currentCidr
            continue
        converted_cidrs[i] = '~' + currentCidr[len(prefix):]
    
    cidr_list = ','.join(converted_cidrs)
    return f"'{cidr_list}'.split(',')"

def generate_pac_fast(domains, proxy, direct_domains, cidrs, local_tlds):
    # render the pac file
    with open('./pac-template', 'r') as f:
        proxy_content = f.read()
    domains_list = []
    for domain in domains:
        domains_list.append(domain)
    proxy_content = proxy_content.replace('__PROXY__', json.dumps(str(proxy)))
    proxy_content = proxy_content.replace(
        '__DOMAINS__',
        json.dumps(domains_list, sort_keys=True, separators=(',', ':'))
    )

    direct_domains_list = []
    for domain in direct_domains:
        direct_domains_list.append(domain)
    proxy_content = proxy_content.replace(
        '__DIRECT_DOMAINS__',
        json.dumps(direct_domains_list, sort_keys=True, separators=(',', ':'))
    )

    proxy_content = proxy_content.replace(
        '__CIDRS__', cidrs
    )

    tlds_list = []
    for domain in local_tlds:
        tlds_list.append(domain)
    proxy_content = proxy_content.replace(
        '__LOCAL_TLDS__',
        json.dumps(tlds_list, sort_keys=True, separators=(',', ':'))
    )

    return proxy_content

def main():
    args = parse_args()
    user_rule = None
    direct_rule = None
    localtld_rule = None
    if args.user_rule:
        userrule_parts = urllib.parse.urlsplit(args.user_rule)
        if not userrule_parts.scheme or not userrule_parts.netloc:
            # It's not an URL, deal it as local file
            with open(args.user_rule, 'r') as f:
                user_rule = f.read()
        else:
            # Yeah, it's an URL, try to download it
            print('Downloading user rules file from %s' % args.user_rule)
            user_rule = urllib.request.urlopen(args.user_rule, timeout=10).read().decode('utf-8')
        user_rule = user_rule.splitlines(False)

    if args.direct_rule:
        directrule_parts = urllib.parse.urlsplit(args.direct_rule)
        if not directrule_parts.scheme or not directrule_parts.netloc:
            # It's not an URL, deal it as local file
            with open(args.direct_rule, 'r') as f:
                direct_rule = f.read()
        else:
            # Yeah, it's an URL, try to download it
            print('Downloading user rules file from %s' % args.user_rule)
            direct_rule = urllib.request.urlopen(args.direct_rule, timeout=10).read().decode('utf-8')
        direct_rule = direct_rule.splitlines(False)
    else:
        direct_rule = []

    if args.localtld_rule:
        tldrule_parts = urllib.parse.urlsplit(args.localtld_rule)
        if not tldrule_parts.scheme or not tldrule_parts.netloc:
            # It's not an URL, deal it as local file
            with open(args.localtld_rule, 'r') as f:
                localtld_rule = f.read()
        else:
            # Yeah, it's an URL, try to download it
            print('Downloading local tlds rules file from %s' % args.user_rule)
            localtld_rule = urllib.request.urlopen(args.localtld_rule, timeout=10).read().decode('utf-8')
        localtld_rule = localtld_rule.splitlines(False)
    else:
        localtld_rule = []

    cidrs = generate_cnip_cidrs()

    # domains = reduce_domains(domains)
    pac_content = generate_pac_fast(user_rule, args.proxy, direct_rule, cidrs, localtld_rule)

    with open(args.output, 'w') as f:
        f.write(pac_content)


if __name__ == '__main__':
    main()
