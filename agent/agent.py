#!/usr/bin/env python3
import argparse
import logging
import time
import iptc
import requests
import yaml

logging.basicConfig(level=logging.INFO)
    
def write_chain(table, name, rules):
    table.autocommit = False
    chain = iptc.Chain(table, name)
    old_rules = chain.rules
    for rule in old_rules:
        chain.delete_rule(rule)
    for rule in reversed(rules):
        chain.insert_rule(rule)
    table.commit()
    table.refresh()

def accept_localhost(rule):
    rule.target = iptc.Target(rule, 'ACCEPT')
    rule.in_interface = 'lo'
    return rule

def accept_related_established(rule):
    rule.target = iptc.Target(rule, 'ACCEPT')
    match = iptc.Match(rule, 'state')
    match.state = 'RELATED,ESTABLISHED'
    rule.add_match(match)
    return rule

def create_rule(rule, action, ip, protocol, port):
    rule.target = iptc.Target(rule, action)
    if ip:
        rule.src = ip
    if protocol:
        rule.protocol = protocol
        if port:
            match = rule.create_match(protocol)
            match.dport = port
            rule.add_match(match)
    return rule

def update_iptables(policy):
    policies = [p.split() for p in policy]
    for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
        rules = [accept_localhost(iptc.Rule6()), accept_related_established(iptc.Rule6())]
        rules += [create_rule(iptc.Rule(), p[1], p[2], p[3], p[4]) if len(p) > 2 else create_rule(iptc.Rule(), p[1], None, None, None) for p in policies where p[0] == chain]
        write_chain(iptc.Table(iptc.Table.FILTER), chain, rules)
        write_chain(iptc.Table6(iptc.Table6.FILTER), chain, [create_rule(iptc.Rule6(), 'DROP', None, None, None)])

def poll(interval, uri, token):
    while True:
        try:
            headers = {'Authorization': 'Bearer ' + token}
            response = requests.get(uri, headers=headers)
            policy = response.json()
            update_iptables(policy)
            logging.info('%d %s', response.status_code, policy)
        except Exception as e:
            logging.error(e)
        time.sleep(interval)

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='agent/config.yaml')
    args = parser.parse_args()
    with open(args.config, 'r') as f:
        config = yaml.load(f)
    poll(5, config['uri'], config['token'])
