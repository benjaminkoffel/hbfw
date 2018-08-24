#!/usr/bin/env python3
import argparse
import logging
import time
import iptc
import requests
import yaml

logging.basicConfig(level=logging.INFO)

def write_chain(name, rules):
    table = iptc.Table(iptc.Table.FILTER)
    table.autocommit = False
    chain = iptc.Chain(table, name)
    old_rules = chain.rules
    for rule in old_rules:
        chain.delete_rule(rule)
    for rule in rules:
        chain.insert_rule(rule)
    table.commit()
    table.refresh()

def accept_localhost():
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, 'ACCEPT')
    rule.in_interface = 'lo'
    return rule

def accept_related_established():
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, 'ACCEPT')
    match = iptc.Match(rule, 'state')
    match.state = 'RELATED,ESTABLISHED'
    rule.add_match(match)
    return rule

def drop_all():
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, 'DROP')
    return rule

def create_rule(action, ip, protocol, port):
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, action)
    rule.src = ip
    rule.protocol = protocol
    match = rule.create_match(protocol)
    match.dport = port
    rule.add_match(match)
    return rule

def update_iptables(policy):
    rules = [accept_localhost(), accept_related_established()]
    rules += [create_rule(action, ip, 'tcp', port) for action, ip, port in policy]
    rules += [drop_all()]
    write_chain('INPUT', rules)

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
    parser.add_argument('--config')
    args = parser.parse_args()
    with open(args.config, 'r') as f:
        config = yaml.load(f)
    poll(5, config['uri'], config['token'])
