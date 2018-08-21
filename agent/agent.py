#!/usr/bin/env python3
import argparse
import logging
import time
import requests
import yaml

logging.basicConfig(level=logging.INFO)

def poll(interval, uri, token):
    while True:
        try:
            headers = {'Authorization': 'Bearer ' + token}
            response = requests.get(uri, headers=headers)
            logging.info('%d %s', response.status_code, response.content.decode('utf-8'))
            # todo: write iptables rules
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
