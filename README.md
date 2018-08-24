# Host Based Firewall

A very simplistic POC of using an agent based firewall to create a network of public facing hosts.

Configuration is stored in central API defining policies and responding to agents.

API issues signed tokens that are given to agents to identify them via tags.

Agents periodically poll API and their IP address and token ID is stored along with their tags.

Policies are selected via tags and `TAG:` fields are expanded with any matching hosts that have reported in.

## Usage

Install API on a server and update `uri` and `key` in `api/config.yaml`.
```
sudo python3 -m pip install api/requirements.txt
python3 api/api.py
```

Rotate signing certificates and manually delete public key from `api/id.jwks`.
```
POST /rotate HTTP/1.1
Authorization: Bearer [ADMINISTRATION_KEY]
```

Issue a new token for one of your hosts containing tags to identify it.
```
POST /issue HTTP/1.1
Authorization: Bearer [ADMINISTRATION_KEY]

{"tags": ["COMPUTER1", "WORKGROUP"]}
```

Install agent on your host and update `uri` and `token` in `agent/config.yaml`.
```
sudo python3 -m pip install agent/requirements.txt
sudo python3 agent/agent.py
```
