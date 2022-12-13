import os
from stix2 import MemoryStore
from stix2 import Filter
from pprint import pprint

'''
Get ATT&CK STIX data for a given domain and version
'''

def get_attack_version(domain, version):
    ms = MemoryStore()
    ms.load_from_file(os.path.join(domain, f"{domain}-{version}.json"))
    return ms

'''
Get all Tactics (as STIX objects)
'''

def get_all_tactics(dataset):
    return dataset.query([
        Filter("type", "=",  "x-mitre-tactic")
    ])


# Define the dataset
dataset = get_attack_version("enterprise-attack", "12.1")

# Retrieve all Tactics as STIX objects
tactics_stix_objects = get_all_tactics(dataset)

# Display the result:
pprint(tactics_stix_objects)
