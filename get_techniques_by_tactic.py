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
Remove any revoked or deprecated objects from the data source
'''

def remove_revoked_deprecated(stix_objects):
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

'''
Get all techniques for a specific Tactic
'''

def get_tactic_techniques(dataset, tactic):
    return dataset.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])


# Define the dataset
dataset = get_attack_version("enterprise-attack", "12.1")

# Retrieve all groups as STIX objects
tactic = "initial-access"
tactic_techniques_stix_objects = remove_revoked_deprecated(get_tactic_techniques(dataset, tactic))

# Print the result
pprint(tactic_techniques_stix_objects)
