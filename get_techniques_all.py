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
Get all techniques and/or sub-techniques (as STIX objects)
We can filter on "techniques", "subtechniques", or "both"
'''

def get_all_techniques(dataset, include="both"):
    if include == "techniques":
        return dataset.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
    elif include == "subtechniques":
        return dataset.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        return dataset.query([
            Filter('type', '=', 'attack-pattern')
        ])


# Define the dataset
dataset = get_attack_version("enterprise-attack", "12.1")

# Retrieve all groups as STIX objects
techniques_stix_objects = remove_revoked_deprecated(get_all_techniques(dataset, "both"))

# Display the result:
pprint(techniques_stix_objects)
