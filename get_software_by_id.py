import os, sys
from stix2 import MemoryStore
from stix2 import Filter
from pprint import pprint
from itertools import chain

"""
Get ATT&CK STIX data for a given domain and version
"""

def get_attack_version(domain, version):
    ms = MemoryStore()
    ms.load_from_file(os.path.join(domain, f"{domain}-{version}.json"))
    return ms

"""
Get ATT&CK STIX data a specific software
"""

def get_software_by_id(dataset, software_id):
    return list(
        chain.from_iterable(
            dataset.query(f)
            for f in [
                [ Filter("external_references.external_id", "=", software_id)],
                [ Filter("type", "=", "tool"),
                Filter("type", "=", "malware")]
            ]
        )
    )


# Define the dataset
dataset = get_attack_version("enterprise-attack", "12.1")

# Retrieve a software
software = get_software_by_id(dataset, sys.argv[1])

# Display the result
pprint(software)

'''
Sample output:
[Tool(type='tool', id='tool--03342581-f790-4f03-ba41-e82e67392e23', created_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', created='2017-05-31T21:32:31.601Z', modified='2021-10-15T20:33:54.392Z', name='Net', description='The [Net](https://attack.mitre.org/software/S0039) utility is a component of the Windows operating system. It is used in command-line operations for control of users, groups, services, and network connections. (Citation: Microsoft Net Utility)\n\n[Net](https://attack.mitre.org/software/S0039) has a great deal of functionality, (Citation: Savill 1999) much of which is useful for an adversary, such as gathering system and network information for Discovery, moving laterally through [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) using <code>net use</code> commands, and interacting with services. The net1.exe utility is executed for certain functionality when net.exe is run and can be used directly in commands such as <code>net1 user</code>.', revoked=False, labels=['tool'], external_references=[ExternalReference(source_name='mitre-attack', url='https://attack.mitre.org/software/S0039', external_id='S0039'), ExternalReference(source_name='Microsoft Net Utility', description='Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.', url='https://msdn.microsoft.com/en-us/library/aa939914'), ExternalReference(source_name='Savill 1999', description='Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.', url='http://windowsitpro.com/windows/netexe-reference')], object_marking_refs=['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'], x_mitre_aliases=['Net', 'net.exe'], x_mitre_attack_spec_version='2.1.0', x_mitre_contributors=['David Ferguson, CyberSponse'], x_mitre_domains=['enterprise-attack'], x_mitre_modified_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', x_mitre_platforms=['Windows'], x_mitre_version='2.3')]
]
'''
