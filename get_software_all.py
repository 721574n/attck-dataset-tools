import os
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

"""
Get ATT&CK STIX data for all software
"""

def get_all_software(dataset):
    return list(
        chain.from_iterable(
            dataset.query(f)
            for f in [
                Filter("type", "=", "tool"),
                Filter("type", "=", "malware")]
        )
    )


# Define the dataset
dataset = get_attack_version("enterprise-attack", "12.1")

# Retrieve all software
software = remove_revoked_deprecated(get_all_software(dataset))

# Display the result
pprint(software)


'''
Sample output:

[Tool(type='tool', id='tool--03342581-f790-4f03-ba41-e82e67392e23', created_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', created='2017-05-31T21:32:31.601Z', modified='2021-10-15T20:33:54.392Z', name='Net', description='The [Net](https://attack.mitre.org/software/S0039) utility is a component of the Windows operating system. It is used in command-line operations for control of users, groups, services, and network connections. (Citation: Microsoft Net Utility)\n\n[Net](https://attack.mitre.org/software/S0039) has a great deal of functionality, (Citation: Savill 1999) much of which is useful for an adversary, such as gathering system and network information for Discovery, moving laterally through [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) using <code>net use</code> commands, and interacting with services. The net1.exe utility is executed for certain functionality when net.exe is run and can be used directly in commands such as <code>net1 user</code>.', revoked=False, labels=['tool'], external_references=[ExternalReference(source_name='mitre-attack', url='https://attack.mitre.org/software/S0039', external_id='S0039'), ExternalReference(source_name='Microsoft Net Utility', description='Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.', url='https://msdn.microsoft.com/en-us/library/aa939914'), ExternalReference(source_name='Savill 1999', description='Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.', url='http://windowsitpro.com/windows/netexe-reference')], object_marking_refs=['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'], x_mitre_aliases=['Net', 'net.exe'], x_mitre_attack_spec_version='2.1.0', x_mitre_contributors=['David Ferguson, CyberSponse'], x_mitre_domains=['enterprise-attack'], x_mitre_modified_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', x_mitre_platforms=['Windows'], x_mitre_version='2.3'),
 Tool(type='tool', id='tool--03c6e0ea-96d3-4b23-9afb-05055663cf4b', created_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', created='2021-03-18T14:57:34.628Z', modified='2021-04-25T23:30:38.375Z', name='RemoteUtilities', description='[RemoteUtilities](https://attack.mitre.org/software/S0592) is a legitimate remote administration tool that has been used by [MuddyWater](https://attack.mitre.org/groups/G0069) since at least 2021 for execution on target machines.(Citation: Trend Micro Muddy Water March 2021)', revoked=False, labels=['tool'], external_references=[ExternalReference(source_name='mitre-attack', url='https://attack.mitre.org/software/S0592', external_id='S0592'), ExternalReference(source_name='Trend Micro Muddy Water March 2021', description='Peretz, A. and Theck, E. (2021, March 5). Earth Vetala – MuddyWater Continues to Target Organizations in the Middle East. Retrieved March 18, 2021.', url='https://www.trendmicro.com/en_us/research/21/c/earth-vetala---muddywater-continues-to-target-organizations-in-t.html')], object_marking_refs=['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'], x_mitre_aliases=['RemoteUtilities'], x_mitre_attack_spec_version='2.1.0', x_mitre_domains=['enterprise-attack'], x_mitre_modified_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', x_mitre_platforms=['Windows'], x_mitre_version='1.0'),
...
]
'''
