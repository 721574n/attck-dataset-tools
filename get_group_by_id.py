import os, sys
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
Get Group details by its ID
'''

def get_group_by_id(src, group_id):
    """get ATT&CK STIX data for a given group"""
    return src.query([
        Filter("external_references.external_id", "=", group_id),
        Filter("type", "=", "intrusion-set")
    ])[0]


# Define the dataset
dataset = get_attack_version("enterprise-attack", "12.1")

# Retrieve a specific group as STIX objects
group_stix_object = get_group_by_id(dataset, sys.argv[1])

# Display the name of the group (using the STIX object)
print("GROUP NAME: " + group_stix_object.name)

# Display the result (STIX)
pprint(group_stix_object)

# Display the result (JSON)
print(group_stix_object.serialize(pretty=True))


'''
Sample output (using group G0001):
IntrusionSet(type='intrusion-set', id='intrusion-set--a0cb9370-e39b-44d5-9f50-ef78e412b973', created_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', created='2017-05-31T21:31:45.629Z', modified='2022-04-15T15:52:00.359Z', name='Axiom', description='[Axiom](https://attack.mitre.org/groups/G0001) is a suspected Chinese cyber espionage group that has targeted the aerospace, defense, government, manufacturing, and media sectors since at least 2008. Some reporting suggests a degree of overlap between [Axiom](https://attack.mitre.org/groups/G0001) and [Winnti Group](https://attack.mitre.org/groups/G0044) but the two groups appear to be distinct based on differences in reporting on TTPs and targeting.(Citation: Kaspersky Winnti April 2013)(Citation: Kaspersky Winnti June 2015)(Citation: Novetta Winnti April 2015)', aliases=['Axiom', 'Group 72'], revoked=False, external_references=[ExternalReference(source_name='mitre-attack', url='https://attack.mitre.org/groups/G0001', external_id='G0001'), ExternalReference(source_name='Group 72', description='(Citation: Cisco Group 72)'), ExternalReference(source_name='Axiom', description='(Citation: Novetta-Axiom)'), ExternalReference(source_name='Cisco Group 72', description='Esler, J., Lee, M., and Williams, C. (2014, October 14). Threat Spotlight: Group 72. Retrieved January 14, 2016.', url='http://blogs.cisco.com/security/talos/threat-spotlight-group-72'), ExternalReference(source_name='Kaspersky Winnti April 2013', description="Kaspersky Lab's Global Research and Analysis Team. (2013, April 11). Winnti. More than just a game. Retrieved February 8, 2017.", url='https://securelist.com/winnti-more-than-just-a-game/37029/'), ExternalReference(source_name='Novetta Winnti April 2015', description='Novetta Threat Research Group. (2015, April 7). Winnti Analysis. Retrieved February 8, 2017.', url='http://www.novetta.com/wp-content/uploads/2015/04/novetta_winntianalysis.pdf'), ExternalReference(source_name='Novetta-Axiom', description='Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.', url='http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf'), ExternalReference(source_name='Kaspersky Winnti June 2015', description='Tarakanov, D. (2015, June 22). Games are over: Winnti is now targeting pharmaceutical companies. Retrieved January 14, 2016.', url='https://securelist.com/games-are-over/70991/')], object_marking_refs=['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'], x_mitre_attack_spec_version='2.1.0', x_mitre_deprecated=False, x_mitre_domains=['enterprise-attack'], x_mitre_modified_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5', x_mitre_version='2.0')
'''
