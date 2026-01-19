#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import json
import os
import glob

# Namespaces used in SCAP datastreams
NAMESPACES = {
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
    'xccdf-1.1': 'http://checklists.nist.gov/xccdf/1.1',
    'ds': 'http://scap.nist.gov/schema/scap/source/1.2',
    'dc': 'http://purl.org/dc/elements/1.1/'
}

def extract_profiles_from_datastream(datastream_path):
    """
    Extract all profiles from a SCAP datastream
    Returns: List of profiles with metadata
    """
    tree = ET.parse(datastream_path)
    root = tree.getroot()
    
    profiles = []
    
    # Find all Profile elements
    for profile in root.findall('.//xccdf:Profile', NAMESPACES):
        profile_id = profile.get('id', '')
        
        # Extract title
        title_elem = profile.find('xccdf:title', NAMESPACES)
        title = title_elem.text if title_elem is not None else 'Unknown'
        
        # Extract description
        desc_elem = profile.find('xccdf:description', NAMESPACES)
        description = desc_elem.text if desc_elem is not None else ''
        
        # Extract version (from description or metadata)
        version = extract_version_from_text(description)
        
        # Count selected rules
        selected_rules = profile.findall('.//xccdf:select[@selected="true"]', NAMESPACES)
        rule_count = len(selected_rules)
        
        profiles.append({
            'id': profile_id,
            'title': title,
            'description': description,
            'version': version,
            'rule_count': rule_count,
            'selected_rule_ids': [r.get('idref') for r in selected_rules]
        })
    
    return profiles


def extract_rules_from_datastream(datastream_path, profile_id=None):
    """
    Extract all rules from datastream, optionally filtered by profile
    Returns: List of rules with metadata
    """
    tree = ET.parse(datastream_path)
    root = tree.getroot()
    
    # Get selected rules for this profile
    selected_rule_ids = set()
    if profile_id:
        profile = root.find(f'.//xccdf:Profile[@id="{profile_id}"]', NAMESPACES)
        if profile:
            selected_rules = profile.findall('.//xccdf:select[@selected="true"]', NAMESPACES)
            selected_rule_ids = {r.get('idref') for r in selected_rules}
    
    rules = []
    
    # Find all Rule elements
    for rule in root.findall('.//xccdf:Rule', NAMESPACES):
        rule_id = rule.get('id', '')
        
        # Skip if profile specified and rule not selected
        if profile_id and rule_id not in selected_rule_ids:
            continue
        
        # Extract title
        title_elem = rule.find('xccdf:title', NAMESPACES)
        title = title_elem.text if title_elem is not None else 'Unknown'
        
        # Extract severity
        severity = rule.get('severity', 'unknown')
        
        # Extract description
        desc_elem = rule.find('xccdf:description', NAMESPACES)
        description = desc_elem.text if desc_elem is not None else ''
        
        # Extract rationale
        rationale_elem = rule.find('xccdf:rationale', NAMESPACES)
        rationale = rationale_elem.text if rationale_elem is not None else ''
        
        # Extract references (CIS, NIST, etc.)
        references = extract_references(rule)
        
        # Extract customizable values/parameters
        parameters = extract_rule_parameters(root, rule_id)
        
        rules.append({
            'id': rule_id,
            'title': title,
            'description': description,
            'severity': severity,
            'rationale': rationale,
            'references': references,
            'has_parameters': len(parameters) > 0,
            'parameters': parameters
        })
    
    return rules


def extract_rule_parameters(root, rule_id):
    """
    Extract customizable parameters (Values) associated with a rule
    """
    parameters = {}
    
    # Find Value elements referenced by this rule
    # Look for check-content-ref or similar references
    rule = root.find(f'.//xccdf:Rule[@id="{rule_id}"]', NAMESPACES)
    if not rule:
        return parameters
    
    # Find all Value references in the rule's checks
    for check in rule.findall('.//xccdf:check', NAMESPACES):
        for check_export in check.findall('.//xccdf:check-export', NAMESPACES):
            value_id = check_export.get('value-id', '')
            if value_id:
                # Find the actual Value definition
                value_elem = root.find(f'.//xccdf:Value[@id="{value_id}"]', NAMESPACES)
                if value_elem:
                    title_elem = value_elem.find('xccdf:title', NAMESPACES)
                    value_title = title_elem.text if title_elem is not None else 'Unknown'
                    
                    # Get default value
                    default_value_elem = value_elem.find('xccdf:value', NAMESPACES)
                    default_value = default_value_elem.text if default_value_elem is not None else ''
                    
                    # Get value type
                    value_type = value_elem.get('type', 'string')
                    
                    # Extract variable name (simplified from ID)
                    var_name = value_id.replace('xccdf_org.ssgproject.content_value_', '')
                    
                    parameters[var_name] = {
                        'name': value_title,
                        'default': default_value,
                        'type': value_type,
                        'value_id': value_id
                    }
    
    return parameters


def extract_references(rule):
    """
    Extract compliance framework references (CIS, NIST, etc.)
    """
    references = {
        'cis': [],
        'nist': [],
        'srg': [],
        'stigid': [],
        'cce': []
    }
    
    for ref in rule.findall('.//xccdf:reference', NAMESPACES):
        href = ref.get('href', '')
        text = ref.text or ''
        
        if 'cisecurity' in href.lower() or 'cis' in href.lower():
            references['cis'].append(text)
        elif 'nist' in href.lower():
            references['nist'].append(text)
        elif 'disa' in href.lower() and 'srg' in text.upper():
            references['srg'].append(text)
        elif 'stigid' in href.lower():
            references['stigid'].append(text)
    
    # Extract CCE (Common Configuration Enumeration)
    for ident in rule.findall('.//xccdf:ident', NAMESPACES):
        system = ident.get('system', '')
        if 'cce' in system.lower():
            references['cce'].append(ident.text)
    
    return references


def extract_version_from_text(text):
    """
    Extract version number from description text
    Example: "v3.0.0" or "version 3.0.0"
    """
    import re
    if not text:
        return 'Unknown'
    
    # Look for version patterns
    patterns = [
        r'v(\d+\.\d+\.\d+)',
        r'version\s+(\d+\.\d+\.\d+)',
        r'Version\s+(\d+\.\d+\.\d+)',
        r'\bv(\d+\.\d+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return 'v' + match.group(1)
    
    return 'Unknown'


def scan_scap_directory(scap_dir='/opt'):
    """
    Scan directory for all SCAP datastreams
    Returns: Dictionary of available datastreams grouped by OS
    """
    datastreams = {}
    
    # Find all SSG directories
    ssg_dirs = glob.glob(f'{scap_dir}/scap-security-guide-*')
    
    for ssg_dir in ssg_dirs:
        version = os.path.basename(ssg_dir).replace('scap-security-guide-', '')
        
        # Find all datastream files
        ds_files = glob.glob(f'{ssg_dir}/ssg-*-ds.xml')
        
        for ds_file in ds_files:
            basename = os.path.basename(ds_file)
            # Extract OS name: ssg-rhel8-ds.xml -> rhel8
            os_name = basename.replace('ssg-', '').replace('-ds.xml', '')
            
            if os_name not in datastreams:
                datastreams[os_name] = []
            
            datastreams[os_name].append({
                'path': ds_file,
                'version': version,
                'filename': basename
            })
    
    return datastreams


def build_profile_database(scap_dir='/opt'):
    """
    Build complete database of all profiles and rules from SCAP content
    """
    database = {
        'metadata': {
            'generated': datetime.now().isoformat(),
            'scap_directory': scap_dir
        },
        'datastreams': {},
        'profiles': {},
        'rules': {}
    }
    
    # Scan for datastreams
    datastreams = scan_scap_directory(scap_dir)
    database['datastreams'] = datastreams
    
    # Process each datastream
    for os_name, ds_list in datastreams.items():
        database['profiles'][os_name] = {}
        database['rules'][os_name] = {}
        
        for ds_info in ds_list:
            ds_path = ds_info['path']
            version = ds_info['version']
            
            print(f"Processing {os_name} version {version}...")
            
            # Extract profiles
            profiles = extract_profiles_from_datastream(ds_path)
            database['profiles'][os_name][version] = profiles
            
            # Extract rules for each profile
            database['rules'][os_name][version] = {}
            for profile in profiles:
                rules = extract_rules_from_datastream(ds_path, profile['id'])
                database['rules'][os_name][version][profile['id']] = rules
    
    return database


# Main execution
if __name__ == '__main__':
    import sys
    from datetime import datetime
    
    scap_dir = sys.argv[1] if len(sys.argv) > 1 else '/opt'
    
    print(f"Scanning SCAP content in: {scap_dir}")
    print("=" * 60)
    
    # Build the complete database
    database = build_profile_database(scap_dir)
    
    # Save to JSON
    output_file = 'scap_database.json'
    with open(output_file, 'w') as f:
        json.dump(database, f, indent=2)
    
    print(f"\nDatabase saved to: {output_file}")
    print(f"Total OS variants: {len(database['datastreams'])}")
    
    # Print summary
    for os_name in database['profiles']:
        for version in database['profiles'][os_name]:
            profile_count = len(database['profiles'][os_name][version])
            print(f"  {os_name} v{version}: {profile_count} profiles")
