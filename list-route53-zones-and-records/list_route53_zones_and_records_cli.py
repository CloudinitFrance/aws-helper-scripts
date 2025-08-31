#!/usr/bin/env python3
"""
Comprehensive Route 53 inventory with DNS analysis and security assessment.

This script provides a complete overview of Route 53 hosted zones and DNS records
including security analysis, configuration review, and optimization recommendations.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional
import re
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def validate_aws_credentials():
    """Validate AWS credentials before proceeding."""
    try:
        sts = boto3.client('sts')
        response = sts.get_caller_identity()
        print(f"Using AWS Account: {response.get('Account', 'Unknown')}")
        print(f"User/Role: {response.get('Arn', 'Unknown')}")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error: AWS credentials not found or incomplete: {e}")
        print("Please configure your credentials using 'aws configure' or environment variables.")
        return False
    except ClientError as e:
        print(f"Error validating credentials: {e.response['Error']['Message']}")
        return False

def get_hosted_zones_with_pagination(route53_client) -> List[Dict]:
    """Get all hosted zones with pagination."""
    zones = []
    
    try:
        paginator = route53_client.get_paginator('list_hosted_zones')
        
        for page in paginator.paginate():
            zones.extend(page['HostedZones'])
        
        return zones
        
    except ClientError as e:
        print(f"Error retrieving hosted zones: {e.response['Error']['Message']}")
        return []

def get_resource_record_sets_with_pagination(route53_client, hosted_zone_id: str) -> List[Dict]:
    """Get all resource record sets for a hosted zone with pagination."""
    records = []
    
    try:
        paginator = route53_client.get_paginator('list_resource_record_sets')
        
        for page in paginator.paginate(HostedZoneId=hosted_zone_id):
            records.extend(page['ResourceRecordSets'])
        
        return records
        
    except ClientError as e:
        print(f"Error retrieving records for zone {hosted_zone_id}: {e.response['Error']['Message']}")
        return []

def get_zone_tags(route53_client, zone_id: str) -> Dict:
    """Get tags for a hosted zone."""
    try:
        response = route53_client.list_tags_for_resource(
            ResourceType='hostedzone',
            ResourceId=zone_id
        )
        tags = {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        return tags
    except ClientError:
        return {}

def check_dns_resolution(hostname: str) -> Optional[str]:
    """Check if hostname resolves to an IP address."""
    try:
        socket.gethostbyname(hostname)
        return None  # DNS resolves = not vulnerable
    except socket.gaierror:
        return "DNS does not resolve - service deleted"

def check_http_response(target: str, error_patterns: List[str], timeout: int = 10) -> Optional[str]:
    """Check HTTP response for vulnerability patterns."""
    try:
        response = requests.get(f'http://{target}', timeout=timeout, allow_redirects=True)
        content = response.text
        
        for pattern in error_patterns:
            if pattern in content:
                return f'Service shows vulnerability: {pattern}'
    except requests.exceptions.RequestException:
        # Connection errors aren't necessarily vulnerabilities
        pass
    
    return None

def detect_subdomain_takeover(record: Dict) -> Optional[Dict]:
    """Detect potential subdomain takeover vulnerability for a single record."""
    if record['Type'] != 'CNAME':
        return None
    
    # Define vulnerable services and their detection methods
    vulnerable_services = {
        'github.io': {
            'type': 'http_check',
            'patterns': ["There isn't a GitHub Pages site here"]
        },
        'herokuapp.com': {
            'type': 'http_check',
            'patterns': ["No such app"]
        },
        'cloudfront.net': {
            'type': 'dns_check',
            'patterns': []
        },
        's3-website': {
            'type': 'http_check',
            'patterns': ["NoSuchBucket", "IncorrectEndpoint", "AllAccessDisabled"]
        },
        's3.amazonaws.com': {
            'type': 'http_check',
            'patterns': ["NoSuchBucket", "AllAccessDisabled"]
        },
        'azurewebsites.net': {
            'type': 'dns_check',
            'patterns': []
        },
        'azurefd.net': {
            'type': 'dns_check',
            'patterns': []
        },
        'azureedge.net': {
            'type': 'dns_check',
            'patterns': []
        },
        'cloudapp.azure.com': {
            'type': 'dns_check',
            'patterns': []
        },
        'cloudapp.net': {
            'type': 'dns_check',
            'patterns': []
        },
        'trafficmanager.net': {
            'type': 'dns_check',
            'patterns': []
        }
    }
    
    # Get CNAME target
    target = None
    if 'ResourceRecords' in record:
        for rr in record['ResourceRecords']:
            if 'Value' in rr:
                target = rr['Value'].rstrip('.')
                break
    
    if not target:
        return None
    
    # Check if target points to a vulnerable service
    for service, config in vulnerable_services.items():
        if service in target.lower():
            vulnerability = None
            
            if config['type'] == 'dns_check':
                # Check if DNS resolves
                vulnerability = check_dns_resolution(target)
            else:
                # Check HTTP response
                vulnerability = check_http_response(target, config['patterns'])
            
            if vulnerability:
                return {
                    'subdomain': record['Name'],
                    'target': target,
                    'service': service,
                    'vulnerability': vulnerability,
                    'severity': 'CRITICAL',
                    'risk_type': 'subdomain_takeover'
                }
    
    return None

def detect_subdomain_takeovers_batch(dns_records: List[Dict], max_workers: int = 10) -> List[Dict]:
    """Detect subdomain takeover vulnerabilities for multiple records in parallel."""
    takeover_risks = []
    cname_records = [r for r in dns_records if r['Type'] == 'CNAME']
    
    if not cname_records:
        return takeover_risks
    
    print(f"🔍 Checking {len(cname_records)} CNAME records for subdomain takeover vulnerabilities...")
    
    with ThreadPoolExecutor(max_workers=min(max_workers, len(cname_records))) as executor:
        future_to_record = {
            executor.submit(detect_subdomain_takeover, record): record
            for record in cname_records
        }
        
        for future in as_completed(future_to_record):
            try:
                result = future.result()
                if result:
                    takeover_risks.append(result)
                    print(f"🚨 CRITICAL: Subdomain takeover risk found - {result['subdomain']} → {result['target']}")
            except Exception as e:
                record = future_to_record[future]
                print(f"⚠️  Warning: Error checking {record.get('Name', 'Unknown')}: {str(e)}")
    
    return takeover_risks

def analyze_spf_record_comprehensive(spf_record: str) -> List[Dict]:
    """Comprehensive SPF record analysis."""
    issues = []
    
    # Remove v=spf1 prefix for analysis
    spf_content = spf_record.lower().replace('v=spf1', '').strip()
    mechanisms = spf_content.split()
    
    # Check for dangerous mechanisms
    if '+all' in mechanisms:
        issues.append({
            'severity': 'CRITICAL',
            'issue': 'SPF record contains +all (allows any sender)',
            'recommendation': 'Change to ~all (soft fail) or -all (hard fail)'
        })
    elif '?all' in mechanisms:
        issues.append({
            'severity': 'HIGH',
            'issue': 'SPF record contains ?all (neutral - no policy)',
            'recommendation': 'Change to ~all (soft fail) or -all (hard fail)'
        })
    elif '~all' not in mechanisms and '-all' not in mechanisms:
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'SPF record missing all mechanism',
            'recommendation': 'Add ~all or -all to define failure policy'
        })
    
    # Count DNS lookups (RFC 7208 limit is 10)
    dns_lookup_mechanisms = ['include:', 'a:', 'mx:', 'exists:', 'redirect=']
    dns_lookup_count = 0
    
    for mechanism in mechanisms:
        for lookup_type in dns_lookup_mechanisms:
            if mechanism.startswith(lookup_type):
                dns_lookup_count += 1
                break
    
    if dns_lookup_count > 10:
        issues.append({
            'severity': 'CRITICAL',
            'issue': f'SPF record has {dns_lookup_count} DNS lookups (RFC limit: 10)',
            'recommendation': 'Reduce DNS lookups by flattening includes or removing unused mechanisms'
        })
    elif dns_lookup_count > 8:
        issues.append({
            'severity': 'MEDIUM',
            'issue': f'SPF record has {dns_lookup_count} DNS lookups (approaching limit of 10)',
            'recommendation': 'Consider optimizing to reduce DNS lookups'
        })
    
    # Check for overly broad mechanisms
    for mechanism in mechanisms:
        if mechanism.startswith('ip4:'):
            ip_range = mechanism[4:]
            if '/' in ip_range:
                try:
                    prefix = int(ip_range.split('/')[-1])
                    if prefix < 16:
                        issues.append({
                            'severity': 'HIGH',
                            'issue': f'Very broad IP range in SPF: {ip_range}',
                            'recommendation': 'Use more specific IP ranges when possible'
                        })
                except ValueError:
                    pass
        elif mechanism == 'a' or mechanism == 'mx':
            issues.append({
                'severity': 'MEDIUM',
                'issue': f'Bare {mechanism} mechanism may be overly broad',
                'recommendation': f'Consider using {mechanism}:specific-domain.com for better control'
            })
    
    return issues

def analyze_dmarc_record_comprehensive(dmarc_record: str) -> List[Dict]:
    """Comprehensive DMARC record analysis."""
    issues = []
    
    # Parse DMARC record into key-value pairs
    dmarc_content = dmarc_record.lower().replace('v=dmarc1', '').strip()
    policy_parts = {}
    
    for part in dmarc_content.split(';'):
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            policy_parts[key.strip()] = value.strip()
    
    # Check policy enforcement
    policy = policy_parts.get('p', 'none')
    if policy == 'none':
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'DMARC policy is set to none (monitor only)',
            'recommendation': 'Graduate to p=quarantine then p=reject for enforcement'
        })
    elif policy == 'quarantine':
        issues.append({
            'severity': 'LOW',
            'issue': 'DMARC policy set to quarantine (good intermediate step)',
            'recommendation': 'Consider upgrading to p=reject when ready'
        })
    elif policy not in ['none', 'quarantine', 'reject']:
        issues.append({
            'severity': 'HIGH',
            'issue': f'Invalid DMARC policy: {policy}',
            'recommendation': 'Use p=none, p=quarantine, or p=reject'
        })
    
    # Check subdomain policy
    sp = policy_parts.get('sp', policy)  # Inherits from main policy if not set
    if sp != policy and sp == 'none':
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'Subdomain policy weaker than main policy',
            'recommendation': 'Consider matching subdomain policy to main policy'
        })
    
    # Check alignment settings
    aspf = policy_parts.get('aspf', 'r')  # SPF alignment (relaxed by default)
    adkim = policy_parts.get('adkim', 'r')  # DKIM alignment (relaxed by default)
    
    if aspf == 'r' and adkim == 'r':
        issues.append({
            'severity': 'LOW',
            'issue': 'Both SPF and DKIM alignment set to relaxed',
            'recommendation': 'Consider strict alignment (aspf=s, adkim=s) for better security'
        })
    
    # Check percentage
    pct = policy_parts.get('pct', '100')
    try:
        pct_value = int(pct)
        if pct_value < 100 and policy in ['quarantine', 'reject']:
            issues.append({
                'severity': 'MEDIUM',
                'issue': f'DMARC policy only applies to {pct_value}% of messages',
                'recommendation': 'Increase pct=100 when confident in policy'
            })
    except ValueError:
        issues.append({
            'severity': 'HIGH',
            'issue': f'Invalid DMARC percentage: {pct}',
            'recommendation': 'Use pct=0 to pct=100'
        })
    
    # Check for reporting URIs
    rua = policy_parts.get('rua', '')  # Aggregate reports
    ruf = policy_parts.get('ruf', '')  # Forensic reports
    
    if not rua:
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'No aggregate report URI (rua) specified',
            'recommendation': 'Add rua=mailto:dmarc-reports@yourdomain.com'
        })
    
    if policy in ['quarantine', 'reject'] and not ruf:
        issues.append({
            'severity': 'LOW',
            'issue': 'No forensic report URI (ruf) for enforcement policy',
            'recommendation': 'Consider adding ruf=mailto:dmarc-forensic@yourdomain.com'
        })
    
    return issues

def analyze_dns_record(record: Dict, zone_name: str) -> Dict:
    """Analyze a DNS record for security and configuration issues."""
    record_analysis = {
        'Name': record['Name'],
        'Type': record['Type'],
        'TTL': record.get('TTL'),
        'SetIdentifier': record.get('SetIdentifier'),
        'Weight': record.get('Weight'),
        'Failover': record.get('Failover'),
        'GeoLocation': record.get('GeoLocation'),
        'LatencyLocation': record.get('Region'),
        'HealthCheckId': record.get('HealthCheckId'),
        'AliasTarget': record.get('AliasTarget'),
        'ResourceRecords': record.get('ResourceRecords', []),
        'IsAlias': 'AliasTarget' in record,
        'SecurityIssues': [],
        'ConfigurationIssues': [],
        'OptimizationOpportunities': [],
        'RiskLevel': 'Low'
    }
    
    # Analyze record values
    values = []
    if record_analysis['ResourceRecords']:
        values = [rr['Value'] for rr in record_analysis['ResourceRecords']]
    elif record_analysis['AliasTarget']:
        values = [record_analysis['AliasTarget'].get('DNSName', '')]
    
    record_analysis['Values'] = values
    
    # TTL analysis
    if record_analysis['TTL']:
        if record_analysis['TTL'] < 300 and record_analysis['Type'] in ['A', 'AAAA', 'CNAME']:
            record_analysis['OptimizationOpportunities'].append("Very low TTL - consider increasing for better caching")
        elif record_analysis['TTL'] > 86400:  # 24 hours
            record_analysis['OptimizationOpportunities'].append("Very high TTL - may slow DNS updates")
    
    # Security analysis by record type
    if record_analysis['Type'] == 'TXT':
        for value in values:
            # Check for exposed secrets in TXT records
            sensitive_patterns = [
                r'password\s*[:=]\s*\S+',
                r'secret\s*[:=]\s*\S+',
                r'key\s*[:=]\s*\S+',
                r'token\s*[:=]\s*\S+'
            ]
            for pattern in sensitive_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    record_analysis['SecurityIssues'].append("Potential secret in TXT record")
                    record_analysis['RiskLevel'] = 'High'
                    break
            
            # Enhanced SPF analysis
            if 'v=spf1' in value.lower():
                spf_issues = analyze_spf_record_comprehensive(value)
                for issue in spf_issues:
                    if issue['severity'] == 'CRITICAL':
                        record_analysis['SecurityIssues'].append(f"SPF: {issue['issue']}")
                        record_analysis['RiskLevel'] = 'Critical'
                    elif issue['severity'] == 'HIGH':
                        record_analysis['SecurityIssues'].append(f"SPF: {issue['issue']}")
                        if record_analysis['RiskLevel'] not in ['Critical']:
                            record_analysis['RiskLevel'] = 'High'
                    elif issue['severity'] == 'MEDIUM':
                        record_analysis['ConfigurationIssues'].append(f"SPF: {issue['issue']}")
                        if record_analysis['RiskLevel'] == 'Low':
                            record_analysis['RiskLevel'] = 'Medium'
                    else:  # LOW
                        record_analysis['OptimizationOpportunities'].append(f"SPF: {issue['issue']}")
            
            # Enhanced DMARC analysis
            elif 'v=dmarc1' in value.lower():
                dmarc_issues = analyze_dmarc_record_comprehensive(value)
                for issue in dmarc_issues:
                    if issue['severity'] == 'CRITICAL':
                        record_analysis['SecurityIssues'].append(f"DMARC: {issue['issue']}")
                        record_analysis['RiskLevel'] = 'Critical'
                    elif issue['severity'] == 'HIGH':
                        record_analysis['SecurityIssues'].append(f"DMARC: {issue['issue']}")
                        if record_analysis['RiskLevel'] not in ['Critical']:
                            record_analysis['RiskLevel'] = 'High'
                    elif issue['severity'] == 'MEDIUM':
                        record_analysis['ConfigurationIssues'].append(f"DMARC: {issue['issue']}")
                        if record_analysis['RiskLevel'] == 'Low':
                            record_analysis['RiskLevel'] = 'Medium'
                    else:  # LOW
                        record_analysis['OptimizationOpportunities'].append(f"DMARC: {issue['issue']}")
            
            # Check for DKIM records
            elif '._domainkey.' in record['Name']:
                if 'v=DKIM1' not in value:
                    record_analysis['SecurityIssues'].append("Invalid DKIM record format")
                    record_analysis['RiskLevel'] = 'Medium'
                else:
                    record_analysis['OptimizationOpportunities'].append("DKIM authentication configured")
    
    elif record_analysis['Type'] == 'MX':
        for value in values:
            # Check MX priority
            try:
                priority = int(value.split()[0])
                if priority > 100:
                    record_analysis['ConfigurationIssues'].append("Very high MX priority")
            except (ValueError, IndexError):
                record_analysis['ConfigurationIssues'].append("Invalid MX record format")
    
    elif record_analysis['Type'] in ['A', 'AAAA']:
        for value in values:
            # Check for private IP addresses in public DNS
            if record_analysis['Type'] == 'A':
                if (value.startswith('10.') or 
                    value.startswith('172.') and 16 <= int(value.split('.')[1]) <= 31 or
                    value.startswith('192.168.')):
                    record_analysis['SecurityIssues'].append("Private IP in public DNS record")
                    record_analysis['RiskLevel'] = 'Medium'
    
    elif record_analysis['Type'] == 'CNAME':
        # Check for subdomain takeover vulnerability
        takeover_risk = detect_subdomain_takeover(record)
        if takeover_risk:
            record_analysis['SecurityIssues'].append(f"CRITICAL: Subdomain takeover risk - {takeover_risk['vulnerability']}")
            record_analysis['RiskLevel'] = 'Critical'
        
        # Check for development/staging targets
        for value in values:
            if any(env in value.lower() for env in ['test', 'dev', 'staging', 'tmp']):
                record_analysis['ConfigurationIssues'].append("CNAME points to development/test environment")
            
            # Check for localhost
            if value in ['127.0.0.1', '::1']:
                record_analysis['SecurityIssues'].append("Localhost IP in DNS record")
                record_analysis['RiskLevel'] = 'Medium'
    
    elif record_analysis['Type'] == 'CNAME':
        # Check for CNAME at apex
        if record_analysis['Name'].rstrip('.') == zone_name.rstrip('.'):
            record_analysis['ConfigurationIssues'].append("CNAME at zone apex (invalid)")
            record_analysis['RiskLevel'] = 'High'
        
        # Check for CNAME loops
        for value in values:
            if value.rstrip('.') == record_analysis['Name'].rstrip('.'):
                record_analysis['ConfigurationIssues'].append("CNAME pointing to itself")
                record_analysis['RiskLevel'] = 'High'
    
    elif record_analysis['Type'] == 'NS':
        # Check for delegation issues
        if record_analysis['Name'].rstrip('.') != zone_name.rstrip('.'):
            # This is a subdomain delegation
            record_analysis['ConfigurationIssues'].append("Subdomain delegation - verify NS records")
    
    # Health check analysis
    if record_analysis['HealthCheckId'] and not record_analysis['IsAlias']:
        record_analysis['OptimizationOpportunities'].append("Health check configured for non-alias record")
    
    # Routing policy analysis
    if record_analysis['Weight'] is not None:
        if record_analysis['Weight'] == 0:
            record_analysis['ConfigurationIssues'].append("Zero weight in weighted routing")
    
    return record_analysis

def analyze_hosted_zone(zone: Dict, route53_client) -> Dict:
    """Comprehensive analysis of a hosted zone."""
    zone_id = zone['Id'].split('/')[-1]
    zone_name = zone['Name']
    
    zone_analysis = {
        'ZoneId': zone_id,
        'ZoneName': zone_name,
        'CallerReference': zone['CallerReference'],
        'Config': zone.get('Config', {}),
        'ResourceRecordSetCount': zone.get('ResourceRecordSetCount', 0),
        'LinkedService': zone.get('LinkedService'),
        'IsPrivate': zone.get('Config', {}).get('PrivateZone', False),
        'Comment': zone.get('Config', {}).get('Comment', ''),
        'Tags': {},
        'Records': [],
        'RecordTypeStats': {},
        'SecurityIssues': [],
        'ConfigurationIssues': [],
        'OptimizationOpportunities': [],
        'RiskLevel': 'Low'
    }
    
    # Get zone tags
    zone_analysis['Tags'] = get_zone_tags(route53_client, zone_id)
    
    # Get and analyze all records
    print(f"  Analyzing records for {zone_name}...")
    records = get_resource_record_sets_with_pagination(route53_client, zone_id)
    
    for record in records:
        record_analysis = analyze_dns_record(record, zone_name)
        zone_analysis['Records'].append(record_analysis)
        
        # Aggregate record type statistics
        record_type = record_analysis['Type']
        zone_analysis['RecordTypeStats'][record_type] = zone_analysis['RecordTypeStats'].get(record_type, 0) + 1
        
        # Aggregate security issues
        if record_analysis['SecurityIssues']:
            zone_analysis['SecurityIssues'].extend(record_analysis['SecurityIssues'])
        
        if record_analysis['ConfigurationIssues']:
            zone_analysis['ConfigurationIssues'].extend(record_analysis['ConfigurationIssues'])
        
        if record_analysis['OptimizationOpportunities']:
            zone_analysis['OptimizationOpportunities'].extend(record_analysis['OptimizationOpportunities'])
        
        # Update zone risk level based on record risk
        if record_analysis['RiskLevel'] == 'High' and zone_analysis['RiskLevel'] != 'Critical':
            zone_analysis['RiskLevel'] = 'High'
        elif record_analysis['RiskLevel'] == 'Medium' and zone_analysis['RiskLevel'] == 'Low':
            zone_analysis['RiskLevel'] = 'Medium'
    
    # Zone-level analysis
    
    # Check for missing essential records
    has_soa = any(r['Type'] == 'SOA' for r in zone_analysis['Records'])
    has_ns = any(r['Type'] == 'NS' and r['Name'].rstrip('.') == zone_name.rstrip('.') for r in zone_analysis['Records'])
    
    if not has_soa:
        zone_analysis['ConfigurationIssues'].append("Missing SOA record")
        zone_analysis['RiskLevel'] = 'High'
    
    if not has_ns:
        zone_analysis['ConfigurationIssues'].append("Missing NS record for zone apex")
        zone_analysis['RiskLevel'] = 'High'
    
    # Check for too many records
    if len(zone_analysis['Records']) > 1000:
        zone_analysis['OptimizationOpportunities'].append("Large number of DNS records - consider optimization")
    
    # Check for unused zone
    non_system_records = [r for r in zone_analysis['Records'] if r['Type'] not in ['SOA', 'NS']]
    if len(non_system_records) == 0:
        zone_analysis['OptimizationOpportunities'].append("Zone has no user-defined records")
    
    # Security checks for public zones
    if not zone_analysis['IsPrivate']:
        # Check for wildcard records
        wildcard_records = [r for r in zone_analysis['Records'] if '*' in r['Name']]
        if wildcard_records:
            zone_analysis['SecurityIssues'].append("Wildcard DNS records present")
            if zone_analysis['RiskLevel'] == 'Low':
                zone_analysis['RiskLevel'] = 'Medium'
    
    return zone_analysis

def list_route53_zones_and_records(session=None) -> List[Dict]:
    """List and analyze all Route 53 hosted zones and records."""
    try:
        if session:
            route53_client = session.client('route53')
        else:
            route53_client = boto3.client('route53')
        
        print("Scanning Route 53 hosted zones...")
        print("Note: Route 53 is a global service")
        
        # Get all hosted zones with pagination
        print("  Retrieving hosted zones...")
        zones = get_hosted_zones_with_pagination(route53_client)
        
        if not zones:
            print("  No hosted zones found")
            return []
        
        print(f"  Found {len(zones)} hosted zones")
        
        # Analyze each zone
        analyzed_zones = []
        for i, zone in enumerate(zones):
            zone_name = zone['Name']
            print(f"  Analyzing zone {i+1}/{len(zones)}: {zone_name}")
            zone_analysis = analyze_hosted_zone(zone, route53_client)
            analyzed_zones.append(zone_analysis)
        
        return analyzed_zones
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print("  Access denied for Route 53 - check permissions")
        else:
            print(f"  Error accessing Route 53: {e.response['Error']['Message']}")
        return []

def export_to_csv(zones: List[Dict], filename: str):
    """Export zone and record data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'ZoneId', 'ZoneName', 'IsPrivate', 'RecordCount', 'RecordName', 'RecordType',
            'TTL', 'Values', 'IsAlias', 'RiskLevel', 'SecurityIssues',
            'ConfigurationIssues', 'OptimizationOpportunities', 'Tags'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for zone in zones:
            zone_tags = ', '.join([f"{k}={v}" for k, v in zone.get('Tags', {}).items()])
            
            # Write zone-level row
            zone_row = {
                'ZoneId': zone['ZoneId'],
                'ZoneName': zone['ZoneName'],
                'IsPrivate': zone['IsPrivate'],
                'RecordCount': len(zone['Records']),
                'RecordName': '',
                'RecordType': '',
                'TTL': '',
                'Values': '',
                'IsAlias': '',
                'RiskLevel': zone['RiskLevel'],
                'SecurityIssues': '; '.join(zone.get('SecurityIssues', [])),
                'ConfigurationIssues': '; '.join(zone.get('ConfigurationIssues', [])),
                'OptimizationOpportunities': '; '.join(zone.get('OptimizationOpportunities', [])),
                'Tags': zone_tags
            }
            writer.writerow(zone_row)
            
            # Write record-level rows
            for record in zone['Records']:
                record_row = {
                    'ZoneId': zone['ZoneId'],
                    'ZoneName': zone['ZoneName'],
                    'IsPrivate': zone['IsPrivate'],
                    'RecordCount': len(zone['Records']),
                    'RecordName': record['Name'],
                    'RecordType': record['Type'],
                    'TTL': record.get('TTL', ''),
                    'Values': ', '.join(record.get('Values', [])),
                    'IsAlias': record.get('IsAlias', False),
                    'RiskLevel': record.get('RiskLevel', 'Low'),
                    'SecurityIssues': '; '.join(record.get('SecurityIssues', [])),
                    'ConfigurationIssues': '; '.join(record.get('ConfigurationIssues', [])),
                    'OptimizationOpportunities': '; '.join(record.get('OptimizationOpportunities', [])),
                    'Tags': zone_tags
                }
                writer.writerow(record_row)

def export_to_json(zones: List[Dict], filename: str):
    """Export zone data to JSON."""
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(zones, jsonfile, indent=2, default=str)

def print_summary_report(zones: List[Dict]):
    """Print comprehensive summary report."""
    total_zones = len(zones)
    
    if total_zones == 0:
        print(f"\n{'='*80}")
        print("ROUTE 53 SUMMARY")
        print(f"{'='*80}")
        print("No Route 53 hosted zones found.")
        print(f"{'='*80}")
        return
    
    # Statistics
    public_zones = [z for z in zones if not z['IsPrivate']]
    private_zones = [z for z in zones if z['IsPrivate']]
    zones_with_issues = [z for z in zones if z.get('SecurityIssues') or z.get('ConfigurationIssues')]
    
    total_records = sum(len(z['Records']) for z in zones)
    
    # Record type statistics
    record_type_stats = {}
    for zone in zones:
        for record_type, count in zone.get('RecordTypeStats', {}).items():
            record_type_stats[record_type] = record_type_stats.get(record_type, 0) + count
    
    print(f"\n{'='*80}")
    print("ROUTE 53 SUMMARY")
    print(f"{'='*80}")
    print(f"Total Hosted Zones: {total_zones}")
    print(f"Public Zones: {len(public_zones)}")
    print(f"Private Zones: {len(private_zones)}")
    print(f"Total DNS Records: {total_records}")
    print(f"Zones with Issues: {len(zones_with_issues)}")
    
    # Record type distribution
    print(f"\n{'='*80}")
    print("RECORD TYPE DISTRIBUTION")
    print(f"{'='*80}")
    for record_type, count in sorted(record_type_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_records) * 100 if total_records > 0 else 0
        print(f"{record_type:10} {count:6} records ({percentage:5.1f}%)")
    
    # Zone details
    print(f"\n{'='*80}")
    print("HOSTED ZONES OVERVIEW")
    print(f"{'='*80}")
    print(f"{'Zone Name':40} {'Type':8} {'Records':8} {'Risk':8} {'Issues'}")
    print("-" * 85)
    
    for zone in zones:
        zone_type = "Private" if zone['IsPrivate'] else "Public"
        issues_count = len(zone.get('SecurityIssues', []) + zone.get('ConfigurationIssues', []))
        
        risk_indicator = {
            'Critical': '🔴',
            'High': '🟡',
            'Medium': '🟠',
            'Low': '🟢'
        }.get(zone.get('RiskLevel', 'Low'), '❓')
        
        print(f"{zone['ZoneName']:40} {zone_type:8} {len(zone['Records']):8} "
              f"{risk_indicator} {zone.get('RiskLevel', 'Low'):6} {issues_count}")
    
    # Security issues details
    security_zones = [z for z in zones if z.get('SecurityIssues')]
    if security_zones:
        print(f"\n{'='*80}")
        print("SECURITY ISSUES REQUIRING ATTENTION")
        print(f"{'='*80}")
        
        for zone in security_zones:
            print(f"\n{zone['ZoneName']} ({zone['RiskLevel']} risk):")
            for issue in zone.get('SecurityIssues', [])[:5]:  # Show top 5
                print(f"  ⚠️  {issue}")
            if len(zone.get('SecurityIssues', [])) > 5:
                print(f"  ... and {len(zone.get('SecurityIssues', [])) - 5} more issues")
    
    # Configuration issues
    config_zones = [z for z in zones if z.get('ConfigurationIssues')]
    if config_zones:
        print(f"\n{'='*80}")
        print("CONFIGURATION ISSUES")
        print(f"{'='*80}")
        
        for zone in config_zones[:5]:  # Show top 5 zones
            print(f"\n{zone['ZoneName']}:")
            for issue in zone.get('ConfigurationIssues', [])[:3]:  # Show top 3 issues
                print(f"  🔧 {issue}")
    
    # Optimization opportunities
    optimization_zones = [z for z in zones if z.get('OptimizationOpportunities')]
    if optimization_zones:
        print(f"\n{'='*80}")
        print("OPTIMIZATION OPPORTUNITIES")
        print(f"{'='*80}")
        print(f"Zones with optimization opportunities: {len(optimization_zones)}")
        
        # Common optimization opportunities
        all_opportunities = []
        for zone in optimization_zones:
            all_opportunities.extend(zone.get('OptimizationOpportunities', []))
        
        opportunity_counts = {}
        for opp in all_opportunities:
            opportunity_counts[opp] = opportunity_counts.get(opp, 0) + 1
        
        for opp, count in sorted(opportunity_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  💡 {opp} ({count} occurrences)")
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS:")
    print("- Review and fix security issues in DNS records")
    print("- Validate SPF, DKIM, and DMARC records for email security")
    print("- Remove unused zones and records to reduce costs")
    print("- Optimize TTL values for better performance")
    print("- Implement health checks for critical services")
    print("- Use alias records for AWS resources when possible")
    print(f"{'='*80}")

def send_sns_alert(zones: List[Dict], sns_topic_arn: str, session=None) -> None:
    """Send SNS notifications for critical and high risk Route53 DNS security findings."""
    try:
        # Create SNS client
        if session:
            sns_client = session.client('sns')
            sts_client = session.client('sts')
        else:
            sns_client = boto3.client('sns')
            sts_client = boto3.client('sts')
        
        # Get account ID for context
        try:
            account_id = sts_client.get_caller_identity().get('Account', 'Unknown')
        except:
            account_id = 'Unknown'
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk zones
        high_risk_zones = [z for z in zones if z.get('RiskLevel') == 'High']
        critical_zones = [z for z in zones if z.get('RiskLevel') == 'Critical']
        
        if not critical_zones and not high_risk_zones:
            print("📧 No critical or high risk Route53 DNS findings to alert")
            return
        
        # Build notification message
        subject = f"🚨 DNS Security Alert - Account {account_id}"
        
        # Calculate statistics
        total_zones = len(zones)
        total_records = sum(z.get('Statistics', {}).get('total_records', 0) for z in zones)
        zones_with_security_issues = len([z for z in zones if z.get('SecurityIssues')])
        
        # Calculate subdomain takeover statistics
        total_takeover_risks = sum(z.get('Statistics', {}).get('subdomain_takeover_risks', 0) for z in zones)
        total_cname_records = sum(z.get('Statistics', {}).get('cname_records', 0) for z in zones)
        
        message_parts = [
            f"CRITICAL DNS SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total hosted zones: {total_zones}",
            f"• Zones with security issues: {zones_with_security_issues}",
            f"• Critical risk zones: {len(critical_zones)}",
            f"• High risk zones: {len(high_risk_zones)}",
            f"• Total DNS records: {total_records}",
            f"• CNAME records analyzed: {total_cname_records}",
            f"• 🚨 SUBDOMAIN TAKEOVER RISKS: {total_takeover_risks}",
            f""
        ]
        
        # Add critical findings details
        if critical_zones:
            message_parts.append("🔴 CRITICAL RISK ZONES:")
            for zone in critical_zones:
                message_parts.append(f"  • {zone['ZoneName']} ({zone['ZoneId']})")
                message_parts.append(f"    - Zone Type: {'Private' if zone.get('Config', {}).get('PrivateZone') else 'Public'}")
                message_parts.append(f"    - Record Count: {zone.get('Statistics', {}).get('total_records', 0)}")
                for issue in zone.get('SecurityIssues', [])[:3]:  # Limit to first 3 issues
                    message_parts.append(f"    - 🚨 {issue}")
                message_parts.append(f"    - ⚠️  IMMEDIATE ACTION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_zones:
            message_parts.append("🟠 HIGH RISK ZONES (Email Security Issues):")
            for zone in high_risk_zones:
                message_parts.append(f"  • {zone['ZoneName']} ({zone['ZoneId']})")
                message_parts.append(f"    - Zone Type: {'Private' if zone.get('Config', {}).get('PrivateZone') else 'Public'}")
                message_parts.append(f"    - Record Count: {zone.get('Statistics', {}).get('total_records', 0)}")
                for issue in zone.get('SecurityIssues', [])[:3]:  # Limit to first 3 issues
                    message_parts.append(f"    - ⚠️  {issue}")
            message_parts.append("")
        
        # Add email security specific recommendations
        mx_zones = [z for z in zones if any(r.get('Type') == 'MX' for r in z.get('Records', []))]
        if mx_zones:
            message_parts.extend([
                "EMAIL SECURITY ANALYSIS:",
                f"• Zones with MX records: {len(mx_zones)}",
                f"• Missing SPF protection: {len([z for z in mx_zones if 'Zone has MX records but no SPF record' in z.get('SecurityIssues', [])])}",
                f"• Missing DMARC protection: {len([z for z in mx_zones if 'Zone has MX records but no DMARC record' in z.get('SecurityIssues', [])])}",
                ""
            ])
        
        # Add subdomain takeover analysis if any risks found
        if total_takeover_risks > 0:
            takeover_zones = [z for z in zones if z.get('Statistics', {}).get('subdomain_takeover_risks', 0) > 0]
            message_parts.extend([
                "🚨 SUBDOMAIN TAKEOVER RISKS DETECTED:",
                f"• Zones with takeover risks: {len(takeover_zones)}",
                f"• Total vulnerable CNAME records: {total_takeover_risks}",
                ""
            ])
            
            for zone in takeover_zones[:3]:  # Limit to first 3 zones
                message_parts.append(f"  • Zone: {zone['ZoneName']}")
                takeover_issues = [issue for issue in zone.get('SecurityIssues', []) if 'Subdomain takeover risk' in issue]
                for issue in takeover_issues[:2]:  # Limit to first 2 issues per zone
                    message_parts.append(f"    - {issue}")
                message_parts.append("")
        
        # Add remediation recommendations
        remediation_actions = [
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Add SPF records for all domains with MX records",
            "2. Implement DMARC policies (start with p=none, progress to p=quarantine/reject)",
            "3. Review and fix permissive SPF policies (+all, ?all)",
            "4. Implement DKIM signing for email authentication",
            "5. Monitor DNS changes and maintain security configurations",
            "6. Review private IP addresses in public DNS records",
        ]
        
        if total_takeover_risks > 0:
            remediation_actions.extend([
                "7. 🚨 URGENT: Fix subdomain takeover vulnerabilities immediately",
                "8. Remove or reclaim abandoned CNAME targets",
                "9. Audit all external service dependencies"
            ])
        
        message_parts.extend(remediation_actions)
        
        # Add email and subdomain takeover setup guidance
        setup_guidance = [
            "",
            "EMAIL SECURITY SETUP:",
            "# Add SPF record",
            'TXT @ "v=spf1 include:_spf.google.com ~all"',
            "",
            "# Add DMARC record", 
            '_dmarc TXT "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"',
            "",
            "# Add DKIM record (get from email provider)",
            'selector._domainkey TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"',
        ]
        
        if total_takeover_risks > 0:
            setup_guidance.extend([
                "",
                "SUBDOMAIN TAKEOVER REMEDIATION:",
                "# Remove vulnerable CNAME records",
                "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch file://remove-cname.json",
                "",
                "# Or reclaim the service (example for GitHub Pages)",
                "# 1. Create repository: abandoned-site",
                "# 2. Enable GitHub Pages",
                "# 3. Add CNAME file with your domain"
            ])
        
        setup_guidance.extend([
            "",
            "For detailed DNS analysis, run the Route53 Security Validator manually or check the exported reports.",
            "",
            "This alert was generated by the Route53 DNS Security Validator CLI tool."
        ])
        
        message_parts.extend(setup_guidance)
        message = "\n".join(message_parts)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        print(f"📧 SNS notification sent successfully. MessageId: {message_id}")
        print(f"📧 Notified about {len(critical_zones)} critical and {len(high_risk_zones)} high risk DNS zones")
        
    except Exception as e:
        print(f"❌ Failed to send SNS notification: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive Route 53 DNS inventory with security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic Route 53 analysis
  ./list_route53_zones_and_records.py
  
  # Full security scan including subdomain takeover detection
  ./list_route53_zones_and_records.py --check-takeovers
  
  # Export detailed report
  ./list_route53_zones_and_records.py --export-csv route53_inventory.csv
  
  # Show only zones with issues
  ./list_route53_zones_and_records.py --issues-only

ANALYSIS INCLUDES:
- DNS record validation and security checks
- SPF/DKIM/DMARC analysis for email security
- Subdomain takeover vulnerability detection (with --check-takeovers)
- TTL optimization recommendations
- Configuration issue detection
- Security risk assessment
- Cost optimization opportunities

NOTE: Route 53 is a global AWS service
"""
    )
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--issues-only', action='store_true',
                       help='Show only zones with security or configuration issues')
    parser.add_argument('--check-takeovers', action='store_true',
                       help='Check for subdomain takeover vulnerabilities (may take time)')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Maximum worker threads for subdomain takeover checks (default: 10)')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--sns-topic', help='SNS topic ARN for DNS security alerts')
    
    args = parser.parse_args()

    # Validate credentials
    if not validate_aws_credentials():
        sys.exit(1)

    try:
        # Create session
        session = None
        if args.profile:
            session = boto3.Session(profile_name=args.profile)

        print("=" * 60)

        # Analyze Route 53
        all_zones = list_route53_zones_and_records(session)

        # Perform batch subdomain takeover checking if requested
        if args.check_takeovers:
            print("\n🔍 SUBDOMAIN TAKEOVER VULNERABILITY SCAN")
            print("=" * 60)
            
            all_takeover_risks = []
            for zone in all_zones:
                zone_records = zone.get('Records', [])
                if zone_records:
                    print(f"Checking zone: {zone['ZoneName']}")
                    takeover_risks = detect_subdomain_takeovers_batch(zone_records, args.max_workers)
                    all_takeover_risks.extend(takeover_risks)
                    
                    # Add takeover risks to zone statistics
                    if takeover_risks:
                        if 'SecurityIssues' not in zone:
                            zone['SecurityIssues'] = []
                        for risk in takeover_risks:
                            zone['SecurityIssues'].append(f"Subdomain takeover: {risk['subdomain']} → {risk['target']}")
                        zone['RiskLevel'] = 'Critical'
            
            # Summary of takeover scan
            if all_takeover_risks:
                print(f"\n🚨 CRITICAL: Found {len(all_takeover_risks)} subdomain takeover vulnerabilities!")
                print("IMMEDIATE ACTION REQUIRED:")
                for risk in all_takeover_risks[:5]:  # Show first 5
                    print(f"  • {risk['subdomain']} → {risk['target']} ({risk['service']})")
                    print(f"    Issue: {risk['vulnerability']}")
                if len(all_takeover_risks) > 5:
                    print(f"  ... and {len(all_takeover_risks) - 5} more vulnerabilities")
            else:
                print("✅ No subdomain takeover vulnerabilities detected")

        # Filter results if requested
        display_zones = all_zones
        if args.issues_only:
            display_zones = [
                z for z in all_zones 
                if z.get('SecurityIssues') or z.get('ConfigurationIssues')
            ]

        # Print summary report
        print_summary_report(all_zones)

        # Export to files if requested
        if args.export_csv:
            export_to_csv(all_zones, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(all_zones, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        # Send SNS alert if topic is provided and findings exist
        if args.sns_topic:
            critical_and_high_zones = [z for z in all_zones if z.get('RiskLevel') in ['Critical', 'High']]
            if critical_and_high_zones:
                print(f"\n📧 Sending SNS alert for {len(critical_and_high_zones)} high-risk DNS zones...")
                send_sns_alert(all_zones, args.sns_topic, session)
            else:
                print("\n📧 No critical or high-risk DNS zones - no SNS alert sent")

        # Return appropriate exit code for automation
        security_issues = [z for z in all_zones if z.get('SecurityIssues')]
        critical_zones = [z for z in all_zones if z.get('RiskLevel') == 'Critical']
        config_issues = [z for z in all_zones if z.get('ConfigurationIssues')]
        
        if critical_zones:
            print(f"\n🚨 CRITICAL: Found {len(critical_zones)} zones with critical DNS issues!")
            sys.exit(2)
        elif security_issues:
            print(f"\n🔒 SECURITY: Found {len(security_issues)} zones with security issues!")
            sys.exit(1)
        elif config_issues:
            print(f"\n🔧 CONFIG: Found {len(config_issues)} zones with configuration issues!")
            sys.exit(1)
        else:
            print(f"\n✅ All Route 53 zones are properly configured!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access Route 53. Required permissions:")
            print("- route53:ListHostedZones")
            print("- route53:ListResourceRecordSets")
            print("- route53:ListTagsForResource")
        else:
            print(f"AWS API Error: {e.response['Error']['Message']}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

