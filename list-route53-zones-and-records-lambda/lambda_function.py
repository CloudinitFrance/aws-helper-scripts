#!/usr/bin/env python3
"""
List Route53 Zones and Records Inventory - Lambda Version
Serverless function for automated DNS infrastructure auditing
"""

import json
import boto3
import os
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any
import logging
from datetime import datetime, timezone
import re
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_hosted_zones_with_pagination(route53_client) -> List[Dict]:
    """Get all hosted zones with pagination."""
    zones = []
    
    try:
        paginator = route53_client.get_paginator('list_hosted_zones')
        
        for page in paginator.paginate():
            zones.extend(page['HostedZones'])
        
        return zones
        
    except ClientError as e:
        logger.warning(f"Error retrieving hosted zones: {e.response['Error']['Message']}")
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
        logger.warning(f"Error retrieving records for zone {hosted_zone_id}: {e.response['Error']['Message']}")
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
            except Exception as e:
                record = future_to_record[future]
                logger.warning(f"Error checking subdomain takeover for {record.get('Name', 'Unknown')}: {str(e)}")
    
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
    
    # Check for common typos and issues
    problematic_patterns = [
        ('include:_spf.google.com', 'include:_spf.google.com is correct'),
        ('include:spf.google.com', 'Should be include:_spf.google.com'),
        ('include:amazonses.com', 'Should be include:amazonses.com with proper subdomain'),
    ]
    
    spf_content_check = ' '.join(mechanisms)
    for pattern, recommendation in problematic_patterns:
        if pattern in spf_content_check and pattern != 'include:_spf.google.com':
            issues.append({
                'severity': 'MEDIUM',
                'issue': f'Potential SPF syntax issue: {pattern}',
                'recommendation': recommendation
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

def check_dkim_record_presence(domain: str, route53_client) -> List[Dict]:
    """Check for DKIM record presence (basic check)."""
    issues = []
    
    # This is a simplified check - in practice, DKIM selectors vary by provider
    common_selectors = ['default', 'selector1', 'selector2', 'google', 'amazonses', 'k1']
    
    try:
        # Get all records for the domain
        response = route53_client.list_resource_record_sets(HostedZoneId=domain)
        records = response.get('ResourceRecordSets', [])
        
        # Look for DKIM records
        dkim_records = [r for r in records if r['Type'] == 'TXT' and '._domainkey.' in r['Name']]
        
        if not dkim_records:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'No DKIM records found',
                'recommendation': 'Implement DKIM signing with your email provider'
            })
        else:
            # Basic DKIM record validation
            for record in dkim_records:
                for rr in record.get('ResourceRecords', []):
                    value = rr.get('Value', '').strip('"')
                    if 'v=DKIM1' not in value:
                        issues.append({
                            'severity': 'MEDIUM',
                            'issue': f'Invalid DKIM record format in {record["Name"]}',
                            'recommendation': 'Ensure DKIM record starts with v=DKIM1'
                        })
    
    except Exception as e:
        logger.warning(f"Could not check DKIM records: {str(e)}")
    
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
    record_values = []
    if record_analysis['IsAlias']:
        alias_target = record_analysis['AliasTarget']
        record_values.append(alias_target.get('DNSName', ''))
    else:
        record_values = [rr.get('Value', '') for rr in record_analysis['ResourceRecords']]
    
    # Security analysis based on record type
    if record['Type'] == 'A':
        for value in record_values:
            if value.startswith('127.') or value.startswith('10.') or value.startswith('192.168.') or value.startswith('172.'):
                if not value.startswith('127.'):  # Allow localhost but flag private IPs
                    record_analysis['SecurityIssues'].append(f"Private IP address: {value}")
                    record_analysis['RiskLevel'] = 'Medium'
    
    elif record['Type'] == 'CNAME':
        for value in record_values:
            if 'test' in value.lower() or 'dev' in value.lower() or 'staging' in value.lower():
                record_analysis['ConfigurationIssues'].append("CNAME points to development/test environment")
        
        # Check for subdomain takeover vulnerability
        takeover_risk = detect_subdomain_takeover(record)
        if takeover_risk:
            record_analysis['SecurityIssues'].append(f"CRITICAL: Subdomain takeover risk - {takeover_risk['vulnerability']}")
            record_analysis['RiskLevel'] = 'Critical'
    
    elif record['Type'] == 'MX':
        if not record_values:
            record_analysis['SecurityIssues'].append("MX record with no mail servers")
            record_analysis['RiskLevel'] = 'High'
    
    elif record['Type'] == 'TXT':
        for value in record_values:
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
    
    # TTL analysis
    if record_analysis['TTL']:
        if record_analysis['TTL'] < 300:  # 5 minutes
            record_analysis['ConfigurationIssues'].append("Very low TTL may cause high query volume")
        elif record_analysis['TTL'] > 86400:  # 24 hours
            record_analysis['OptimizationOpportunities'].append("High TTL may slow DNS updates")
    else:
        if record_analysis['IsAlias']:
            record_analysis['OptimizationOpportunities'].append("Using alias record (good practice)")
    
    # Health check analysis
    if record_analysis['HealthCheckId']:
        record_analysis['OptimizationOpportunities'].append("Health check configured")
    elif record['Type'] in ['A', 'AAAA'] and not record_analysis['IsAlias']:
        record_analysis['OptimizationOpportunities'].append("Consider adding health check for critical records")
    
    # Weighted/latency routing analysis
    if record_analysis['Weight'] is not None:
        record_analysis['OptimizationOpportunities'].append("Using weighted routing")
    if record_analysis['LatencyLocation']:
        record_analysis['OptimizationOpportunities'].append("Using latency-based routing")
    if record_analysis['GeoLocation']:
        record_analysis['OptimizationOpportunities'].append("Using geo-location routing")
    
    return record_analysis

def analyze_hosted_zone(zone: Dict, route53_client) -> Dict:
    """Comprehensive analysis of a hosted zone."""
    zone_id = zone['Id'].replace('/hostedzone/', '')
    zone_name = zone['Name']
    
    zone_analysis = {
        'Id': zone_id,
        'Name': zone_name,
        'CallerReference': zone.get('CallerReference', ''),
        'Config': zone.get('Config', {}),
        'ResourceRecordSetCount': zone.get('ResourceRecordSetCount', 0),
        'LinkedService': zone.get('LinkedService'),
        'Tags': {},
        'Records': [],
        'Statistics': {
            'total_records': 0,
            'record_types': {},
            'alias_records': 0,
            'weighted_records': 0,
            'latency_records': 0,
            'geo_records': 0,
            'health_checked_records': 0,
            'security_issues': 0,
            'configuration_issues': 0,
            'optimization_opportunities': 0,
            'subdomain_takeover_risks': 0,
            'cname_records': 0
        },
        'SecurityIssues': [],
        'ConfigurationIssues': [],
        'OptimizationOpportunities': [],
        'RiskLevel': 'Low'
    }
    
    # Get zone tags
    zone_analysis['Tags'] = get_zone_tags(route53_client, zone_id)
    
    # Get all DNS records for the zone
    logger.info(f"Analyzing zone: {zone_name}")
    records = get_resource_record_sets_with_pagination(route53_client, zone_id)
    
    for record in records:
        record_analysis = analyze_dns_record(record, zone_name)
        zone_analysis['Records'].append(record_analysis)
        
        # Update statistics
        zone_analysis['Statistics']['total_records'] += 1
        
        record_type = record_analysis['Type']
        zone_analysis['Statistics']['record_types'][record_type] = \
            zone_analysis['Statistics']['record_types'].get(record_type, 0) + 1
        
        if record_analysis['IsAlias']:
            zone_analysis['Statistics']['alias_records'] += 1
        
        if record_analysis['Weight'] is not None:
            zone_analysis['Statistics']['weighted_records'] += 1
        
        if record_analysis['LatencyLocation']:
            zone_analysis['Statistics']['latency_records'] += 1
        
        if record_analysis['GeoLocation']:
            zone_analysis['Statistics']['geo_records'] += 1
        
        if record_analysis['HealthCheckId']:
            zone_analysis['Statistics']['health_checked_records'] += 1
        
        # Count CNAME records for subdomain takeover analysis
        if record_analysis['Type'] == 'CNAME':
            zone_analysis['Statistics']['cname_records'] += 1
        
        # Count subdomain takeover risks
        if any('Subdomain takeover risk' in issue for issue in record_analysis['SecurityIssues']):
            zone_analysis['Statistics']['subdomain_takeover_risks'] += 1
        
        # Aggregate issues
        if record_analysis['SecurityIssues']:
            zone_analysis['Statistics']['security_issues'] += len(record_analysis['SecurityIssues'])
            zone_analysis['SecurityIssues'].extend(record_analysis['SecurityIssues'])
        
        if record_analysis['ConfigurationIssues']:
            zone_analysis['Statistics']['configuration_issues'] += len(record_analysis['ConfigurationIssues'])
            zone_analysis['ConfigurationIssues'].extend(record_analysis['ConfigurationIssues'])
        
        if record_analysis['OptimizationOpportunities']:
            zone_analysis['Statistics']['optimization_opportunities'] += len(record_analysis['OptimizationOpportunities'])
            zone_analysis['OptimizationOpportunities'].extend(record_analysis['OptimizationOpportunities'])
        
        # Update zone risk level
        if record_analysis['RiskLevel'] == 'Critical':
            zone_analysis['RiskLevel'] = 'Critical'
        elif record_analysis['RiskLevel'] == 'High' and zone_analysis['RiskLevel'] not in ['Critical']:
            zone_analysis['RiskLevel'] = 'High'
        elif record_analysis['RiskLevel'] == 'Medium' and zone_analysis['RiskLevel'] == 'Low':
            zone_analysis['RiskLevel'] = 'Medium'
    
    # Zone-level analysis
    if zone_analysis['Config'].get('PrivateZone', False):
        zone_analysis['OptimizationOpportunities'].append("Private hosted zone (good for internal resources)")
    
    # Enhanced email security analysis
    mx_records = [r for r in zone_analysis['Records'] if r['Type'] == 'MX']
    spf_records = [r for r in zone_analysis['Records'] if r['Type'] == 'TXT' and any('v=spf1' in str(rr.get('Value', '')) for rr in r['ResourceRecords'])]
    dmarc_records = [r for r in zone_analysis['Records'] if r['Type'] == 'TXT' and any('v=dmarc1' in str(rr.get('Value', '')) for rr in r['ResourceRecords'])]
    dkim_records = [r for r in zone_analysis['Records'] if r['Type'] == 'TXT' and '._domainkey.' in r['Name']]
    
    if mx_records:
        # Zone has email capabilities, check for email security
        if not spf_records:
            zone_analysis['SecurityIssues'].append("Zone has MX records but no SPF record - emails may be marked as spam")
            if zone_analysis['RiskLevel'] not in ['Critical']:
                zone_analysis['RiskLevel'] = 'High'
        
        if not dmarc_records:
            zone_analysis['SecurityIssues'].append("Zone has MX records but no DMARC record - no email authentication policy")
            if zone_analysis['RiskLevel'] == 'Low':
                zone_analysis['RiskLevel'] = 'Medium'
        
        if not dkim_records:
            zone_analysis['ConfigurationIssues'].append("Zone has MX records but no DKIM records - consider implementing DKIM signing")
        
        # Check for SPF+DMARC without DKIM (suboptimal)
        if spf_records and dmarc_records and not dkim_records:
            zone_analysis['OptimizationOpportunities'].append("Email security partially implemented - add DKIM for complete authentication")
        
        # Check for comprehensive email security
        if spf_records and dmarc_records and dkim_records:
            zone_analysis['OptimizationOpportunities'].append("Comprehensive email security implemented (SPF + DMARC + DKIM)")
    
    # Additional DKIM analysis
    if dkim_records and not mx_records:
        zone_analysis['ConfigurationIssues'].append("DKIM records found but no MX records - unusual configuration")
    
    # Remove duplicates from issues lists
    zone_analysis['SecurityIssues'] = list(set(zone_analysis['SecurityIssues']))
    zone_analysis['ConfigurationIssues'] = list(set(zone_analysis['ConfigurationIssues']))
    zone_analysis['OptimizationOpportunities'] = list(set(zone_analysis['OptimizationOpportunities']))
    
    # Limit records in response for performance
    zone_analysis['Records'] = zone_analysis['Records'][:100]  # Limit to first 100 records
    
    return zone_analysis

def list_route53_zones_and_records() -> Dict:
    """
    List all Route53 hosted zones and their DNS records.
    """
    try:
        route53_client = boto3.client('route53')
        
        logger.info("Listing Route53 hosted zones...")
        
        # Get all hosted zones
        zones = get_hosted_zones_with_pagination(route53_client)
        
        if not zones:
            logger.info("No hosted zones found")
            return {
                'hosted_zones': [],
                'statistics': {
                    'total_zones': 0,
                    'private_zones': 0,
                    'public_zones': 0,
                    'total_records': 0,
                    'zones_with_security_issues': 0,
                    'zones_with_config_issues': 0,
                    'record_type_distribution': {},
                    'risk_distribution': {}
                },
                'errors': []
            }
        
        logger.info(f"Found {len(zones)} hosted zones")
        
        # Analyze each zone
        analyzed_zones = []
        for zone in zones:
            zone_analysis = analyze_hosted_zone(zone, route53_client)
            analyzed_zones.append(zone_analysis)
        
        # Calculate summary statistics
        total_zones = len(analyzed_zones)
        private_zones = len([z for z in analyzed_zones if z['Config'].get('PrivateZone', False)])
        public_zones = total_zones - private_zones
        total_records = sum(z['Statistics']['total_records'] for z in analyzed_zones)
        zones_with_security_issues = len([z for z in analyzed_zones if z['SecurityIssues']])
        zones_with_config_issues = len([z for z in analyzed_zones if z['ConfigurationIssues']])
        
        # Record type distribution
        record_type_distribution = {}
        risk_distribution = {}
        
        for zone in analyzed_zones:
            for record_type, count in zone['Statistics']['record_types'].items():
                record_type_distribution[record_type] = record_type_distribution.get(record_type, 0) + count
            
            risk_level = zone['RiskLevel']
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        results = {
            'hosted_zones': analyzed_zones,
            'statistics': {
                'total_zones': total_zones,
                'private_zones': private_zones,
                'public_zones': public_zones,
                'total_records': total_records,
                'zones_with_security_issues': zones_with_security_issues,
                'zones_with_config_issues': zones_with_config_issues,
                'record_type_distribution': record_type_distribution,
                'risk_distribution': risk_distribution,
                'average_records_per_zone': round(total_records / max(total_zones, 1), 1)
            },
            'errors': []
        }
        
        logger.info(f"Completed Route53 analysis: {total_zones} zones, {total_records} records")
        return results
        
    except ClientError as e:
        error_message = f"Error listing Route53 zones: {e.response['Error']['Message']}"
        logger.error(error_message)
        return {
            'hosted_zones': [],
            'statistics': {
                'total_zones': 0,
                'private_zones': 0,
                'public_zones': 0,
                'total_records': 0,
                'zones_with_security_issues': 0,
                'zones_with_config_issues': 0,
                'record_type_distribution': {},
                'risk_distribution': {},
                'average_records_per_zone': 0
            },
            'errors': [error_message]
        }

def send_security_notifications(results: Dict, account_id: str) -> None:
    """Send SNS notifications for critical and high risk Route53 DNS security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk zones
        high_risk_zones = [z for z in results['hosted_zones'] if z['RiskLevel'] == 'High']
        critical_zones = [z for z in results['hosted_zones'] if z['RiskLevel'] == 'Critical']
        
        if not critical_zones and not high_risk_zones:
            logger.info("No critical or high risk Route53 DNS findings to notify")
            return
        
        # Build notification message
        subject = f"🚨 DNS Security Alert - Account {account_id}"
        
        # Calculate subdomain takeover statistics
        total_takeover_risks = sum(z['Statistics'].get('subdomain_takeover_risks', 0) for z in results['hosted_zones'])
        total_cname_records = sum(z['Statistics'].get('cname_records', 0) for z in results['hosted_zones'])
        
        message_parts = [
            f"CRITICAL DNS SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total hosted zones: {results['statistics']['total_zones']}",
            f"• Zones with security issues: {results['statistics']['zones_with_security_issues']}",
            f"• Critical risk zones: {len(critical_zones)}",
            f"• High risk zones: {len(high_risk_zones)}",
            f"• Total DNS records: {results['statistics']['total_records']}",
            f"• CNAME records analyzed: {total_cname_records}",
            f"• 🚨 SUBDOMAIN TAKEOVER RISKS: {total_takeover_risks}",
            f""
        ]
        
        # Add critical findings details
        if critical_zones:
            message_parts.append("🔴 CRITICAL RISK ZONES:")
            for zone in critical_zones:
                message_parts.append(f"  • {zone['Name']} ({zone['Id']})")
                message_parts.append(f"    - Zone Type: {'Private' if zone['Config'].get('PrivateZone') else 'Public'}")
                message_parts.append(f"    - Record Count: {zone['Statistics']['total_records']}")
                for issue in zone['SecurityIssues'][:3]:  # Limit to first 3 issues
                    message_parts.append(f"    - 🚨 {issue}")
                message_parts.append(f"    - ⚠️  IMMEDIATE ACTION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_zones:
            message_parts.append("🟠 HIGH RISK ZONES (Email Security Issues):")
            for zone in high_risk_zones:
                message_parts.append(f"  • {zone['Name']} ({zone['Id']})")
                message_parts.append(f"    - Zone Type: {'Private' if zone['Config'].get('PrivateZone') else 'Public'}")
                message_parts.append(f"    - Record Count: {zone['Statistics']['total_records']}")
                for issue in zone['SecurityIssues'][:3]:  # Limit to first 3 issues
                    message_parts.append(f"    - ⚠️  {issue}")
            message_parts.append("")
        
        # Add email security specific recommendations
        mx_zones = [z for z in results['hosted_zones'] if any(r['Type'] == 'MX' for r in z['Records'])]
        if mx_zones:
            message_parts.extend([
                "EMAIL SECURITY ANALYSIS:",
                f"• Zones with MX records: {len(mx_zones)}",
                f"• Missing SPF protection: {len([z for z in mx_zones if 'Zone has MX records but no SPF record' in z['SecurityIssues']])}",
                f"• Missing DMARC protection: {len([z for z in mx_zones if 'Zone has MX records but no DMARC record' in z['SecurityIssues']])}",
                ""
            ])
        
        # Add subdomain takeover analysis if any risks found
        if total_takeover_risks > 0:
            takeover_zones = [z for z in results['hosted_zones'] if z['Statistics'].get('subdomain_takeover_risks', 0) > 0]
            message_parts.extend([
                "🚨 SUBDOMAIN TAKEOVER RISKS DETECTED:",
                f"• Zones with takeover risks: {len(takeover_zones)}",
                f"• Total vulnerable CNAME records: {total_takeover_risks}",
                ""
            ])
            
            for zone in takeover_zones[:3]:  # Limit to first 3 zones
                message_parts.append(f"  • Zone: {zone['Name']}")
                takeover_issues = [issue for issue in zone['SecurityIssues'] if 'Subdomain takeover risk' in issue]
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
            "For detailed DNS security guidance, check CISA DNS security recommendations.",
            "",
            "This alert was generated by the automated Route53 DNS Security Audit function."
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
        logger.info(f"SNS notification sent successfully. MessageId: {message_id}")
        logger.info(f"Notified about {len(critical_zones)} critical and {len(high_risk_zones)} high risk DNS zones")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for Route53 zones and records inventory
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with inventory results
    """
    try:
        logger.info("Starting Route53 zones and records inventory")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Inventorying Route53 in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform inventory
        results = list_route53_zones_and_records()
        
        # Determine if alerts should be triggered
        alerts_triggered = (results['statistics']['zones_with_security_issues'] > 0 or 
                          results['statistics']['risk_distribution'].get('High', 0) > 0 or
                          results['statistics']['risk_distribution'].get('Critical', 0) > 0 or
                          len(results['errors']) > 0)
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Inventory completed. "
                   f"Zones: {results['statistics']['total_zones']}, "
                   f"Records: {results['statistics']['total_records']}, "
                   f"Security issues: {results['statistics']['zones_with_security_issues']}")
        
        if results['statistics']['total_zones'] == 0:
            logger.info("No Route53 hosted zones found")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(results, account_id)
            logger.warning(f"ROUTE53 SECURITY ALERT: {results['statistics']['zones_with_security_issues']} zones with security issues")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'Route53 inventory completed successfully',
                'results': {
                    'inventory_data': results,
                    'inventory_parameters': {
                        'account_id': account_id,
                        'caller_arn': caller_arn
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"Route53 inventory failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Route53 inventory failed',
                'executionId': context.aws_request_id
            }
        }