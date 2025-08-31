#!/usr/bin/env python3
"""
Comprehensive AWS KMS keys inventory across regions with usage and security analysis.

This script provides a complete overview of KMS keys including usage patterns,
security configuration, cost optimization opportunities, and compliance checks.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional

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

# Comprehensive list of AWS regions as of 2024
AWS_REGIONS = [
    # US East (N. Virginia, Ohio)
    'us-east-1', 'us-east-2',
    # US West (N. California, Oregon)
    'us-west-1', 'us-west-2',
    # Africa (Cape Town)
    'af-south-1',
    # Asia Pacific (Hong Kong, Hyderabad, Jakarta, Melbourne, Mumbai, Osaka, Seoul, Singapore, Sydney, Tokyo)
    'ap-east-1', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 
    'ap-southeast-3', 'ap-southeast-4', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    # Canada (Central, West)
    'ca-central-1', 'ca-west-1',
    # Europe (Frankfurt, Ireland, London, Milan, Paris, Spain, Stockholm, Zurich)
    'eu-central-1', 'eu-central-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 
    'eu-south-1', 'eu-south-2', 'eu-north-1',
    # Middle East (Bahrain, UAE)
    'me-south-1', 'me-central-1',
    # South America (São Paulo)
    'sa-east-1',
    # Israel (Tel Aviv)
    'il-central-1',
]

def get_available_regions(ec2_client) -> List[str]:
    """Get list of available KMS regions."""
    return AWS_REGIONS

def get_kms_keys_with_pagination(kms_client) -> List[Dict]:
    """Get all KMS keys with pagination."""
    keys = []
    
    try:
        paginator = kms_client.get_paginator('list_keys')
        
        for page in paginator.paginate():
            keys.extend(page['Keys'])
        
        return keys
        
    except ClientError as e:
        print(f"Error retrieving KMS keys: {e.response['Error']['Message']}")
        return []

def get_key_policies(kms_client, key_id: str) -> Dict:
    """Get key policies and policy names."""
    try:
        # Get policy names
        policy_names_response = kms_client.list_key_policies(KeyId=key_id)
        policy_names = policy_names_response.get('PolicyNames', [])
        
        policies = {}
        for policy_name in policy_names:
            try:
                policy_response = kms_client.get_key_policy(KeyId=key_id, PolicyName=policy_name)
                policies[policy_name] = policy_response.get('Policy', '')
            except ClientError:
                continue
        
        return policies
    except ClientError:
        return {}

def get_key_grants(kms_client, key_id: str) -> List[Dict]:
    """Get grants for a KMS key."""
    try:
        paginator = kms_client.get_paginator('list_grants')
        grants = []
        
        for page in paginator.paginate(KeyId=key_id):
            grants.extend(page['Grants'])
        
        return grants
    except ClientError:
        return []

def get_key_aliases(kms_client, key_id: str) -> List[str]:
    """Get aliases for a KMS key."""
    try:
        paginator = kms_client.get_paginator('list_aliases')
        aliases = []
        
        for page in paginator.paginate():
            for alias in page['Aliases']:
                if alias.get('TargetKeyId') == key_id:
                    aliases.append(alias['AliasName'])
        
        return aliases
    except ClientError:
        return []

def analyze_kms_key(key: Dict, region: str, kms_client) -> Dict:
    """Comprehensive analysis of a KMS key."""
    key_id = key['KeyId']
    
    # Get detailed key metadata
    try:
        key_metadata_response = kms_client.describe_key(KeyId=key_id)
        key_metadata = key_metadata_response['KeyMetadata']
    except ClientError as e:
        return {
            'Region': region,
            'KeyId': key_id,
            'Error': f"Failed to describe key: {e.response['Error']['Message']}"
        }
    
    key_analysis = {
        'Region': region,
        'KeyId': key_id,
        'KeyArn': key_metadata.get('Arn', ''),
        'Description': key_metadata.get('Description', ''),
        'KeyUsage': key_metadata.get('KeyUsage', 'ENCRYPT_DECRYPT'),
        'KeyState': key_metadata.get('KeyState', 'Unknown'),
        'Enabled': key_metadata.get('Enabled', False),
        'Origin': key_metadata.get('Origin', 'AWS_KMS'),
        'KeyManager': key_metadata.get('KeyManager', 'CUSTOMER'),
        'CustomerMasterKeySpec': key_metadata.get('CustomerMasterKeySpec', 'SYMMETRIC_DEFAULT'),
        'EncryptionAlgorithms': key_metadata.get('EncryptionAlgorithms', []),
        'SigningAlgorithms': key_metadata.get('SigningAlgorithms', []),
        'CreationDate': key_metadata.get('CreationDate'),
        'DeletionDate': key_metadata.get('DeletionDate'),
        'ValidTo': key_metadata.get('ValidTo'),
        'MultiRegion': key_metadata.get('MultiRegion', False),
        'MultiRegionConfiguration': key_metadata.get('MultiRegionConfiguration', {}),
        'PendingDeletionWindowInDays': key_metadata.get('PendingDeletionWindowInDays'),
        'Aliases': [],
        'LastUsedDate': None,
        'DaysSinceLastUsed': None,
        'Grants': [],
        'Policies': {},
        'SecurityIssues': [],
        'CostOptimizationOpportunities': [],
        'ComplianceIssues': [],
        'RiskLevel': 'Low',
        'UsageLevel': 'Active'
    }
    
    # Skip AWS managed keys unless specifically requested
    if key_analysis['KeyManager'] == 'AWS':
        return None
    
    # Get last used date
    try:
        usage_response = kms_client.get_key_last_used_date(KeyId=key_id)
        last_used = usage_response.get('KeyLastUsedDate')
        if last_used:
            key_analysis['LastUsedDate'] = last_used
            days_since_used = (datetime.now(timezone.utc) - last_used).days
            key_analysis['DaysSinceLastUsed'] = days_since_used
        else:
            key_analysis['DaysSinceLastUsed'] = None
    except ClientError:
        key_analysis['DaysSinceLastUsed'] = None
    
    # Get aliases
    key_analysis['Aliases'] = get_key_aliases(kms_client, key_id)
    
    # Get grants
    key_analysis['Grants'] = get_key_grants(kms_client, key_id)
    
    # Get policies
    key_analysis['Policies'] = get_key_policies(kms_client, key_id)
    
    # Get tags
    try:
        tags_response = kms_client.list_resource_tags(KeyId=key_id)
        tags = {tag['TagKey']: tag['TagValue'] for tag in tags_response.get('Tags', [])}
        key_analysis['Tags'] = tags
    except ClientError:
        key_analysis['Tags'] = {}
    
    # Security and compliance analysis
    
    # Key state analysis
    if key_analysis['KeyState'] == 'PendingDeletion':
        key_analysis['SecurityIssues'].append("Key is scheduled for deletion")
        key_analysis['RiskLevel'] = 'Critical'
    elif key_analysis['KeyState'] == 'Disabled':
        key_analysis['SecurityIssues'].append("Key is disabled")
        key_analysis['RiskLevel'] = 'Medium'
    elif not key_analysis['Enabled']:
        key_analysis['SecurityIssues'].append("Key is not enabled")
        key_analysis['RiskLevel'] = 'Medium'
    
    # Usage analysis
    if key_analysis['DaysSinceLastUsed'] is not None:
        if key_analysis['DaysSinceLastUsed'] > 365:
            key_analysis['CostOptimizationOpportunities'].append("Key not used in over a year")
            key_analysis['UsageLevel'] = 'Unused'
        elif key_analysis['DaysSinceLastUsed'] > 90:
            key_analysis['CostOptimizationOpportunities'].append("Key not used in over 90 days")
            key_analysis['UsageLevel'] = 'Inactive'
        elif key_analysis['DaysSinceLastUsed'] > 30:
            key_analysis['UsageLevel'] = 'Low'
    elif key_analysis['DaysSinceLastUsed'] is None and key_analysis['KeyState'] == 'Enabled':
        key_analysis['CostOptimizationOpportunities'].append("Key has never been used")
        key_analysis['UsageLevel'] = 'Never Used'
    
    # Policy analysis
    if not key_analysis['Policies']:
        key_analysis['SecurityIssues'].append("No key policies found")
        if key_analysis['RiskLevel'] == 'Low':
            key_analysis['RiskLevel'] = 'Medium'
    
    # Check for overly permissive policies
    for policy_name, policy_content in key_analysis['Policies'].items():
        if '"*"' in policy_content and '"Resource": "*"' in policy_content:
            key_analysis['SecurityIssues'].append("Policy allows access to all resources")
            key_analysis['RiskLevel'] = 'High'
        
        if '"Principal": "*"' in policy_content:
            key_analysis['SecurityIssues'].append("Policy allows access from any principal")
            key_analysis['RiskLevel'] = 'Critical'
    
    # Grants analysis
    if len(key_analysis['Grants']) > 10:
        key_analysis['SecurityIssues'].append(f"High number of grants ({len(key_analysis['Grants'])})")
    
    # Check for external grants
    for grant in key_analysis['Grants']:
        grantee_principal = grant.get('GranteePrincipal', '')
        if ':root' in grantee_principal and grantee_principal.split(':')[4] != key_analysis['KeyArn'].split(':')[4]:
            key_analysis['SecurityIssues'].append("Grant to external AWS account")
            if key_analysis['RiskLevel'] in ['Low', 'Medium']:
                key_analysis['RiskLevel'] = 'High'
    
    # Origin analysis
    if key_analysis['Origin'] == 'EXTERNAL':
        key_analysis['ComplianceIssues'].append("External key material - verify compliance requirements")
    
    # Multi-region analysis
    if key_analysis['MultiRegion']:
        key_analysis['ComplianceIssues'].append("Multi-region key - verify data residency requirements")
    
    # Encryption algorithm analysis
    if 'RSA_2048' in key_analysis.get('EncryptionAlgorithms', []):
        key_analysis['SecurityIssues'].append("Using RSA_2048 - consider stronger algorithms")
    
    # Age analysis
    if key_analysis['CreationDate']:
        days_old = (datetime.now(timezone.utc) - key_analysis['CreationDate']).days
        key_analysis['DaysOld'] = days_old
        
        if days_old > 1095:  # 3 years
            key_analysis['ComplianceIssues'].append("Key is over 3 years old - consider rotation")
    else:
        key_analysis['DaysOld'] = 0
    
    # Alias analysis
    if not key_analysis['Aliases']:
        key_analysis['CostOptimizationOpportunities'].append("No aliases defined - consider adding for easier management")
    
    return key_analysis

def list_kms_keys_in_region(region: str, session=None, include_aws_managed=False) -> List[Dict]:
    """List and analyze KMS keys in a specific region."""
    try:
        if session:
            kms_client = session.client('kms', region_name=region)
        else:
            kms_client = boto3.client('kms', region_name=region)
        
        print(f"Scanning region: {region}")
        
        # Get all KMS keys with pagination
        print("  Retrieving KMS keys...")
        keys = get_kms_keys_with_pagination(kms_client)
        
        if not keys:
            print(f"  No KMS keys found in {region}")
            return []
        
        print(f"  Found {len(keys)} KMS keys")
        
        # Analyze each key
        analyzed_keys = []
        for i, key in enumerate(keys):
            print(f"  Analyzing {i+1}/{len(keys)}: {key['KeyId'][:8]}...")
            key_analysis = analyze_kms_key(key, region, kms_client)
            
            # Filter AWS managed keys unless requested
            if key_analysis and (include_aws_managed or key_analysis.get('KeyManager') == 'CUSTOMER'):
                analyzed_keys.append(key_analysis)
        
        customer_managed_count = len([k for k in analyzed_keys if k.get('KeyManager') == 'CUSTOMER'])
        print(f"  Found {customer_managed_count} customer-managed keys")
        
        return analyzed_keys
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"  Access denied for region {region} - skipping")
        else:
            print(f"  Error in region {region}: {e.response['Error']['Message']}")
        return []

def export_to_csv(keys: List[Dict], filename: str):
    """Export key data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Region', 'KeyId', 'Description', 'KeyUsage', 'KeyState', 'Enabled',
            'Origin', 'KeyManager', 'CustomerMasterKeySpec', 'MultiRegion',
            'DaysSinceLastUsed', 'UsageLevel', 'DaysOld', 'AliasCount', 'GrantsCount',
            'RiskLevel', 'SecurityIssues', 'CostOptimizationOpportunities',
            'ComplianceIssues', 'Aliases', 'Tags'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for key in keys:
            row = key.copy()
            # Convert lists and complex types to strings for CSV
            row['SecurityIssues'] = '; '.join(key.get('SecurityIssues', []))
            row['CostOptimizationOpportunities'] = '; '.join(key.get('CostOptimizationOpportunities', []))
            row['ComplianceIssues'] = '; '.join(key.get('ComplianceIssues', []))
            row['Aliases'] = ', '.join(key.get('Aliases', []))
            row['AliasCount'] = len(key.get('Aliases', []))
            row['GrantsCount'] = len(key.get('Grants', []))
            row['Tags'] = ', '.join([f"{k}={v}" for k, v in key.get('Tags', {}).items()])
            writer.writerow(row)

def export_to_json(keys: List[Dict], filename: str):
    """Export key data to JSON."""
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(keys, jsonfile, indent=2, default=str)

def send_security_notifications(keys: List[Dict], account_id: str, sns_topic_arn: str = None, session=None) -> None:
    """Send SNS notifications for critical and high risk KMS key security findings."""
    try:
        if not sns_topic_arn:
            print("Warning: No SNS topic ARN provided, skipping security notifications")
            return
        
        if session:
            sns_client = session.client('sns')
        else:
            sns_client = boto3.client('sns')
        
        # Calculate summary statistics
        total_keys = len(keys)
        if total_keys == 0:
            return
        
        # Calculate risk distribution
        critical_risk_keys = len([k for k in keys if k.get('RiskLevel') == 'Critical'])
        high_risk_keys = len([k for k in keys if k.get('RiskLevel') == 'High'])
        unused_keys = len([k for k in keys if k.get('UsageLevel') in ['Unused', 'Never Used']])
        enabled_keys = len([k for k in keys if k.get('Enabled')])
        security_issues = len([k for k in keys if k.get('SecurityIssues')])
        
        # Calculate security score
        if total_keys > 0:
            enabled_score = (enabled_keys / total_keys) * 30
            usage_score = ((total_keys - unused_keys) / total_keys) * 40  
            security_score = ((total_keys - security_issues) / total_keys) * 30
            overall_security_score = round(enabled_score + usage_score + security_score, 1)
        else:
            overall_security_score = 100
        
        # Determine if notification is needed
        needs_notification = (critical_risk_keys > 0 or 
                            high_risk_keys > 0 or 
                            overall_security_score < 70 or 
                            unused_keys > 20)
        
        if not needs_notification:
            print("No critical or high risk KMS key findings to notify")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Determine risk level and subject
        if critical_risk_keys > 0:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL KMS Security Alert - {critical_risk_keys} Keys Pending Deletion"
        elif overall_security_score < 50:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL KMS Security Alert - Security Score {overall_security_score}%"
        elif high_risk_keys > 0 or overall_security_score < 70:
            risk_level = "HIGH"
            subject = f"⚠️ HIGH KMS Security Alert - Security Issues Detected"
        else:
            risk_level = "MEDIUM"
            subject = f"🟡 KMS Management Alert - Cost Optimization Needed"
        
        # Build usage and state distributions
        usage_distribution = {}
        state_distribution = {}
        for key in keys:
            usage_level = key.get('UsageLevel', 'Unknown')
            usage_distribution[usage_level] = usage_distribution.get(usage_level, 0) + 1
            
            key_state = key.get('KeyState', 'Unknown')
            state_distribution[key_state] = state_distribution.get(key_state, 0) + 1
        
        # Build notification message
        message_parts = [
            f"KMS KEY SECURITY AND COMPLIANCE ALERT",
            f"Risk Level: {risk_level}",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total KMS keys analyzed: {total_keys:,}",
            f"• Critical risk keys: {critical_risk_keys}",
            f"• High risk keys: {high_risk_keys}",
            f"• Unused keys: {unused_keys}",
            f"• Overall security score: {overall_security_score}%",
            f"• Estimated monthly cost: ${total_keys * 1.0:,.2f}",
            f"• Potential savings from cleanup: ${unused_keys * 1.0:,.2f}/month",
            f""
        ]
        
        # Add critical findings details
        if critical_risk_keys > 0:
            message_parts.append("🔴 CRITICAL RISK KEYS:")
            for key in keys:
                if key.get('RiskLevel') == 'Critical':
                    key_name = key.get('Aliases', [key['KeyId']])[0] if key.get('Aliases') else key['KeyId']
                    message_parts.append(f"  • {key_name} ({key['Region']})")
                    message_parts.append(f"    - State: {key.get('KeyState', 'Unknown')}")
                    if key.get('KeyState') == 'PendingDeletion':
                        message_parts.append(f"    - ⚠️  DAYS UNTIL DELETION: {key.get('PendingDeletionWindowInDays', 'Unknown')}")
                    for issue in key.get('SecurityIssues', [])[:2]:  # Limit to 2 issues
                        message_parts.append(f"    - 🚨 {issue}")
                    message_parts.append(f"    - ⚠️  IMMEDIATE ACTION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_keys > 0:
            message_parts.append("🟠 HIGH RISK KEYS:")
            high_risk_count = 0
            for key in keys:
                if key.get('RiskLevel') == 'High' and high_risk_count < 5:  # Limit to 5 keys
                    key_name = key.get('Aliases', [key['KeyId']])[0] if key.get('Aliases') else key['KeyId']
                    message_parts.append(f"  • {key_name} ({key['Region']})")
                    message_parts.append(f"    - Usage: {key.get('UsageLevel', 'Unknown')}")
                    message_parts.append(f"    - Last used: {key.get('DaysSinceLastUsed', 'Never')} days ago")
                    for issue in key.get('SecurityIssues', [])[:2]:
                        message_parts.append(f"    - ⚠️  {issue}")
                    high_risk_count += 1
            message_parts.append("")
        
        # Add usage analysis
        if usage_distribution:
            message_parts.append("KEY USAGE ANALYSIS:")
            for usage_level, count in usage_distribution.items():
                message_parts.append(f"  • {usage_level}: {count} keys")
            message_parts.append("")
        
        # Add state distribution
        if state_distribution:
            message_parts.append("KEY STATE DISTRIBUTION:")
            for state, count in state_distribution.items():
                if state == 'PendingDeletion' and count > 0:
                    message_parts.append(f"  • {state}: {count} keys ⚠️  CRITICAL")
                else:
                    message_parts.append(f"  • {state}: {count} keys")
            message_parts.append("")
        
        # Add cost impact
        if unused_keys > 0:
            message_parts.extend([
                "COST OPTIMIZATION OPPORTUNITIES:",
                f"• {unused_keys} unused keys costing ${unused_keys * 1.0:,.2f}/month",
                f"• Potential annual savings: ${unused_keys * 12.0:,.2f}",
                ""
            ])
        
        # Add security risks section
        message_parts.extend([
            "SECURITY RISKS:",
            "• Keys pending deletion may cause data access failures",
            "• Disabled keys prevent encryption/decryption operations",
            "• Unused keys increase attack surface and management overhead",
            "• Excessive grants may allow unauthorized key usage",
            "• Old keys (3+ years) may need rotation for compliance",
            ""
        ])
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Review keys pending deletion - cancel if still needed",
            "2. Re-enable disabled keys that are required for operations",
            "3. Clean up unused keys after verifying no dependencies",
            "4. Review and reduce excessive key grants", 
            "5. Rotate old keys (3+ years) as per compliance requirements",
            "6. Add aliases to keys for better management",
            "",
            "KEY MANAGEMENT COMMANDS:",
            "# Cancel key deletion",
            "aws kms cancel-key-deletion --key-id KEY_ID --region REGION",
            "",
            "# Enable a disabled key",
            "aws kms enable-key --key-id KEY_ID --region REGION",
            "",
            "# List key grants",
            "aws kms list-grants --key-id KEY_ID --region REGION",
            "",
            "# Schedule key deletion (after verification)",
            "aws kms schedule-key-deletion --key-id KEY_ID --pending-window-in-days 30 --region REGION",
            "",
            "# Create key alias",
            "aws kms create-alias --alias-name alias/my-key-name --target-key-id KEY_ID --region REGION",
            "",
            "KEY ROTATION BEST PRACTICES:",
            "• Enable automatic key rotation for eligible keys",
            "• Rotate keys manually for compliance requirements",
            "• Document key usage and ownership",
            "• Implement least-privilege key policies",
            "• Monitor key usage patterns regularly",
            "",
            "For detailed KMS security guidance, see AWS KMS Best Practices documentation.",
            "",
            "This alert was generated by the automated KMS Key Security and Usage Audit function."
        ])
        
        message = "\n".join(message_parts)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        print(f"SNS notification sent successfully. MessageId: {message_id}")
        print(f"Notified about {critical_risk_keys} critical and {high_risk_keys} high risk KMS keys")
        
    except Exception as e:
        print(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def calculate_security_score(keys: List[Dict]) -> float:
    """Calculate overall security score based on key metrics."""
    if not keys:
        return 100.0
    
    total_keys = len(keys)
    enabled_keys = len([k for k in keys if k.get('Enabled')])
    unused_keys = len([k for k in keys if k.get('UsageLevel') in ['Unused', 'Never Used']])
    security_issues = len([k for k in keys if k.get('SecurityIssues')])
    
    # Security score calculation (same as Lambda version)
    enabled_score = (enabled_keys / total_keys) * 30
    usage_score = ((total_keys - unused_keys) / total_keys) * 40
    security_score = ((total_keys - security_issues) / total_keys) * 30
    overall_security_score = round(enabled_score + usage_score + security_score, 1)
    
    return overall_security_score

def print_summary_report(keys: List[Dict], sns_topic: str = None):
    """Print comprehensive summary report with security score."""
    total_keys = len(keys)
    
    if total_keys == 0:
        print(f"\n{'='*80}")
        print("KMS KEYS SUMMARY")
        print(f"{'='*80}")
        print("No KMS keys found in any scanned regions.")
        print(f"{'='*80}")
        return
    
    # Group by region and analyze
    by_region = {}
    enabled_keys = []
    unused_keys = []
    security_issues = []
    multi_region_keys = []
    
    # Usage and state statistics
    usage_stats = {}
    state_stats = {}
    origin_stats = {}
    
    for key in keys:
        region = key['Region']
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(key)
        
        # Statistics tracking
        usage_level = key.get('UsageLevel', 'Unknown')
        usage_stats[usage_level] = usage_stats.get(usage_level, 0) + 1
        
        key_state = key.get('KeyState', 'Unknown')
        state_stats[key_state] = state_stats.get(key_state, 0) + 1
        
        origin = key.get('Origin', 'Unknown')
        origin_stats[origin] = origin_stats.get(origin, 0) + 1
        
        # Issues tracking
        if key.get('Enabled'):
            enabled_keys.append(key)
        
        if key.get('UsageLevel') in ['Unused', 'Never Used']:
            unused_keys.append(key)
        
        if key.get('SecurityIssues'):
            security_issues.append(key)
        
        if key.get('MultiRegion'):
            multi_region_keys.append(key)
    
    # Calculate security score
    security_score = calculate_security_score(keys)
    
    # Risk distribution
    critical_risk_keys = len([k for k in keys if k.get('RiskLevel') == 'Critical'])
    high_risk_keys = len([k for k in keys if k.get('RiskLevel') == 'High'])
    medium_risk_keys = len([k for k in keys if k.get('RiskLevel') == 'Medium'])
    
    print(f"\n{'='*80}")
    print("KMS KEYS SUMMARY")
    print(f"{'='*80}")
    print(f"Total KMS Keys: {total_keys}")
    print(f"Regions with Keys: {len(by_region)}")
    print(f"Enabled Keys: {len(enabled_keys)}")
    print(f"Unused Keys: {len(unused_keys)}")
    print(f"Keys with Security Issues: {len(security_issues)}")
    print(f"Multi-Region Keys: {len(multi_region_keys)}")
    
    # Security score display
    score_indicator = "🔴" if security_score < 50 else "🟡" if security_score < 70 else "🟢"
    print(f"\n🛡️  OVERALL SECURITY SCORE: {score_indicator} {security_score}%")
    print(f"   • Critical Risk Keys: {critical_risk_keys}")
    print(f"   • High Risk Keys: {high_risk_keys}")
    print(f"   • Medium Risk Keys: {medium_risk_keys}")
    
    if security_score < 70:
        print(f"\n⚠️  SECURITY ALERT: Score below 70% indicates security concerns")
        if sns_topic:
            print(f"   📧 SNS notifications will be sent to: {sns_topic}")
    
    # Usage distribution
    print(f"\n{'='*80}")
    print("USAGE DISTRIBUTION")
    print(f"{'='*80}")
    for usage, count in sorted(usage_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_keys) * 100
        usage_indicator = {
            'Active': '🟢',
            'Low': '🟡',
            'Inactive': '🟠',
            'Unused': '🔴',
            'Never Used': '⚫'
        }.get(usage, '❓')
        print(f"{usage_indicator} {usage:15} {count:6} keys ({percentage:5.1f}%)")
    
    # Key state distribution
    print(f"\n{'='*80}")
    print("KEY STATE DISTRIBUTION")
    print(f"{'='*80}")
    for state, count in sorted(state_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_keys) * 100
        state_indicator = {
            'Enabled': '✅',
            'Disabled': '❌',
            'PendingDeletion': '🗑️'
        }.get(state, '❓')
        print(f"{state_indicator} {state:15} {count:6} keys ({percentage:5.1f}%)")
    
    # Regional breakdown
    print(f"\n{'='*80}")
    print("BREAKDOWN BY REGION")
    print(f"{'='*80}")
    for region, region_keys in sorted(by_region.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n{region}: {len(region_keys)} keys")
        
        # Show keys with issues
        issues_keys = [k for k in region_keys if k.get('SecurityIssues') or k.get('CostOptimizationOpportunities')]
        if issues_keys:
            print(f"  Keys with issues: {len(issues_keys)}")
            for key in issues_keys[:3]:  # Show top 3
                issues_count = len(key.get('SecurityIssues', []) + key.get('CostOptimizationOpportunities', []))
                key_display = key.get('Aliases', [key['KeyId'][:8]])[0] if key.get('Aliases') else key['KeyId'][:8]
                print(f"    {key_display:30} ({issues_count} issues)")
            if len(issues_keys) > 3:
                print(f"    ... and {len(issues_keys) - 3} more")
    
    # Unused keys (cost optimization)
    if unused_keys:
        print(f"\n{'='*80}")
        print("UNUSED KEYS (COST OPTIMIZATION OPPORTUNITY)")
        print(f"{'='*80}")
        print(f"{'Key ID/Alias':30} {'Region':12} {'Usage Level':12} {'Days Since Used':15} {'State'}")
        print("-" * 85)
        
        for key in unused_keys[:15]:  # Show top 15
            key_display = key.get('Aliases', [key['KeyId'][:8]])[0] if key.get('Aliases') else key['KeyId'][:8]
            days_since = str(key.get('DaysSinceLastUsed', 'Never')) if key.get('DaysSinceLastUsed') else 'Never'
            
            print(f"{key_display:30} "
                  f"{key['Region']:12} "
                  f"{key.get('UsageLevel', 'Unknown'):12} "
                  f"{days_since:15} "
                  f"{key.get('KeyState', 'Unknown')}")
        
        if len(unused_keys) > 15:
            print(f"... and {len(unused_keys) - 15} more unused keys")
    
    # Security issues
    if security_issues:
        print(f"\n{'='*80}")
        print("SECURITY ISSUES REQUIRING ATTENTION")
        print(f"{'='*80}")
        
        # Group by risk level
        critical_risk = [k for k in keys if k.get('RiskLevel') == 'Critical']
        high_risk = [k for k in keys if k.get('RiskLevel') == 'High']
        medium_risk = [k for k in keys if k.get('RiskLevel') == 'Medium']
        
        print(f"Critical Risk: {len(critical_risk)}")
        print(f"High Risk: {len(high_risk)}")
        print(f"Medium Risk: {len(medium_risk)}")
        
        print(f"\n{'Key ID/Alias':30} {'Region':12} {'Risk':8} {'Issues'}")
        print("-" * 80)
        
        for key in (critical_risk + high_risk)[:10]:  # Show top 10 highest risk
            risk_indicator = {
                'Critical': '🔴',
                'High': '🟡',
                'Medium': '🟠',
                'Low': '🟢'
            }.get(key.get('RiskLevel'), '❓')
            
            key_display = key.get('Aliases', [key['KeyId'][:8]])[0] if key.get('Aliases') else key['KeyId'][:8]
            issues_summary = ', '.join(key.get('SecurityIssues', [])[:2])
            if len(key.get('SecurityIssues', [])) > 2:
                issues_summary += '...'
            
            print(f"{key_display:30} "
                  f"{key['Region']:12} "
                  f"{risk_indicator} {key.get('RiskLevel', 'Low'):6} "
                  f"{issues_summary}")
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS:")
    print("- Review and disable/delete unused keys to reduce costs")
    print("- Audit key policies for overly permissive access")
    print("- Consider key rotation for keys over 3 years old")
    print("- Add aliases to keys for easier management")
    print("- Review grants to external accounts")
    print("- Enable CloudTrail logging for key usage monitoring")
    print(f"{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive KMS keys inventory with usage and security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # List keys in specific region
  ./list_kms_keys_with_usage.py --region us-east-1
  
  # Scan all regions
  ./list_kms_keys_with_usage.py --all-regions
  
  # Export detailed report
  ./list_kms_keys_with_usage.py --all-regions --export-csv kms_inventory.csv
  
  # Show only unused keys
  ./list_kms_keys_with_usage.py --all-regions --unused-only
  
  # Include AWS managed keys
  ./list_kms_keys_with_usage.py --all-regions --include-aws-managed

ANALYSIS INCLUDES:
- Key usage patterns and last used dates
- Security policy analysis
- Grants and permissions review
- Cost optimization opportunities
- Compliance checks (age, rotation)
- Multi-region key analysis
"""
    )
    parser.add_argument('--region', help='Specific AWS region to check')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Check all available regions')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--unused-only', action='store_true',
                       help='Show only unused or rarely used keys')
    parser.add_argument('--include-aws-managed', action='store_true',
                       help='Include AWS managed keys in analysis')
    parser.add_argument('--sns-topic', help='SNS topic ARN for security notifications')
    parser.add_argument('--profile', help='AWS profile to use')
    
    args = parser.parse_args()

    # Validate arguments
    if not args.region and not args.all_regions:
        print("Error: Must specify either --region or --all-regions")
        sys.exit(1)

    # Validate credentials
    if not validate_aws_credentials():
        sys.exit(1)

    try:
        # Create session
        session = None
        if args.profile:
            session = boto3.Session(profile_name=args.profile)

        # Determine regions to scan
        regions_to_scan = []
        if args.all_regions:
            # Get all available regions
            ec2_client = session.client('ec2') if session else boto3.client('ec2')
            regions_to_scan = get_available_regions(ec2_client)
            print(f"Scanning {len(regions_to_scan)} regions for KMS keys...")
        else:
            regions_to_scan = [args.region]
            print(f"Scanning region: {args.region}")

        print("=" * 60)

        # Scan all regions
        all_keys = []
        for region in regions_to_scan:
            region_keys = list_kms_keys_in_region(region, session, args.include_aws_managed)
            all_keys.extend(region_keys)

        # Filter results if requested
        display_keys = all_keys
        if args.unused_only:
            display_keys = [
                k for k in all_keys 
                if k.get('UsageLevel') in ['Unused', 'Never Used', 'Inactive']
            ]

        # Print summary report
        print_summary_report(all_keys, args.sns_topic)
        
        # Send SNS notifications if configured and needed
        if args.sns_topic and all_keys:
            # Calculate summary statistics for notifications
            security_score = calculate_security_score(all_keys)
            critical_risk_keys = len([k for k in all_keys if k.get('RiskLevel') == 'Critical'])
            high_risk_keys = len([k for k in all_keys if k.get('RiskLevel') == 'High'])
            unused_keys = len([k for k in all_keys if k.get('UsageLevel') in ['Unused', 'Never Used']])
            
            # Determine if notification is needed
            needs_notification = (critical_risk_keys > 0 or 
                                high_risk_keys > 0 or 
                                security_score < 70 or 
                                unused_keys > 20)
            
            if needs_notification:
                # Prepare summary stats structure
                summary_stats = {
                    'total_keys': len(all_keys),
                    'critical_risk_keys': critical_risk_keys,
                    'high_risk_keys': high_risk_keys,
                    'total_unused_keys': unused_keys,
                    'overall_security_score': security_score,
                    'estimated_monthly_cost': len(all_keys) * 1.0,  # $1 per key per month
                    'potential_monthly_savings': unused_keys * 1.0,  # $1 per unused key
                    'global_usage_distribution': {},
                    'global_state_distribution': {}
                }
                
                # Calculate distributions
                for key in all_keys:
                    usage_level = key.get('UsageLevel', 'Unknown')
                    summary_stats['global_usage_distribution'][usage_level] = \
                        summary_stats['global_usage_distribution'].get(usage_level, 0) + 1
                    
                    key_state = key.get('KeyState', 'Unknown')
                    summary_stats['global_state_distribution'][key_state] = \
                        summary_stats['global_state_distribution'].get(key_state, 0) + 1
                
                # Group keys by region for notification
                region_results = []
                by_region = {}
                for key in all_keys:
                    region = key['Region']
                    if region not in by_region:
                        by_region[region] = []
                    by_region[region].append(key)
                
                for region, region_keys in by_region.items():
                    region_results.append({
                        'region': region,
                        'kms_keys': region_keys
                    })
                
                # Get account ID
                sts_client = session.client('sts') if session else boto3.client('sts')
                account_id = sts_client.get_caller_identity().get('Account', 'Unknown')
                
                print(f"\n📧 Sending security notifications to SNS topic: {args.sns_topic}")
                send_security_notifications(all_keys, account_id, args.sns_topic, session)
            else:
                print(f"\nℹ️ No critical security issues found - no SNS notifications sent")

        # Export to files if requested
        if args.export_csv:
            export_to_csv(all_keys, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(all_keys, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        # Return appropriate exit code for automation
        unused_keys = [k for k in all_keys if k.get('UsageLevel') in ['Unused', 'Never Used']]
        critical_keys = [k for k in all_keys if k.get('RiskLevel') == 'Critical']
        security_issues = [k for k in all_keys if k.get('SecurityIssues')]
        
        if critical_keys:
            print(f"\n🚨 CRITICAL: Found {len(critical_keys)} critical risk KMS keys!")
            sys.exit(2)
        elif security_issues:
            print(f"\n🔒 SECURITY: Found {len(security_issues)} keys with security issues!")
            sys.exit(1)
        elif unused_keys:
            print(f"\n💰 COST: Found {len(unused_keys)} unused keys - potential cost savings!")
            sys.exit(0)
        else:
            print(f"\n✅ All KMS keys are properly used and configured!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access KMS. Required permissions:")
            print("- kms:ListKeys")
            print("- kms:DescribeKey")
            print("- kms:GetKeyLastUsedDate")
            print("- kms:ListAliases")
            print("- kms:ListGrants")
            print("- kms:ListKeyPolicies")
            print("- kms:GetKeyPolicy")
            print("- kms:ListResourceTags")
            print("- ec2:DescribeRegions")
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

