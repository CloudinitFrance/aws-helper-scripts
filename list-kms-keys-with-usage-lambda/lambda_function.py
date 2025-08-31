#!/usr/bin/env python3
"""
List KMS Keys with Usage Inventory - Lambda Version
Serverless function for automated KMS key auditing and cost optimization
"""

import json
import boto3
import os
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any
import logging
from datetime import datetime, timezone, timedelta

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

def get_all_regions() -> List[str]:
    """Get all AWS regions where KMS is available."""
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
        logger.warning(f"Error retrieving KMS keys: {e.response['Error']['Message']}")
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
            key_analysis['LastUsedDate'] = last_used.isoformat() if last_used else None
            days_since_used = (datetime.now(timezone.utc) - last_used).days
            key_analysis['DaysSinceLastUsed'] = days_since_used
        else:
            key_analysis['DaysSinceLastUsed'] = None
    except ClientError:
        key_analysis['DaysSinceLastUsed'] = None
    
    # Get aliases
    key_analysis['Aliases'] = get_key_aliases(kms_client, key_id)
    
    # Get grants (limited for performance)
    grants = get_key_grants(kms_client, key_id)
    key_analysis['Grants'] = len(grants)  # Store count instead of full data for performance
    
    # Get policies (limited for performance)
    policies = get_key_policies(kms_client, key_id)
    key_analysis['PolicyCount'] = len(policies)
    
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
    
    # Grants analysis
    if key_analysis['Grants'] > 10:
        key_analysis['SecurityIssues'].append(f"High number of grants ({key_analysis['Grants']})")
    
    # Origin analysis
    if key_analysis['Origin'] == 'EXTERNAL':
        key_analysis['ComplianceIssues'].append("External key material - verify compliance requirements")
    
    # Multi-region analysis
    if key_analysis['MultiRegion']:
        key_analysis['ComplianceIssues'].append("Multi-region key - verify data residency requirements")
    
    # Age analysis
    if key_analysis['CreationDate']:
        if isinstance(key_analysis['CreationDate'], str):
            creation_date = datetime.fromisoformat(key_analysis['CreationDate'].replace('Z', '+00:00'))
        else:
            creation_date = key_analysis['CreationDate']
        days_old = (datetime.now(timezone.utc) - creation_date).days
        key_analysis['DaysOld'] = days_old
        key_analysis['CreationDate'] = creation_date.isoformat()
        
        if days_old > 1095:  # 3 years
            key_analysis['ComplianceIssues'].append("Key is over 3 years old - consider rotation")
    else:
        key_analysis['DaysOld'] = 0
    
    # Alias analysis
    if not key_analysis['Aliases']:
        key_analysis['CostOptimizationOpportunities'].append("No aliases defined - consider adding for easier management")
    
    return key_analysis

def list_kms_keys_in_region(region: str, max_keys: int = 50) -> Dict:
    """List and analyze KMS keys in a specific region."""
    try:
        kms_client = boto3.client('kms', region_name=region)
        
        logger.info(f"Scanning region: {region}")
        
        # Get all KMS keys with pagination
        keys = get_kms_keys_with_pagination(kms_client)
        
        if not keys:
            logger.info(f"No KMS keys found in {region}")
            return {
                'region': region,
                'kms_keys': [],
                'statistics': {
                    'total_keys': 0,
                    'customer_managed_keys': 0,
                    'enabled_keys': 0,
                    'unused_keys': 0,
                    'security_issues': 0,
                    'cost_optimization_opportunities': 0,
                    'usage_distribution': {},
                    'state_distribution': {},
                    'risk_distribution': {}
                },
                'errors': []
            }
        
        logger.info(f"Found {len(keys)} KMS keys in {region}")
        
        # Analyze each key
        analyzed_keys = []
        for key in keys:
            key_analysis = analyze_kms_key(key, region, kms_client)
            
            # Filter AWS managed keys
            if key_analysis and key_analysis.get('KeyManager') == 'CUSTOMER':
                analyzed_keys.append(key_analysis)
        
        # Calculate statistics
        total_keys = len(analyzed_keys)
        enabled_keys = len([k for k in analyzed_keys if k.get('Enabled')])
        unused_keys = len([k for k in analyzed_keys if k.get('UsageLevel') in ['Unused', 'Never Used']])
        security_issues = len([k for k in analyzed_keys if k.get('SecurityIssues')])
        cost_optimization = len([k for k in analyzed_keys if k.get('CostOptimizationOpportunities')])
        
        # Usage distribution
        usage_distribution = {}
        state_distribution = {}
        risk_distribution = {}
        
        for key in analyzed_keys:
            usage_level = key.get('UsageLevel', 'Unknown')
            usage_distribution[usage_level] = usage_distribution.get(usage_level, 0) + 1
            
            key_state = key.get('KeyState', 'Unknown')
            state_distribution[key_state] = state_distribution.get(key_state, 0) + 1
            
            risk_level = key.get('RiskLevel', 'Low')
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        region_results = {
            'region': region,
            'kms_keys': analyzed_keys[:max_keys],  # Limit for response size
            'keys_truncated': len(analyzed_keys) > max_keys,
            'total_keys_found': len(analyzed_keys),
            'statistics': {
                'total_keys': total_keys,
                'customer_managed_keys': total_keys,
                'enabled_keys': enabled_keys,
                'unused_keys': unused_keys,
                'security_issues': security_issues,
                'cost_optimization_opportunities': cost_optimization,
                'usage_distribution': usage_distribution,
                'state_distribution': state_distribution,
                'risk_distribution': risk_distribution,
                'monthly_cost_estimate': total_keys * 1.0  # $1 per key per month
            },
            'errors': []
        }
        
        logger.info(f"Completed analysis for {region}: {total_keys} customer-managed keys")
        return region_results
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'kms_keys': [],
            'statistics': {
                'total_keys': 0,
                'customer_managed_keys': 0,
                'enabled_keys': 0,
                'unused_keys': 0,
                'security_issues': 0,
                'cost_optimization_opportunities': 0,
                'usage_distribution': {},
                'state_distribution': {},
                'risk_distribution': {},
                'monthly_cost_estimate': 0
            },
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def list_kms_keys_parallel(scan_all_regions_flag: bool, max_workers: int = 10, max_keys: int = 50) -> List[Dict]:
    """
    List KMS keys across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Listing KMS keys in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Listing KMS keys in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region listing tasks
        future_to_region = {
            executor.submit(list_kms_keys_in_region, region, max_keys): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed analysis for {region}: "
                           f"{result['statistics']['total_keys']} keys")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'kms_keys': [],
                    'statistics': {
                        'total_keys': 0,
                        'customer_managed_keys': 0,
                        'enabled_keys': 0,
                        'unused_keys': 0,
                        'security_issues': 0,
                        'cost_optimization_opportunities': 0,
                        'usage_distribution': {},
                        'state_distribution': {},
                        'risk_distribution': {},
                        'monthly_cost_estimate': 0
                    },
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel KMS keys analysis complete")
    return all_results

def send_security_notifications(summary_stats: Dict, results: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk KMS key security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk conditions
        critical_risk_keys = summary_stats['critical_risk_keys']
        high_risk_keys = summary_stats['high_risk_keys']
        unused_keys = summary_stats['total_unused_keys']
        security_score = summary_stats['overall_security_score']
        
        # Determine if notification is needed
        needs_notification = (critical_risk_keys > 0 or 
                            high_risk_keys > 0 or 
                            security_score < 70 or 
                            unused_keys > 20)
        
        if not needs_notification:
            logger.info("No critical or high risk KMS key findings to notify")
            return
        
        # Determine risk level and subject
        if critical_risk_keys > 0:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL KMS Security Alert - {critical_risk_keys} Keys Pending Deletion"
        elif security_score < 50:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL KMS Security Alert - Security Score {security_score}%"
        elif high_risk_keys > 0 or security_score < 70:
            risk_level = "HIGH"
            subject = f"⚠️ HIGH KMS Security Alert - Security Issues Detected"
        else:
            risk_level = "MEDIUM"
            subject = f"🟡 KMS Management Alert - Cost Optimization Needed"
        
        # Build notification message
        message_parts = [
            f"KMS KEY SECURITY AND COMPLIANCE ALERT",
            f"Risk Level: {risk_level}",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total KMS keys analyzed: {summary_stats['total_keys']:,}",
            f"• Critical risk keys: {critical_risk_keys}",
            f"• High risk keys: {high_risk_keys}",
            f"• Unused keys: {unused_keys}",
            f"• Overall security score: {security_score}%",
            f"• Estimated monthly cost: ${summary_stats['estimated_monthly_cost']:,.2f}",
            f"• Potential savings from cleanup: ${summary_stats['potential_monthly_savings']:,.2f}/month",
            f""
        ]
        
        # Add critical findings details
        if critical_risk_keys > 0:
            message_parts.append("🔴 CRITICAL RISK KEYS:")
            for result in results:
                for key in result.get('kms_keys', []):
                    if key.get('RiskLevel') == 'Critical':
                        key_name = key.get('Aliases', [key['KeyId']])[0] if key.get('Aliases') else key['KeyId']
                        message_parts.append(f"  • {key_name} ({result['region']})")
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
            for result in results:
                for key in result.get('kms_keys', []):
                    if key.get('RiskLevel') == 'High' and high_risk_count < 5:  # Limit to 5 keys
                        key_name = key.get('Aliases', [key['KeyId']])[0] if key.get('Aliases') else key['KeyId']
                        message_parts.append(f"  • {key_name} ({result['region']})")
                        message_parts.append(f"    - Usage: {key.get('UsageLevel', 'Unknown')}")
                        message_parts.append(f"    - Last used: {key.get('DaysSinceLastUsed', 'Never')} days ago")
                        for issue in key.get('SecurityIssues', [])[:2]:
                            message_parts.append(f"    - ⚠️  {issue}")
                        high_risk_count += 1
            message_parts.append("")
        
        # Add usage analysis
        if summary_stats['global_usage_distribution']:
            message_parts.append("KEY USAGE ANALYSIS:")
            for usage_level, count in summary_stats['global_usage_distribution'].items():
                message_parts.append(f"  • {usage_level}: {count} keys")
            message_parts.append("")
        
        # Add state distribution
        if summary_stats['global_state_distribution']:
            message_parts.append("KEY STATE DISTRIBUTION:")
            for state, count in summary_stats['global_state_distribution'].items():
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
        logger.info(f"SNS notification sent successfully. MessageId: {message_id}")
        logger.info(f"Notified about {critical_risk_keys} critical and {high_risk_keys} high risk KMS keys")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the inventory."""
    # Aggregate distributions
    global_usage_distribution = {}
    global_state_distribution = {}
    global_risk_distribution = {}
    
    for result in results:
        stats = result['statistics']
        
        # Aggregate usage distribution
        for usage, count in stats.get('usage_distribution', {}).items():
            global_usage_distribution[usage] = global_usage_distribution.get(usage, 0) + count
        
        # Aggregate state distribution
        for state, count in stats.get('state_distribution', {}).items():
            global_state_distribution[state] = global_state_distribution.get(state, 0) + count
        
        # Aggregate risk distribution
        for risk, count in stats.get('risk_distribution', {}).items():
            global_risk_distribution[risk] = global_risk_distribution.get(risk, 0) + count
    
    total_keys = sum(r['statistics']['total_keys'] for r in results)
    total_enabled = sum(r['statistics']['enabled_keys'] for r in results)
    total_unused = sum(r['statistics']['unused_keys'] for r in results)
    total_security_issues = sum(r['statistics']['security_issues'] for r in results)
    total_cost_opportunities = sum(r['statistics']['cost_optimization_opportunities'] for r in results)
    total_cost = sum(r['statistics'].get('monthly_cost_estimate', 0) for r in results)
    
    # Security metrics
    critical_risk_keys = global_risk_distribution.get('Critical', 0)
    high_risk_keys = global_risk_distribution.get('High', 0)
    medium_risk_keys = global_risk_distribution.get('Medium', 0)
    
    # Overall security score calculation
    if total_keys > 0:
        enabled_score = (total_enabled / total_keys) * 30
        usage_score = ((total_keys - total_unused) / total_keys) * 40
        security_score = ((total_keys - total_security_issues) / total_keys) * 30
        overall_security_score = round(enabled_score + usage_score + security_score, 1)
    else:
        overall_security_score = 100
    
    return {
        'total_regions_processed': len(results),
        'total_keys': total_keys,
        'total_enabled_keys': total_enabled,
        'total_unused_keys': total_unused,
        'total_security_issues': total_security_issues,
        'total_cost_optimization_opportunities': total_cost_opportunities,
        'global_usage_distribution': global_usage_distribution,
        'global_state_distribution': global_state_distribution,
        'global_risk_distribution': global_risk_distribution,
        'critical_risk_keys': critical_risk_keys,
        'high_risk_keys': high_risk_keys,
        'medium_risk_keys': medium_risk_keys,
        'estimated_monthly_cost': round(total_cost, 2),
        'potential_monthly_savings': round(total_unused * 1.0, 2),  # $1 per unused key
        'overall_security_score': overall_security_score,
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for KMS keys inventory with usage analysis
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with inventory results
    """
    try:
        logger.info("Starting KMS keys inventory with usage analysis")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        max_keys = params.get('max_keys', int(os.environ.get('MAX_KEYS', '50')))
        
        logger.info(f"Configuration - Scan all regions: {scan_all_regions_flag}, Max workers: {max_workers}, Max keys per region: {max_keys}")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Analyzing KMS keys in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform inventory using parallel processing
        results = list_kms_keys_parallel(scan_all_regions_flag, max_workers, max_keys)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = (summary_stats['critical_risk_keys'] > 0 or 
                          summary_stats['high_risk_keys'] > 0 or
                          summary_stats['total_unused_keys'] > 10 or
                          summary_stats['overall_security_score'] < 70 or
                          summary_stats['total_errors'] > 0)
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Inventory completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"KMS keys found: {summary_stats['total_keys']}, "
                   f"Unused keys: {summary_stats['total_unused_keys']}, "
                   f"Security score: {summary_stats['overall_security_score']}%")
        
        if summary_stats['total_keys'] == 0:
            logger.info("No customer-managed KMS keys found in scanned regions")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(summary_stats, results, account_id)
            logger.warning(f"KMS SECURITY/COST ALERT: {summary_stats['critical_risk_keys']} critical risk keys, "
                         f"{summary_stats['total_unused_keys']} unused keys, "
                         f"security score: {summary_stats['overall_security_score']}%")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'KMS keys inventory completed successfully',
                'results': {
                    'region_results': results,
                    'summary': summary_stats,
                    'inventory_parameters': {
                        'scan_all_regions': scan_all_regions_flag,
                        'max_workers': max_workers,
                        'account_id': account_id,
                        'caller_arn': caller_arn
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"KMS keys inventory failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'KMS keys inventory failed',
                'executionId': context.aws_request_id
            }
        }