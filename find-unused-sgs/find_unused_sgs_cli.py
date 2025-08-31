#!/usr/bin/env python3
"""
Find unused EC2 Security Groups across AWS regions with comprehensive analysis.

This script identifies security groups that are not attached to any resources
and provides detailed analysis of their usage and potential for cleanup.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

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
    """Get list of available EC2 regions."""
    return AWS_REGIONS

def get_all_security_groups_with_pagination(ec2_client) -> Dict[str, Dict]:
    """Get all security groups with pagination and detailed information."""
    security_groups = {}
    
    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                security_groups[sg['GroupId']] = {
                    'GroupId': sg['GroupId'],
                    'GroupName': sg['GroupName'],
                    'Description': sg['Description'],
                    'VpcId': sg.get('VpcId', 'EC2-Classic'),
                    'Tags': sg.get('Tags', []),
                    'RulesCount': len(sg.get('IpPermissions', [])) + len(sg.get('IpPermissionsEgress', [])),
                    'InboundRules': len(sg.get('IpPermissions', [])),
                    'OutboundRules': len(sg.get('IpPermissionsEgress', []))
                }
        
        return security_groups
        
    except ClientError as e:
        print(f"Error retrieving security groups: {e.response['Error']['Message']}")
        return {}

def get_used_security_groups_with_pagination(ec2_client) -> Set[str]:
    """Get all security groups that are currently in use."""
    used_sgs = set()
    
    try:
        # Check ENIs (includes EC2 instances, ELBs, RDS, etc.)
        print("  Checking network interfaces...")
        eni_paginator = ec2_client.get_paginator('describe_network_interfaces')
        
        for page in eni_paginator.paginate():
            for eni in page['NetworkInterfaces']:
                for sg in eni.get('Groups', []):
                    used_sgs.add(sg['GroupId'])
        
        # Check Launch Templates
        print("  Checking launch templates...")
        try:
            lt_paginator = ec2_client.get_paginator('describe_launch_templates')
            
            for page in lt_paginator.paginate():
                for lt in page['LaunchTemplates']:
                    try:
                        versions_response = ec2_client.describe_launch_template_versions(
                            LaunchTemplateId=lt['LaunchTemplateId']
                        )
                        for version in versions_response['LaunchTemplateVersions']:
                            lt_data = version.get('LaunchTemplateData', {})
                            for sg_id in lt_data.get('SecurityGroupIds', []):
                                used_sgs.add(sg_id)
                    except ClientError:
                        continue
        except ClientError as e:
            if e.response['Error']['Code'] != 'InvalidAction':
                print(f"    Warning: Could not check launch templates: {e.response['Error']['Message']}")
        
        # Check Auto Scaling Groups
        print("  Checking auto scaling groups...")
        try:
            autoscaling_client = boto3.client('autoscaling', region_name=ec2_client.meta.region_name)
            asg_paginator = autoscaling_client.get_paginator('describe_auto_scaling_groups')
            
            for page in asg_paginator.paginate():
                for asg in page['AutoScalingGroups']:
                    if asg.get('LaunchTemplate'):
                        lt_id = asg['LaunchTemplate']['LaunchTemplateId']
                        try:
                            versions_response = ec2_client.describe_launch_template_versions(
                                LaunchTemplateId=lt_id
                            )
                            for version in versions_response['LaunchTemplateVersions']:
                                lt_data = version.get('LaunchTemplateData', {})
                                for sg_id in lt_data.get('SecurityGroupIds', []):
                                    used_sgs.add(sg_id)
                        except ClientError:
                            continue
        except ClientError as e:
            print(f"    Warning: Could not check auto scaling groups: {e.response['Error']['Message']}")
        
        # Mark default security groups as used
        print("  Checking default security groups...")
        try:
            vpcs_paginator = ec2_client.get_paginator('describe_vpcs')
            
            for page in vpcs_paginator.paginate():
                for vpc in page['Vpcs']:
                    try:
                        default_sgs = ec2_client.describe_security_groups(
                            Filters=[
                                {'Name': 'vpc-id', 'Values': [vpc['VpcId']]},
                                {'Name': 'group-name', 'Values': ['default']}
                            ]
                        )
                        for sg in default_sgs['SecurityGroups']:
                            used_sgs.add(sg['GroupId'])
                    except ClientError:
                        continue
        except ClientError as e:
            print(f"    Warning: Could not check VPCs: {e.response['Error']['Message']}")
        
        # Check security group references (groups referencing other groups)
        print("  Checking security group references...")
        try:
            all_sgs = ec2_client.describe_security_groups()['SecurityGroups']
            for sg in all_sgs:
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                        if 'GroupId' in user_id_group_pair:
                            used_sgs.add(user_id_group_pair['GroupId'])
                
                # Check outbound rules
                for rule in sg.get('IpPermissionsEgress', []):
                    for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                        if 'GroupId' in user_id_group_pair:
                            used_sgs.add(user_id_group_pair['GroupId'])
        except ClientError as e:
            print(f"    Warning: Could not check security group references: {e.response['Error']['Message']}")
        
        return used_sgs
        
    except ClientError as e:
        print(f"Error checking security group usage: {e.response['Error']['Message']}")
        return set()

# Thread-safe printing
print_lock = threading.Lock()

def thread_safe_print(message: str):
    """Thread-safe print function for parallel processing."""
    with print_lock:
        print(message)

def perform_safety_checks(security_group: Dict) -> Dict[str, any]:
    """
    Extensive safety checks before deletion.
    
    Args:
        security_group: Security group information dict
        
    Returns:
        Dict with 'safe_to_delete' boolean and 'reason' string
    """
    # NEVER delete default security groups
    if security_group.get('GroupName') == 'default':
        return {
            'safe_to_delete': False, 
            'reason': 'Default security group - NEVER delete'
        }
    
    # Check for protection tags
    tags_dict = security_group.get('TagsDict', {})
    protected_tags = ['donotdelete', 'protected', 'keep', 'production', 'prod', 'critical', 'permanent']
    
    for tag_key, tag_value in tags_dict.items():
        tag_key_lower = tag_key.lower()
        tag_value_lower = str(tag_value).lower()
        
        if tag_key_lower in protected_tags:
            return {
                'safe_to_delete': False, 
                'reason': f'Protected by tag: {tag_key}'
            }
        
        # Check tag values too
        if any(protected in tag_value_lower for protected in protected_tags):
            return {
                'safe_to_delete': False,
                'reason': f'Protected by tag value: {tag_key}={tag_value}'
            }
    
    # Check if it's a high-complexity security group (many rules)
    rules_count = security_group.get('RulesCount', 0)
    if rules_count > 10:
        return {
            'safe_to_delete': False,
            'reason': f'Complex security group with {rules_count} rules - manual review required'
        }
    
    # Check description for important keywords
    description = security_group.get('Description', '').lower()
    important_keywords = ['production', 'prod', 'critical', 'important', 'database', 'db', 'load', 'balancer', 'web']
    
    for keyword in important_keywords:
        if keyword in description:
            return {
                'safe_to_delete': False,
                'reason': f'Description contains important keyword: {keyword}'
            }
    
    # Additional safety: Skip if group name suggests it's important
    group_name = security_group.get('GroupName', '').lower()
    important_name_parts = ['prod', 'production', 'critical', 'web', 'db', 'database', 'lb', 'elb', 'alb']
    
    for name_part in important_name_parts:
        if name_part in group_name:
            return {
                'safe_to_delete': False,
                'reason': f'Group name suggests importance: {security_group.get("GroupName")}'
            }
    
    # Check if already marked as protected by risk level
    if security_group.get('RiskLevel') == 'Low':
        return {
            'safe_to_delete': False,
            'reason': 'Risk assessment marked as Low (protected)'
        }
    
    return {
        'safe_to_delete': True, 
        'reason': 'Passes all safety checks - safe for cleanup'
    }

def cleanup_unused_security_groups(unused_sgs: List[Dict], dry_run: bool = True) -> List[Dict]:
    """
    Optional cleanup with extensive safety checks.
    
    Args:
        unused_sgs: List of unused security groups
        dry_run: If True, only simulate deletions (default: True)
        
    Returns:
        List of cleanup results
    """
    if not unused_sgs:
        thread_safe_print("No unused security groups provided for cleanup")
        return []
    
    cleanup_results = []
    ec2_clients = {}
    
    thread_safe_print(f"{'DRY RUN: ' if dry_run else ''}Processing {len(unused_sgs)} unused security groups for cleanup")
    
    for sg in unused_sgs:
        region = sg.get('Region', 'unknown')
        sg_id = sg.get('GroupId')
        sg_name = sg.get('GroupName', 'unknown')
        
        if not sg_id:
            cleanup_results.append({
                'sg_id': 'unknown',
                'region': region,
                'action': 'SKIPPED',
                'reason': 'Missing GroupId'
            })
            continue
        
        # Perform extensive safety checks
        safety_check = perform_safety_checks(sg)
        if not safety_check['safe_to_delete']:
            cleanup_results.append({
                'sg_id': sg_id,
                'sg_name': sg_name,
                'region': region,
                'action': 'SKIPPED',
                'reason': safety_check['reason']
            })
            thread_safe_print(f"SKIPPED {sg_id} in {region}: {safety_check['reason']}")
            continue
        
        # Create EC2 client for region if not exists
        if region not in ec2_clients:
            try:
                ec2_clients[region] = boto3.client('ec2', region_name=region)
            except Exception as e:
                cleanup_results.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'region': region,
                    'action': 'ERROR',
                    'reason': f'Failed to create EC2 client: {str(e)}'
                })
                continue
        
        # Final verification: Check if security group still exists and is truly unused
        try:
            # Verify the security group still exists
            describe_response = ec2_clients[region].describe_security_groups(GroupIds=[sg_id])
            if not describe_response['SecurityGroups']:
                cleanup_results.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'region': region,
                    'action': 'SKIPPED',
                    'reason': 'Security group no longer exists'
                })
                continue
            
            current_sg = describe_response['SecurityGroups'][0]
            
            # Double-check it's not default
            if current_sg['GroupName'] == 'default':
                cleanup_results.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'region': region,
                    'action': 'SKIPPED',
                    'reason': 'SAFETY: Default security group detected - NEVER delete'
                })
                thread_safe_print(f"SAFETY ALERT: Almost deleted default security group {sg_id} in {region}!")
                continue
            
            # Final usage check - verify it's still unused
            used_sgs = get_used_security_groups_with_pagination(ec2_clients[region])
            if sg_id in used_sgs:
                cleanup_results.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'region': region,
                    'action': 'SKIPPED',
                    'reason': 'Security group is now in use'
                })
                continue
            
            # Perform deletion or dry run
            try:
                if not dry_run:
                    # Actual deletion
                    ec2_clients[region].delete_security_group(GroupId=sg_id)
                    action = 'DELETED'
                    thread_safe_print(f"DELETED security group {sg_id} ({sg_name}) in {region}")
                else:
                    # Dry run
                    action = 'WOULD_DELETE'
                    thread_safe_print(f"DRY RUN: Would delete security group {sg_id} ({sg_name}) in {region}")
                
                cleanup_results.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'region': region,
                    'action': action,
                    'reason': safety_check['reason']
                })
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                
                if error_code == 'DependencyViolation':
                    reason = f'Cannot delete - still has dependencies: {error_message}'
                elif error_code == 'InvalidGroup.InUse':
                    reason = f'Cannot delete - security group in use: {error_message}'
                else:
                    reason = f'Delete failed ({error_code}): {error_message}'
                
                cleanup_results.append({
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'region': region,
                    'action': 'ERROR',
                    'reason': reason
                })
                thread_safe_print(f"Failed to delete {sg_id} in {region}: {reason}")
                
        except ClientError as e:
            cleanup_results.append({
                'sg_id': sg_id,
                'sg_name': sg_name,
                'region': region,
                'action': 'ERROR', 
                'reason': f'Verification failed: {e.response["Error"]["Message"]}'
            })
        except Exception as e:
            cleanup_results.append({
                'sg_id': sg_id,
                'sg_name': sg_name,
                'region': region,
                'action': 'ERROR',
                'reason': f'Unexpected error: {str(e)}'
            })
    
    return cleanup_results

def scan_regions_parallel(regions: List[str], session, max_workers: int = 5) -> List[Dict]:
    """Parallel region scanning for CLI."""
    all_unused_sgs = []
    
    thread_safe_print(f"Starting parallel scan of {len(regions)} regions with {max_workers} workers...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_region = {
            executor.submit(analyze_unused_security_groups, region, session): region
            for region in regions
        }
        
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                unused_sgs = future.result()
                all_unused_sgs.extend(unused_sgs)
                thread_safe_print(f"✅ Completed scan for region: {region} ({len(unused_sgs)} unused SGs)")
            except Exception as e:
                thread_safe_print(f"❌ Error scanning region {region}: {e}")
    
    return all_unused_sgs

def analyze_unused_security_groups(region: str, session=None) -> List[Dict]:
    """Analyze unused security groups in a specific region."""
    try:
        if session:
            ec2_client = session.client('ec2', region_name=region)
        else:
            ec2_client = boto3.client('ec2', region_name=region)
        
        print(f"Scanning region: {region}")
        
        # Get all security groups
        print("  Retrieving all security groups...")
        all_sgs = get_all_security_groups_with_pagination(ec2_client)
        
        if not all_sgs:
            print(f"  No security groups found in {region}")
            return []
        
        print(f"  Found {len(all_sgs)} security groups")
        
        # Get used security groups
        print("  Analyzing security group usage...")
        used_sgs = get_used_security_groups_with_pagination(ec2_client)
        
        print(f"  Found {len(used_sgs)} security groups in use")
        
        # Identify unused security groups
        unused_security_groups = []
        for sg_id, sg_info in all_sgs.items():
            if sg_id not in used_sgs:
                # Add additional analysis
                sg_analysis = sg_info.copy()
                sg_analysis['Region'] = region
                sg_analysis['IsUnused'] = True
                
                # Analyze tags for protection indicators
                tags = {tag['Key']: tag['Value'] for tag in sg_analysis.get('Tags', [])}
                sg_analysis['HasProtectionTag'] = any(
                    key.lower() in ['donotdelete', 'protected', 'keep'] 
                    for key in tags.keys()
                )
                sg_analysis['TagsDict'] = tags
                
                # Risk assessment
                if sg_analysis['GroupName'] == 'default':
                    sg_analysis['RiskLevel'] = 'Low'  # Default groups should not be deleted
                elif sg_analysis['HasProtectionTag']:
                    sg_analysis['RiskLevel'] = 'Low'
                elif sg_analysis['RulesCount'] > 5:
                    sg_analysis['RiskLevel'] = 'Medium'  # Complex rules, might be important
                else:
                    sg_analysis['RiskLevel'] = 'High'  # Safe to delete
                
                unused_security_groups.append(sg_analysis)
        
        print(f"  Found {len(unused_security_groups)} unused security groups")
        return unused_security_groups
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"  Access denied for region {region} - skipping")
        else:
            print(f"  Error in region {region}: {e.response['Error']['Message']}")
        return []

def export_to_csv(security_groups: List[Dict], filename: str):
    """Export security group data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Region', 'GroupId', 'GroupName', 'Description', 'VpcId',
            'RulesCount', 'InboundRules', 'OutboundRules', 'RiskLevel',
            'HasProtectionTag', 'Tags'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for sg in security_groups:
            row = sg.copy()
            # Convert tags to string
            tags_str = ', '.join([f"{k}={v}" for k, v in sg.get('TagsDict', {}).items()])
            row['Tags'] = tags_str
            writer.writerow(row)

def export_to_json(security_groups: List[Dict], filename: str):
    """Export security group data to JSON."""
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(security_groups, jsonfile, indent=2, default=str)

def print_summary_report(security_groups: List[Dict]):
    """Print comprehensive summary report."""
    total_unused = len(security_groups)
    
    if total_unused == 0:
        print(f"\n{'='*60}")
        print("UNUSED SECURITY GROUPS SUMMARY")
        print(f"{'='*60}")
        print("✅ No unused security groups found in any scanned regions!")
        print(f"{'='*60}")
        return
    
    # Group by region and risk level
    by_region = {}
    high_risk = []
    medium_risk = []
    low_risk = []
    
    for sg in security_groups:
        region = sg['Region']
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(sg)
        
        if sg['RiskLevel'] == 'High':
            high_risk.append(sg)
        elif sg['RiskLevel'] == 'Medium':
            medium_risk.append(sg)
        else:
            low_risk.append(sg)
    
    print(f"\n{'='*80}")
    print("UNUSED SECURITY GROUPS SUMMARY")
    print(f"{'='*80}")
    print(f"Total Unused Security Groups: {total_unused}")
    print(f"Regions with Unused Groups: {len(by_region)}")
    print(f"High Risk (Safe to delete): {len(high_risk)}")
    print(f"Medium Risk (Review needed): {len(medium_risk)}")
    print(f"Low Risk (Keep/Protected): {len(low_risk)}")
    
    # Show by region
    print(f"\n{'='*80}")
    print("BREAKDOWN BY REGION")
    print(f"{'='*80}")
    for region, sgs in by_region.items():
        print(f"\n{region}: {len(sgs)} unused security groups")
        
        # Show top unused groups
        for sg in sorted(sgs, key=lambda x: (x['RiskLevel'] != 'High', x['RiskLevel'] != 'Medium'))[:5]:
            risk_indicator = {
                'High': '🟢',  # Safe to delete
                'Medium': '🟡',  # Review needed
                'Low': '🔴'     # Keep/Protected
            }.get(sg['RiskLevel'], '❓')
            
            print(f"  {risk_indicator} {sg['GroupId']:20} {sg['GroupName']:25} ({sg['RiskLevel']} risk)")
        
        if len(sgs) > 5:
            print(f"  ... and {len(sgs) - 5} more")
    
    # Show high-risk candidates for deletion
    if high_risk:
        print(f"\n{'='*80}")
        print("HIGH-RISK SECURITY GROUPS (SAFE TO DELETE)")
        print(f"{'='*80}")
        print(f"{'Group ID':20} {'Group Name':25} {'Region':12} {'VPC':15} {'Rules':6}")
        print("-" * 85)
        
        for sg in high_risk[:20]:  # Show top 20
            vpc_display = sg['VpcId'] if sg['VpcId'] != 'EC2-Classic' else 'Classic'
            print(f"{sg['GroupId']:20} {sg['GroupName']:25} {sg['Region']:12} {vpc_display:15} {sg['RulesCount']:6}")
        
        if len(high_risk) > 20:
            print(f"... and {len(high_risk) - 20} more high-risk security groups")
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS:")
    print("🟢 High Risk: Generally safe to delete")
    print("🟡 Medium Risk: Review rules and usage before deletion")
    print("🔴 Low Risk: Keep (default groups or protected)")
    print(f"{'='*80}")

def print_cleanup_summary(cleanup_results: List[Dict]):
    """Print summary of cleanup operations."""
    if not cleanup_results:
        print("No cleanup operations performed")
        return
    
    # Count actions
    actions = {}
    for result in cleanup_results:
        action = result['action']
        actions[action] = actions.get(action, 0) + 1
    
    print(f"\n{'='*80}")
    print("CLEANUP SUMMARY")
    print(f"{'='*80}")
    
    for action, count in actions.items():
        emoji = {
            'DELETED': '✅',
            'WOULD_DELETE': '🔍',
            'SKIPPED': '⏭️',
            'ERROR': '❌'
        }.get(action, '❓')
        print(f"{emoji} {action}: {count}")
    
    # Show details for significant actions
    deleted = [r for r in cleanup_results if r['action'] in ['DELETED', 'WOULD_DELETE']]
    errors = [r for r in cleanup_results if r['action'] == 'ERROR']
    
    if deleted:
        print(f"\n{'='*60}")
        print(f"SECURITY GROUPS {'DELETED' if any(r['action'] == 'DELETED' for r in deleted) else 'MARKED FOR DELETION'}")
        print(f"{'='*60}")
        
        for result in deleted[:10]:  # Show first 10
            action_display = '✅ DELETED' if result['action'] == 'DELETED' else '🔍 WOULD DELETE'
            print(f"{action_display}: {result['sg_id']} ({result.get('sg_name', 'unknown')}) in {result['region']}")
        
        if len(deleted) > 10:
            print(f"... and {len(deleted) - 10} more")
    
    if errors:
        print(f"\n{'='*60}")
        print("CLEANUP ERRORS")
        print(f"{'='*60}")
        
        for result in errors[:5]:  # Show first 5 errors
            print(f"❌ {result['sg_id']} in {result['region']}: {result['reason']}")
        
        if len(errors) > 5:
            print(f"... and {len(errors) - 5} more errors")

def send_sns_alert(security_groups: List[Dict], sns_topic_arn: str, session=None) -> None:
    """Send SNS notifications for excessive unused security groups (security hygiene alerts)."""
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
        
        # Calculate summary statistics
        total_unused = len(security_groups)
        
        # Only send alerts for significant security hygiene issues
        if total_unused < 100:  # Less than 100 unused SGs is acceptable
            print(f"📧 Only {total_unused} unused security groups found - below notification threshold")
            return
        
        # Group by region for analysis
        by_region = {}
        high_risk = []
        unused_with_rules = []
        unused_with_tags = []
        
        for sg in security_groups:
            region = sg['Region']
            if region not in by_region:
                by_region[region] = []
            by_region[region].append(sg)
            
            if sg['RiskLevel'] == 'High':
                high_risk.append(sg)
            if sg.get('Rules', 0) > 2:  # More than default egress rules
                unused_with_rules.append(sg)
            if sg.get('Tags', []):
                unused_with_tags.append(sg)
        
        # Determine risk level based on unused count
        if total_unused >= 500:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL Security Hygiene Alert - {total_unused} Unused Security Groups"
        elif total_unused >= 200:
            risk_level = "HIGH"
            subject = f"⚠️ HIGH Security Hygiene Alert - {total_unused} Unused Security Groups"
        else:
            risk_level = "MEDIUM"
            subject = f"🟡 Security Hygiene Alert - {total_unused} Unused Security Groups"
        
        # Build notification message
        message_parts = [
            f"SECURITY HYGIENE ALERT - EXCESSIVE UNUSED SECURITY GROUPS",
            f"Risk Level: {risk_level}",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total unused security groups: {total_unused:,}",
            f"• Unused with custom rules: {len(unused_with_rules):,}",
            f"• Unused with tags: {len(unused_with_tags):,}",
            f"• High risk (safe to delete): {len(high_risk):,}",
            f"• Regions with unused SGs: {len(by_region)}",
            f""
        ]
        
        # Add region breakdown for top regions with unused SGs
        message_parts.append("TOP REGIONS WITH UNUSED SECURITY GROUPS:")
        sorted_regions = sorted(by_region.items(), 
                              key=lambda x: len(x[1]), 
                              reverse=True)[:5]
        
        for region, sgs in sorted_regions:
            message_parts.append(f"  • {region}: {len(sgs)} unused SGs")
        message_parts.append("")
        
        # Add security risks section
        message_parts.extend([
            "SECURITY RISKS:",
            "• Attack Surface: Each unused SG increases management complexity",
            "• Compliance Issues: Violates principle of least privilege",
            "• Audit Challenges: Makes security reviews more difficult",
            "• Misuse Potential: Unused SGs might be accidentally attached to resources",
            "• Configuration Drift: Increases risk of misconfiguration over time",
            ""
        ])
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Review unused security groups with custom rules first",
            "2. Check for any launch template references",
            "3. Verify security groups are truly unused (not referenced by other SGs)",
            "4. Delete unused security groups in batches",
            "5. Implement automated cleanup policies",
            "6. Tag security groups with purpose and owner for better management",
            "",
            "CLEANUP COMMANDS:",
            "# List unused security groups in a region",
            "aws ec2 describe-security-groups --region REGION \\",
            "  --filters Name=group-id,Values=sg-xxxxx \\",
            "  --query 'SecurityGroups[*].[GroupId,GroupName,Description]'",
            "",
            "# Delete an unused security group",
            "aws ec2 delete-security-group --group-id sg-xxxxx --region REGION",
            "",
            "# Bulk cleanup script example",
            "for sg in $(aws ec2 describe-security-groups --region REGION \\",
            "  --query 'SecurityGroups[?GroupName!=`default`].GroupId' \\",
            "  --output text); do",
            "    # Verify SG is truly unused before deletion",
            "    aws ec2 delete-security-group --group-id $sg --region REGION 2>/dev/null",
            "done",
            "",
            "PREVENTION STRATEGIES:",
            "• Implement tagging policies for all security groups",
            "• Use IaC tools (CloudFormation/Terraform) for SG management",
            "• Regular automated cleanup (monthly/quarterly)",
            "• Enforce security group limits per VPC",
            "• Monitor security group creation and usage metrics",
            "",
            "For automated cleanup tools, see AWS Security Group Cleanup documentation.",
            "",
            "This alert was generated by the Security Group Hygiene Audit CLI tool."
        ])
        
        message = "\n".join(message_parts)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        print(f"📧 SNS notification sent successfully. MessageId: {message_id}")
        print(f"📧 Alerted about {total_unused} unused security groups with {risk_level} risk level")
        
    except Exception as e:
        print(f"❌ Failed to send SNS notification: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="Find unused EC2 Security Groups with multi-region support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Scan specific region
  ./find_unused_sgs.py --region us-east-1
  
  # Scan all regions
  ./find_unused_sgs.py --all-regions
  
  # Export detailed report
  ./find_unused_sgs.py --all-regions --export-csv unused_sgs_report.csv
  
  # Show only high-risk (safe to delete) groups
  ./find_unused_sgs.py --all-regions --high-risk-only

CHECKS PERFORMED:
- Network interface attachments (EC2, ELB, RDS, etc.)
- Launch template references
- Auto Scaling Group configurations
- Security group cross-references
- Default security group protection
"""
    )
    parser.add_argument('--region', help='Specific AWS region to check')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Check all available regions')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--high-risk-only', action='store_true',
                       help='Show only high-risk (safe to delete) security groups')
    parser.add_argument('--profile', help='AWS profile to use')
    
    # Parallel processing options
    parser.add_argument('--no-parallel', action='store_true',
                       help='Disable parallel processing (scan regions sequentially)')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of parallel workers (default: 5, max: 20)')
    
    # Cleanup options (SAFETY FIRST)
    parser.add_argument('--cleanup', action='store_true',
                       help='Enable optional cleanup functionality (dry-run by default)')
    parser.add_argument('--cleanup-confirm', action='store_true',
                       help='DANGER: Actually delete security groups (not just dry-run)')
    parser.add_argument('--cleanup-export', help='Export cleanup results to JSON file')
    parser.add_argument('--sns-topic', help='SNS topic ARN for security hygiene alerts')
    
    args = parser.parse_args()

    # Validate arguments
    if not args.region and not args.all_regions:
        print("Error: Must specify either --region or --all-regions")
        sys.exit(1)
    
    # Validate cleanup arguments
    if args.cleanup_confirm and not args.cleanup:
        print("Error: --cleanup-confirm requires --cleanup to be enabled")
        sys.exit(1)
    
    # Validate max workers
    if args.max_workers > 20:
        print("Warning: Max workers limited to 20 for API safety")
        args.max_workers = 20
    elif args.max_workers < 1:
        args.max_workers = 1

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
            print(f"Scanning {len(regions_to_scan)} regions for unused security groups...")
        else:
            regions_to_scan = [args.region]
            print(f"Scanning region: {args.region}")

        print("=" * 60)

        # Determine scanning method (parallel vs sequential)
        all_unused_sgs = []
        use_parallel = args.all_regions and not args.no_parallel and len(regions_to_scan) > 1
        
        if use_parallel:
            print(f"Using parallel processing with {args.max_workers} workers for faster scanning")
            all_unused_sgs = scan_regions_parallel(regions_to_scan, session, args.max_workers)
        else:
            # Sequential scanning
            if args.all_regions:
                print("Sequential scanning (use --max-workers > 1 for parallel processing)")
            
            for region in regions_to_scan:
                region_unused_sgs = analyze_unused_security_groups(region, session)
                all_unused_sgs.extend(region_unused_sgs)

        # Filter results if requested
        display_sgs = all_unused_sgs
        if args.high_risk_only:
            display_sgs = [sg for sg in all_unused_sgs if sg['RiskLevel'] == 'High']

        # Print summary report
        print_summary_report(all_unused_sgs)

        # Optional cleanup phase
        cleanup_results = []
        if args.cleanup and all_unused_sgs:
            print(f"\n{'='*80}")
            print("OPTIONAL CLEANUP PHASE")
            print(f"{'='*80}")
            
            # Determine dry run mode
            dry_run = not args.cleanup_confirm
            
            if dry_run:
                print("🔍 DRY RUN MODE: Will simulate deletions only (use --cleanup-confirm for actual deletion)")
            else:
                print("⚠️  LIVE MODE: Will actually delete security groups!")
                response = input("Are you absolutely sure you want to delete unused security groups? (type 'yes' to confirm): ")
                if response.lower() != 'yes':
                    print("Cleanup cancelled by user")
                    dry_run = True
            
            # Only cleanup high-risk (safe to delete) security groups
            safe_to_cleanup = [sg for sg in all_unused_sgs if sg.get('RiskLevel') == 'High']
            
            if safe_to_cleanup:
                print(f"\nProcessing {len(safe_to_cleanup)} high-risk unused security groups for cleanup...")
                cleanup_results = cleanup_unused_security_groups(safe_to_cleanup, dry_run)
                
                # Print cleanup summary
                print_cleanup_summary(cleanup_results)
            else:
                print("No high-risk security groups found for safe cleanup")
        
        # Export to files if requested
        if args.export_csv:
            export_to_csv(all_unused_sgs, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(all_unused_sgs, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")
        
        if args.cleanup_export and cleanup_results:
            with open(args.cleanup_export, 'w', encoding='utf-8') as f:
                json.dump(cleanup_results, f, indent=2, default=str)
            print(f"🧹 Cleanup results exported to: {args.cleanup_export}")

        # Send SNS alert if topic is provided and significant findings exist
        if args.sns_topic and all_unused_sgs:
            total_unused = len(all_unused_sgs)
            if total_unused >= 100:  # Only alert for significant hygiene issues
                print(f"\n📧 Sending SNS alert for {total_unused} unused security groups...")
                send_sns_alert(all_unused_sgs, args.sns_topic, session)
            else:
                print(f"\n📧 {total_unused} unused security groups found - below alert threshold")
        elif args.sns_topic and not all_unused_sgs:
            print("\n📧 No unused security groups found - no SNS alert sent")

        # Return appropriate exit code for automation
        high_risk_sgs = [sg for sg in all_unused_sgs if sg['RiskLevel'] == 'High']
        
        if high_risk_sgs:
            print(f"\n🧹 Found {len(high_risk_sgs)} high-risk unused security groups that can be safely deleted!")
            sys.exit(0)
        elif all_unused_sgs:
            print(f"\n📋 Found {len(all_unused_sgs)} unused security groups requiring review.")
            sys.exit(0)
        else:
            print(f"\n✅ No unused security groups found!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access EC2. Required permissions:")
            print("- ec2:DescribeSecurityGroups")
            print("- ec2:DescribeNetworkInterfaces")
            print("- ec2:DescribeLaunchTemplates")
            print("- ec2:DescribeLaunchTemplateVersions")
            print("- ec2:DescribeVpcs")
            print("- ec2:DescribeRegions")
            print("- autoscaling:DescribeAutoScalingGroups")
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

