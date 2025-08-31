#!/usr/bin/env python3
"""
Find Unused Security Groups - Lambda Version
Serverless function for automated security group cleanup analysis
"""

import json
import boto3
import os
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any, Set, Tuple
import logging

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
    """Get all AWS regions where EC2 is available."""
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
        logger.error(f"Error retrieving security groups: {e.response['Error']['Message']}")
        return {}

def get_used_security_groups_with_pagination(ec2_client) -> Set[str]:
    """Get all security groups that are currently in use."""
    used_sgs = set()
    
    try:
        # Check ENIs (includes EC2 instances, ELBs, RDS, etc.)
        logger.info("  Checking network interfaces...")
        eni_paginator = ec2_client.get_paginator('describe_network_interfaces')
        
        for page in eni_paginator.paginate():
            for eni in page['NetworkInterfaces']:
                for sg in eni.get('Groups', []):
                    used_sgs.add(sg['GroupId'])
        
        return used_sgs
        
    except ClientError as e:
        logger.error(f"Error checking ENIs: {e.response['Error']['Message']}")
        return used_sgs

def check_launch_templates(ec2_client, sg_ids: Set[str]) -> Set[str]:
    """Check if security groups are used in launch templates."""
    used_sgs = set()
    
    try:
        templates = ec2_client.describe_launch_templates().get('LaunchTemplates', [])
        
        for template in templates:
            try:
                versions = ec2_client.describe_launch_template_versions(
                    LaunchTemplateId=template['LaunchTemplateId']
                ).get('LaunchTemplateVersions', [])
                
                for version in versions:
                    sg_list = version.get('LaunchTemplateData', {}).get('SecurityGroupIds', [])
                    for sg_id in sg_list:
                        if sg_id in sg_ids:
                            used_sgs.add(sg_id)
            except ClientError as e:
                logger.warning(f"Error checking launch template {template['LaunchTemplateId']}: {e}")
    
    except ClientError as e:
        logger.warning(f"Error checking launch templates: {e}")
    
    return used_sgs

def check_auto_scaling_groups(ec2_client, sg_ids: Set[str]) -> Set[str]:
    """Check if security groups are used in Auto Scaling Groups."""
    used_sgs = set()
    
    try:
        # Create Auto Scaling client for the same region
        autoscaling_client = boto3.client('autoscaling', region_name=ec2_client.meta.region_name)
        asg_paginator = autoscaling_client.get_paginator('describe_auto_scaling_groups')
        
        logger.info("  Checking Auto Scaling Groups...")
        for page in asg_paginator.paginate():
            for asg in page['AutoScalingGroups']:
                # Check launch template
                if asg.get('LaunchTemplate'):
                    lt_id = asg['LaunchTemplate']['LaunchTemplateId']
                    try:
                        versions_response = ec2_client.describe_launch_template_versions(
                            LaunchTemplateId=lt_id
                        )
                        for version in versions_response['LaunchTemplateVersions']:
                            lt_data = version.get('LaunchTemplateData', {})
                            for sg_id in lt_data.get('SecurityGroupIds', []):
                                if sg_id in sg_ids:
                                    used_sgs.add(sg_id)
                    except ClientError as e:
                        logger.warning(f"Error checking launch template {lt_id}: {e}")
                        continue
                
                # Check launch configuration (legacy)
                if asg.get('LaunchConfigurationName'):
                    lc_name = asg['LaunchConfigurationName']
                    try:
                        lc_response = autoscaling_client.describe_launch_configurations(
                            LaunchConfigurationNames=[lc_name]
                        )
                        for lc in lc_response['LaunchConfigurations']:
                            for sg_id in lc.get('SecurityGroups', []):
                                if sg_id in sg_ids:
                                    used_sgs.add(sg_id)
                    except ClientError as e:
                        logger.warning(f"Error checking launch configuration {lc_name}: {e}")
                        continue
        
        logger.info(f"  Found {len(used_sgs)} security groups used in Auto Scaling Groups")
        return used_sgs
        
    except ClientError as e:
        logger.warning(f"Error checking Auto Scaling Groups: {e.response['Error']['Message']}")
        return used_sgs

def check_vpc_default_security_groups(ec2_client, sg_ids: Set[str]) -> Set[str]:
    """Mark default security groups as used (they cannot be deleted)."""
    used_sgs = set()
    
    try:
        logger.info("  Checking VPC default security groups...")
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
                        if sg['GroupId'] in sg_ids:
                            used_sgs.add(sg['GroupId'])
                except ClientError as e:
                    logger.warning(f"Error checking default SG for VPC {vpc['VpcId']}: {e}")
                    continue
        
        logger.info(f"  Found {len(used_sgs)} default security groups")
        return used_sgs
        
    except ClientError as e:
        logger.warning(f"Error checking VPCs: {e.response['Error']['Message']}")
        return used_sgs

def check_security_group_references(ec2_client, sg_ids: Set[str]) -> Set[str]:
    """Check if security groups reference each other in their rules."""
    used_sgs = set()
    
    try:
        all_sgs = ec2_client.describe_security_groups().get('SecurityGroups', [])
        
        for sg in all_sgs:
            # Check ingress rules
            for rule in sg.get('IpPermissions', []):
                for group in rule.get('UserIdGroupPairs', []):
                    ref_sg_id = group.get('GroupId')
                    if ref_sg_id in sg_ids:
                        used_sgs.add(ref_sg_id)
            
            # Check egress rules
            for rule in sg.get('IpPermissionsEgress', []):
                for group in rule.get('UserIdGroupPairs', []):
                    ref_sg_id = group.get('GroupId')
                    if ref_sg_id in sg_ids:
                        used_sgs.add(ref_sg_id)
    
    except ClientError as e:
        logger.warning(f"Error checking security group references: {e}")
    
    return used_sgs

def analyze_unused_security_groups(all_sgs: Dict[str, Dict], used_sgs: Set[str]) -> Tuple[Dict[str, Dict], Dict]:
    """Analyze security groups to identify unused ones."""
    unused_sgs = {}
    stats = {
        'total_security_groups': len(all_sgs),
        'used_security_groups': len(used_sgs),
        'unused_security_groups': 0,
        'default_security_groups': 0,
        'unused_with_rules': 0,
        'unused_with_tags': 0
    }
    
    for sg_id, sg_info in all_sgs.items():
        # Skip default security groups
        if sg_info['GroupName'] == 'default':
            stats['default_security_groups'] += 1
            continue
        
        # Check if unused
        if sg_id not in used_sgs:
            unused_sgs[sg_id] = sg_info
            stats['unused_security_groups'] += 1
            
            # Additional statistics
            if sg_info['RulesCount'] > 2:  # More than just default egress
                stats['unused_with_rules'] += 1
            if sg_info['Tags']:
                stats['unused_with_tags'] += 1
    
    return unused_sgs, stats

def analyze_security_groups_in_region(region: str) -> Dict:
    """Analyze security groups in a specific region."""
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        
        logger.info(f"Analyzing security groups in region: {region}")
        
        # Get all security groups
        all_sgs = get_all_security_groups_with_pagination(ec2_client)
        
        if not all_sgs:
            logger.info(f"No security groups found in {region}")
            return {
                'region': region,
                'unused_security_groups': {},
                'statistics': {
                    'total_security_groups': 0,
                    'used_security_groups': 0,
                    'unused_security_groups': 0
                },
                'errors': []
            }
        
        # Get used security groups
        used_sgs = get_used_security_groups_with_pagination(ec2_client)
        
        # Check launch templates
        launch_template_sgs = check_launch_templates(ec2_client, set(all_sgs.keys()))
        used_sgs.update(launch_template_sgs)
        
        # Check Auto Scaling Groups
        asg_sgs = check_auto_scaling_groups(ec2_client, set(all_sgs.keys()))
        used_sgs.update(asg_sgs)
        
        # Check VPC default security groups
        default_sgs = check_vpc_default_security_groups(ec2_client, set(all_sgs.keys()))
        used_sgs.update(default_sgs)
        
        # Check security group references
        referenced_sgs = check_security_group_references(ec2_client, set(all_sgs.keys()))
        used_sgs.update(referenced_sgs)
        
        # Analyze unused security groups
        unused_sgs, stats = analyze_unused_security_groups(all_sgs, used_sgs)
        
        # Prepare detailed unused security groups list
        unused_details = []
        for sg_id, sg_info in unused_sgs.items():
            unused_details.append({
                'GroupId': sg_id,
                'GroupName': sg_info['GroupName'],
                'VpcId': sg_info['VpcId'],
                'Description': sg_info['Description'],
                'RulesCount': sg_info['RulesCount'],
                'Tags': sg_info['Tags']
            })
        
        logger.info(f"Completed analysis for {region}: {stats['unused_security_groups']} unused security groups found")
        
        return {
            'region': region,
            'unused_security_groups': unused_details[:50],  # Limit for response size
            'statistics': stats,
            'errors': []
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'unused_security_groups': [],
            'statistics': {
                'total_security_groups': 0,
                'used_security_groups': 0,
                'unused_security_groups': 0
            },
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def analyze_security_groups_parallel(scan_all_regions_flag: bool, max_workers: int = 10) -> List[Dict]:
    """
    Analyze security groups across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Analyzing security groups in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Analyzing security groups in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region analysis tasks
        future_to_region = {
            executor.submit(analyze_security_groups_in_region, region): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed analysis for {region}: "
                           f"{result['statistics']['unused_security_groups']} unused security groups")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'unused_security_groups': [],
                    'statistics': {
                        'total_security_groups': 0,
                        'used_security_groups': 0,
                        'unused_security_groups': 0
                    },
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel security group analysis complete")
    return all_results

def send_security_notifications(summary_stats: Dict, results: List[Dict], account_id: str) -> None:
    """Send SNS notifications for excessive unused security groups (security hygiene alerts)."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Define thresholds for security hygiene alerts
        total_unused = summary_stats['total_unused_security_groups']
        
        # Only send alerts for significant security hygiene issues
        if total_unused < 100:  # Less than 100 unused SGs is acceptable
            logger.info(f"Only {total_unused} unused security groups found - below notification threshold")
            return
        
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
            f"• Total security groups: {summary_stats['total_security_groups']:,}",
            f"• Used security groups: {summary_stats['total_used_security_groups']:,}",
            f"• Unused security groups: {total_unused:,}",
            f"• Unused with custom rules: {summary_stats['total_unused_with_rules']:,}",
            f"• Unused with tags: {summary_stats['total_unused_with_tags']:,}",
            f"• Regions analyzed: {summary_stats['total_regions_processed']}",
            f""
        ]
        
        # Calculate usage percentage
        if summary_stats['total_security_groups'] > 0:
            usage_percentage = (summary_stats['total_used_security_groups'] / 
                              summary_stats['total_security_groups'] * 100)
            message_parts.append(f"• Security group utilization: {usage_percentage:.1f}%")
            message_parts.append("")
        
        # Add region breakdown for top regions with unused SGs
        message_parts.append("TOP REGIONS WITH UNUSED SECURITY GROUPS:")
        sorted_regions = sorted(results, 
                              key=lambda x: x['statistics']['unused_security_groups'], 
                              reverse=True)[:5]
        
        for region_data in sorted_regions:
            if region_data['statistics']['unused_security_groups'] > 0:
                message_parts.append(f"  • {region_data['region']}: "
                                   f"{region_data['statistics']['unused_security_groups']} unused SGs")
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
        
        # Add cost impact
        if 'estimated_annual_savings' in summary_stats:
            message_parts.extend([
                "OPERATIONAL IMPACT:",
                f"• Management overhead: {summary_stats['management_hours_saved']:.1f} hours/year",
                f"• Estimated savings: ${summary_stats['estimated_annual_savings']:,.0f}/year",
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
            "This alert was generated by the automated Security Group Hygiene Audit function."
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
        logger.info(f"Notified about {total_unused} unused security groups ({risk_level} risk)")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the analysis."""
    summary = {
        'total_regions_processed': len(results),
        'total_security_groups': sum(r['statistics']['total_security_groups'] for r in results),
        'total_used_security_groups': sum(r['statistics']['used_security_groups'] for r in results),
        'total_unused_security_groups': sum(r['statistics']['unused_security_groups'] for r in results),
        'total_default_security_groups': sum(r['statistics'].get('default_security_groups', 0) for r in results),
        'total_unused_with_rules': sum(r['statistics'].get('unused_with_rules', 0) for r in results),
        'total_unused_with_tags': sum(r['statistics'].get('unused_with_tags', 0) for r in results),
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }
    
    # Calculate management overhead savings
    management_hours_saved = summary['total_unused_security_groups'] * 0.1  # 6 minutes per SG per year
    hourly_rate = 50  # Example DevOps hourly rate
    summary['estimated_annual_savings'] = management_hours_saved * hourly_rate
    summary['management_hours_saved'] = management_hours_saved
    
    return summary

def perform_safety_checks(security_group: Dict) -> Dict[str, Any]:
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
    tags = security_group.get('Tags', [])
    protected_tags = ['donotdelete', 'protected', 'keep', 'production', 'prod', 'critical', 'permanent']
    
    for tag in tags:
        tag_key = tag.get('Key', '').lower()
        tag_value = tag.get('Value', '').lower()
        
        if tag_key in protected_tags:
            return {
                'safe_to_delete': False, 
                'reason': f'Protected by tag: {tag["Key"]}'
            }
        
        # Check tag values too
        if any(protected in tag_value for protected in protected_tags):
            return {
                'safe_to_delete': False,
                'reason': f'Protected by tag value: {tag["Key"]}={tag["Value"]}'
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
        logger.info("No unused security groups provided for cleanup")
        return []
    
    cleanup_results = []
    ec2_clients = {}
    
    logger.info(f"{'DRY RUN: ' if dry_run else ''}Processing {len(unused_sgs)} unused security groups for cleanup")
    
    for sg in unused_sgs:
        region = sg.get('region', 'unknown')
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
            logger.info(f"SKIPPED {sg_id} in {region}: {safety_check['reason']}")
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
                logger.warning(f"SAFETY ALERT: Almost deleted default security group {sg_id} in {region}!")
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
                    logger.info(f"DELETED security group {sg_id} ({sg_name}) in {region}")
                else:
                    # Dry run
                    action = 'WOULD_DELETE'
                    logger.info(f"DRY RUN: Would delete security group {sg_id} ({sg_name}) in {region}")
                
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
                logger.error(f"Failed to delete {sg_id} in {region}: {reason}")
                
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
    
    # Log cleanup summary
    actions_summary = {}
    for result in cleanup_results:
        action = result['action']
        actions_summary[action] = actions_summary.get(action, 0) + 1
    
    logger.info(f"Cleanup summary: {dict(actions_summary)}")
    
    return cleanup_results

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for finding unused security groups with optional cleanup
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with analysis results and optional cleanup results
    """
    try:
        logger.info("Starting unused security groups analysis")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        
        # Cleanup parameters (SAFETY FIRST - defaults to dry run)
        enable_cleanup = params.get('enable_cleanup', 
                                  os.environ.get('ENABLE_CLEANUP', 'false').lower() == 'true')
        dry_run = params.get('dry_run', 
                           os.environ.get('DRY_RUN', 'true').lower() == 'true')
        
        logger.info(f"Configuration - Scan all regions: {scan_all_regions_flag}, Max workers: {max_workers}")
        if enable_cleanup:
            logger.info(f"Cleanup enabled - Dry run: {dry_run}")
        else:
            logger.info("Cleanup disabled - analysis only")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Analyzing security groups in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform analysis using parallel processing
        results = analyze_security_groups_parallel(scan_all_regions_flag, max_workers)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Optional cleanup phase
        cleanup_results = []
        if enable_cleanup and summary_stats['total_unused_security_groups'] > 0:
            logger.info("Starting optional cleanup phase...")
            
            # Collect all unused security groups from all regions
            all_unused_sgs = []
            for region_result in results:
                for unused_sg in region_result['unused_security_groups']:
                    # Add region info for cleanup function
                    unused_sg['region'] = region_result['region']
                    all_unused_sgs.append(unused_sg)
            
            if all_unused_sgs:
                cleanup_results = cleanup_unused_security_groups(all_unused_sgs, dry_run)
                logger.info(f"Cleanup completed. Processed {len(cleanup_results)} security groups")
            else:
                logger.info("No unused security groups to clean up")
        
        # Determine if alerts should be triggered
        alerts_triggered = summary_stats['total_unused_security_groups'] > 50
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Analysis completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Total security groups: {summary_stats['total_security_groups']}, "
                   f"Unused security groups: {summary_stats['total_unused_security_groups']}")
        
        if alerts_triggered:
            # Send SNS notifications for security hygiene alerts
            send_security_notifications(summary_stats, results, account_id)
            logger.warning(f"CLEANUP ALERT: {summary_stats['total_unused_security_groups']} unused security groups detected!")
        
        if summary_stats['total_security_groups'] == 0:
            logger.info("No security groups found in scanned regions")
        else:
            usage_percentage = (summary_stats['total_used_security_groups'] / 
                              summary_stats['total_security_groups'] * 100)
            logger.info(f"Security group usage: {usage_percentage:.1f}%")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'Unused security groups analysis completed successfully',
                'results': {
                    'region_results': results,
                    'summary': summary_stats,
                    'cleanup_results': cleanup_results if enable_cleanup else None,
                    'analysis_parameters': {
                        'scan_all_regions': scan_all_regions_flag,
                        'max_workers': max_workers,
                        'enable_cleanup': enable_cleanup,
                        'dry_run': dry_run if enable_cleanup else None,
                        'account_id': account_id,
                        'caller_arn': caller_arn
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"Unused security groups analysis failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Unused security groups analysis failed',
                'executionId': context.aws_request_id
            }
        }