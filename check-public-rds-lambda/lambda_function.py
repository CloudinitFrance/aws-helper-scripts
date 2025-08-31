#!/usr/bin/env python3
"""
Check Public RDS Instances - Lambda Version
Serverless function for automated RDS security auditing
"""

import json
import boto3
import os
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any
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
    """Get all AWS regions where RDS is available."""
    return AWS_REGIONS

def get_rds_instances_with_pagination(rds_client) -> List[Dict]:
    """Get all RDS instances with pagination."""
    instances = []
    
    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for db_instance in page['DBInstances']:
                instances.append(db_instance)
        
        return instances
        
    except ClientError as e:
        logger.error(f"Error retrieving RDS instances: {e.response['Error']['Message']}")
        return []

def analyze_security_groups(ec2_client, security_group_ids: List[str]) -> List[Dict]:
    """Analyze security groups for potential issues."""
    issues = []
    
    try:
        if not security_group_ids:
            return issues
            
        response = ec2_client.describe_security_groups(GroupIds=security_group_ids)
        
        for sg in response['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    cidr_ip = ip_range.get('CidrIp', '')
                    if cidr_ip == '0.0.0.0/0':
                        issues.append({
                            'SecurityGroupId': sg['GroupId'],
                            'Issue': f"Port {rule.get('FromPort', 'N/A')} open to 0.0.0.0/0",
                            'Risk': 'Critical',
                            'Protocol': rule.get('IpProtocol', 'N/A')
                        })
                    elif cidr_ip.endswith('/0'):
                        issues.append({
                            'SecurityGroupId': sg['GroupId'],
                            'Issue': f"Port {rule.get('FromPort', 'N/A')} open to large CIDR block",
                            'Risk': 'High',
                            'Protocol': rule.get('IpProtocol', 'N/A')
                        })
        
        return issues
        
    except ClientError as e:
        logger.warning(f"Error analyzing security groups: {e}")
        return []

def generate_remediation_commands(instance: Dict) -> List[str]:
    """Generate AWS CLI commands for remediation."""
    commands = []
    
    if instance['PubliclyAccessible']:
        commands.append(f"""
# Make RDS instance private
aws rds modify-db-instance \\
    --db-instance-identifier {instance['DBInstanceIdentifier']} \\
    --no-publicly-accessible \\
    --region {instance['Region']}
        """.strip())
    
    # Security group remediation
    for issue in instance.get('SecurityIssues', []):
        if issue['Risk'] == 'Critical' and '0.0.0.0/0' in issue['Issue']:
            port = 'PORT'  # Extract from issue description
            if 'Port 3306' in issue['Issue']:
                port = '3306'
            elif 'Port 5432' in issue['Issue']:
                port = '5432'
            elif 'Port 1433' in issue['Issue']:
                port = '1433'
            
            commands.append(f"""
# Remove open access from security group
aws ec2 revoke-security-group-ingress \\
    --group-id {issue['SecurityGroupId']} \\
    --protocol tcp \\
    --port {port} \\
    --cidr 0.0.0.0/0 \\
    --region {instance['Region']}
            """.strip())
    
    # Encryption remediation (requires snapshot restore)
    if not instance['StorageEncrypted']:
        commands.append(f"""
# Enable encryption (requires creating encrypted snapshot)
# Step 1: Create snapshot
aws rds create-db-snapshot \\
    --db-instance-identifier {instance['DBInstanceIdentifier']} \\
    --db-snapshot-identifier {instance['DBInstanceIdentifier']}-encrypt-snapshot \\
    --region {instance['Region']}

# Step 2: Copy snapshot with encryption
aws rds copy-db-snapshot \\
    --source-db-snapshot-identifier {instance['DBInstanceIdentifier']}-encrypt-snapshot \\
    --target-db-snapshot-identifier {instance['DBInstanceIdentifier']}-encrypted \\
    --kms-key-id alias/aws/rds \\
    --region {instance['Region']}

# Step 3: Restore from encrypted snapshot
aws rds restore-db-instance-from-db-snapshot \\
    --db-instance-identifier {instance['DBInstanceIdentifier']}-encrypted \\
    --db-snapshot-identifier {instance['DBInstanceIdentifier']}-encrypted \\
    --region {instance['Region']}
        """.strip())
    
    # Backup configuration
    if instance.get('BackupRetentionPeriod', 0) == 0:
        commands.append(f"""
# Enable automated backups
aws rds modify-db-instance \\
    --db-instance-identifier {instance['DBInstanceIdentifier']} \\
    --backup-retention-period 7 \\
    --region {instance['Region']}
        """.strip())
    
    # Multi-AZ deployment
    if not instance.get('MultiAZ', False) and instance['RiskLevel'] in ['Critical', 'High']:
        commands.append(f"""
# Enable Multi-AZ deployment for high availability
aws rds modify-db-instance \\
    --db-instance-identifier {instance['DBInstanceIdentifier']} \\
    --multi-az \\
    --region {instance['Region']}
        """.strip())
    
    return commands

def analyze_rds_security(rds_instance: Dict, region: str, ec2_client) -> Dict:
    """Analyze RDS instance for security configurations."""
    instance_info = {
        'Region': region,
        'DBInstanceIdentifier': rds_instance['DBInstanceIdentifier'],
        'Engine': rds_instance['Engine'],
        'EngineVersion': rds_instance['EngineVersion'],
        'DBInstanceClass': rds_instance['DBInstanceClass'],
        'PubliclyAccessible': rds_instance['PubliclyAccessible'],
        'Endpoint': rds_instance.get('Endpoint', {}).get('Address', 'N/A'),
        'Port': rds_instance.get('Endpoint', {}).get('Port', 'N/A'),
        'StorageEncrypted': rds_instance.get('StorageEncrypted', False),
        'MultiAZ': rds_instance.get('MultiAZ', False),
        'BackupRetentionPeriod': rds_instance.get('BackupRetentionPeriod', 0),
        'VpcId': 'N/A',
        'SubnetGroup': rds_instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A'),
        'SecurityGroups': [],
        'SecurityIssues': [],
        'RiskLevel': 'Low'
    }
    
    # Get VPC information
    if rds_instance.get('DBSubnetGroup'):
        instance_info['VpcId'] = rds_instance['DBSubnetGroup'].get('VpcId', 'N/A')
    
    # Get security groups
    security_groups = []
    for sg in rds_instance.get('VpcSecurityGroups', []):
        security_groups.append({
            'GroupId': sg['VpcSecurityGroupId'],
            'Status': sg['Status']
        })
    instance_info['SecurityGroups'] = security_groups
    
    # Analyze security groups
    sg_ids = [sg['GroupId'] for sg in security_groups]
    instance_info['SecurityIssues'] = analyze_security_groups(ec2_client, sg_ids)
    
    # Determine risk level
    if instance_info['PubliclyAccessible']:
        if instance_info['SecurityIssues']:
            # Has security group issues and is publicly accessible
            critical_issues = [issue for issue in instance_info['SecurityIssues'] if issue['Risk'] == 'Critical']
            if critical_issues:
                instance_info['RiskLevel'] = 'Critical'
            else:
                instance_info['RiskLevel'] = 'High'
        else:
            instance_info['RiskLevel'] = 'Medium'  # Public but secure security groups
    else:
        if not instance_info['StorageEncrypted']:
            instance_info['RiskLevel'] = 'Medium'  # Private but unencrypted
        else:
            instance_info['RiskLevel'] = 'Low'  # Private and encrypted
    
    # Generate automated remediation commands
    instance_info['RemediationCommands'] = generate_remediation_commands(instance_info)
    
    return instance_info

def check_public_rds_in_region(region: str) -> List[Dict]:
    """Check RDS instances in a specific region."""
    try:
        rds_client = boto3.client('rds', region_name=region)
        ec2_client = boto3.client('ec2', region_name=region)
        
        logger.info(f"Scanning region: {region}")
        
        # Get all RDS instances with pagination
        instances = get_rds_instances_with_pagination(rds_client)
        
        if not instances:
            logger.info(f"No RDS instances found in {region}")
            return []
        
        logger.info(f"Found {len(instances)} RDS instances in {region}")
        
        # Analyze each instance
        analyzed_instances = []
        for instance in instances:
            instance_info = analyze_rds_security(instance, region, ec2_client)
            analyzed_instances.append(instance_info)
        
        return analyzed_instances
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return []

def scan_all_regions_parallel(scan_all_regions_flag: bool = False, max_workers: int = 10) -> List[Dict]:
    """
    Scan RDS instances across regions using parallel threading.
    """
    all_instances = []
    
    if scan_all_regions_flag:
        logger.info("Scanning all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Scanning current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region scanning tasks
        future_to_region = {
            executor.submit(check_public_rds_in_region, region): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                instances = future.result()
                if instances:
                    logger.info(f"Found {len(instances)} RDS instances in {region}")
                    all_instances.extend(instances)
                else:
                    logger.info(f"No RDS instances found in {region}")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
    
    logger.info(f"Parallel scanning complete. Total instances found: {len(all_instances)}")
    return all_instances

def filter_instances(instances: List[Dict], public_only: bool = True) -> List[Dict]:
    """Filter instances based on criteria."""
    if public_only:
        return [instance for instance in instances if instance['PubliclyAccessible']]
    return instances

def calculate_summary_stats(instances: List[Dict]) -> Dict:
    """Calculate summary statistics for the audit."""
    total_instances = len(instances)
    public_instances = [i for i in instances if i['PubliclyAccessible']]
    encrypted_instances = [i for i in instances if i['StorageEncrypted']]
    
    # Risk analysis
    critical_risk = [i for i in instances if i['RiskLevel'] == 'Critical']
    high_risk = [i for i in instances if i['RiskLevel'] == 'High']
    medium_risk = [i for i in instances if i['RiskLevel'] == 'Medium']
    low_risk = [i for i in instances if i['RiskLevel'] == 'Low']
    
    return {
        'total_instances': total_instances,
        'public_instances': len(public_instances),
        'encrypted_instances': len(encrypted_instances),
        'critical_risk': len(critical_risk),
        'high_risk': len(high_risk),
        'medium_risk': len(medium_risk),
        'low_risk': len(low_risk),
        'unencrypted_instances': total_instances - len(encrypted_instances)
    }

def send_security_notifications(summary_stats: Dict, all_instances: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk RDS security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk instances
        critical_instances = [i for i in all_instances if i['RiskLevel'] == 'Critical']
        high_risk_instances = [i for i in all_instances if i['RiskLevel'] == 'High']
        
        if not critical_instances and not high_risk_instances:
            logger.info("No critical or high risk RDS findings to notify")
            return
        
        # Build notification message
        subject = f"🚨 RDS Security Alert - Account {account_id}"
        
        message_parts = [
            f"CRITICAL RDS SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total RDS instances: {summary_stats['total_instances']}",
            f"• Public instances: {summary_stats['public_instances']}",
            f"• Critical risk instances: {summary_stats['critical_risk']}",
            f"• High risk instances: {summary_stats['high_risk']}",
            f"• Unencrypted instances: {summary_stats['unencrypted_instances']}",
            f""
        ]
        
        # Add critical findings details
        if critical_instances:
            message_parts.append("🔴 CRITICAL RISK INSTANCES (Public + Security Group Issues):")
            for instance in critical_instances:
                message_parts.append(f"  • {instance['DBInstanceIdentifier']} ({instance['Region']})")
                message_parts.append(f"    - Engine: {instance['Engine']} {instance['EngineVersion']}")
                message_parts.append(f"    - Public access: YES")
                message_parts.append(f"    - Endpoint: {instance['Endpoint']}:{instance['Port']}")
                message_parts.append(f"    - Encrypted: {'YES' if instance['StorageEncrypted'] else 'NO'}")
                for issue in instance['SecurityIssues']:
                    if issue['Risk'] == 'Critical':
                        message_parts.append(f"    - 🚨 {issue['Issue']} (Security Group: {issue['SecurityGroupId']})")
                message_parts.append(f"    - ⚠️  IMMEDIATE ACTION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_instances:
            message_parts.append("🟠 HIGH RISK INSTANCES (Public Access):")
            for instance in high_risk_instances:
                message_parts.append(f"  • {instance['DBInstanceIdentifier']} ({instance['Region']})")
                message_parts.append(f"    - Engine: {instance['Engine']} {instance['EngineVersion']}")
                message_parts.append(f"    - Public access: YES")
                message_parts.append(f"    - Endpoint: {instance['Endpoint']}:{instance['Port']}")
                message_parts.append(f"    - Encrypted: {'YES' if instance['StorageEncrypted'] else 'NO'}")
                message_parts.append(f"    - VPC: {instance['VpcId']}")
                for issue in instance['SecurityIssues']:
                    message_parts.append(f"    - ⚠️  {issue['Issue']} (Security Group: {issue['SecurityGroupId']})")
            message_parts.append("")
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Review and restrict public access on identified RDS instances",
            "2. Update security groups to remove 0.0.0.0/0 access",
            "3. Enable encryption at rest for unencrypted databases",
            "4. Consider using VPC endpoints for private access",
            "5. Enable Multi-AZ deployment for high availability",
            "6. Review and implement database subnet groups",
            "",
            "AUTOMATED REMEDIATION COMMANDS:",
            "# Example commands for critical instances:"
        ])
        
        # Add specific remediation commands for critical instances
        if critical_instances:
            for instance in critical_instances[:2]:  # Show commands for first 2 instances
                if instance.get('RemediationCommands'):
                    message_parts.append(f"# Commands for {instance['DBInstanceIdentifier']}:")
                    for cmd in instance['RemediationCommands'][:2]:  # Show first 2 commands
                        message_parts.append(cmd)
                    message_parts.append("")
        
        message_parts.extend([
            "GENERAL REMEDIATION COMMANDS:",
            "# Modify RDS instance to disable public access",
            "aws rds modify-db-instance --db-instance-identifier INSTANCE_ID --no-publicly-accessible",
            "",
            "# Update security group to remove open access",
            "aws ec2 revoke-security-group-ingress --group-id sg-xxxxx --protocol tcp --port 3306 --cidr 0.0.0.0/0",
            "",
            "For detailed instance analysis, check CloudWatch logs or run the audit manually.",
            "",
            "This alert was generated by the automated RDS Security Audit Lambda function."
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
        logger.info(f"Notified about {len(critical_instances)} critical and {len(high_risk_instances)} high risk RDS instances")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for RDS security auditing
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with audit results
    """
    try:
        logger.info("Starting RDS security audit")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        public_only = params.get('public_only',
                               os.environ.get('PUBLIC_ONLY', 'true').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        
        logger.info(f"Configuration - Scan all regions: {scan_all_regions_flag}, "
                   f"Public only: {public_only}, Max workers: {max_workers}")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Auditing AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Scan for RDS instances using parallel processing
        all_instances = scan_all_regions_parallel(scan_all_regions_flag, max_workers)
        
        # Filter instances based on criteria
        filtered_instances = filter_instances(all_instances, public_only)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(all_instances)
        
        # Determine if alerts should be triggered
        alerts_triggered = (summary_stats['critical_risk'] > 0 or 
                          (public_only and summary_stats['public_instances'] > 0))
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Audit completed. Total instances: {summary_stats['total_instances']}, "
                   f"Public instances: {summary_stats['public_instances']}, "
                   f"Critical risk: {summary_stats['critical_risk']}")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(summary_stats, all_instances, account_id)
            if summary_stats['critical_risk'] > 0:
                logger.warning(f"SECURITY ALERT: Found {summary_stats['critical_risk']} RDS instances with critical security risks!")
            if public_only and summary_stats['public_instances'] > 0:
                logger.warning(f"EXPOSURE ALERT: Found {summary_stats['public_instances']} publicly accessible RDS instances!")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': 'RDS security audit completed successfully',
                'results': {
                    'instances': filtered_instances,
                    'summary': summary_stats,
                    'audit_parameters': {
                        'scan_all_regions': scan_all_regions_flag,
                        'public_only': public_only,
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
        logger.error(f"RDS security audit failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'RDS security audit failed',
                'executionId': context.aws_request_id
            }
        }