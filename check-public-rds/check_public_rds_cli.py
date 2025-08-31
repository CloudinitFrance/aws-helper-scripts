#!/usr/bin/env python3
"""
Detect publicly accessible RDS instances — comprehensive security audit.

This script scans RDS instances across AWS regions to identify potential
security risks from databases accessible from the internet.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def validate_aws_credentials(session=None):
    """Validate AWS credentials before proceeding."""
    try:
        if session:
            sts = session.client('sts')
        else:
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
    """Get list of available RDS regions."""
    return AWS_REGIONS

def analyze_security_groups(ec2_client, security_group_ids: List[str]) -> List[Dict]:
    """Analyze security groups for RDS instances."""
    security_issues = []
    
    try:
        if not security_group_ids:
            return security_issues
            
        response = ec2_client.describe_security_groups(GroupIds=security_group_ids)
        
        for sg in response['SecurityGroups']:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'Unknown')
            
            for rule in sg.get('IpPermissions', []):
                # Check for overly permissive rules
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        protocol = rule.get('IpProtocol', 'All')
                        
                        security_issues.append({
                            'SecurityGroupId': sg_id,
                            'SecurityGroupName': sg_name,
                            'Issue': 'Open to Internet (0.0.0.0/0)',
                            'Protocol': protocol,
                            'Ports': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                            'Risk': 'Critical'
                        })
                
                # Check for large CIDR blocks
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr and '/' in cidr:
                        network_size = int(cidr.split('/')[-1])
                        if network_size <= 16:  # Large networks
                            security_issues.append({
                                'SecurityGroupId': sg_id,
                                'SecurityGroupName': sg_name,
                                'Issue': f'Large network access ({cidr})',
                                'Protocol': rule.get('IpProtocol', 'All'),
                                'Ports': f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}",
                                'Risk': 'High'
                            })
        
        return security_issues
        
    except ClientError as e:
        print(f"Warning: Could not analyze security groups: {e.response['Error']['Message']}")
        return []

def get_rds_instances_with_pagination(rds_client) -> List[Dict]:
    """Get all RDS instances with pagination."""
    instances = []
    
    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            instances.extend(page['DBInstances'])
        
        return instances
        
    except ClientError as e:
        print(f"Error retrieving RDS instances: {e.response['Error']['Message']}")
        return []

def analyze_rds_security(rds_instance: Dict, region: str, ec2_client) -> Dict:
    """Comprehensive security analysis for an RDS instance."""
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
        'VpcId': None,
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
    
    return instance_info

def check_public_rds_in_region(region: str, session=None) -> List[Dict]:
    """Check RDS instances in a specific region."""
    try:
        if session:
            rds_client = session.client('rds', region_name=region)
            ec2_client = session.client('ec2', region_name=region)
        else:
            rds_client = boto3.client('rds', region_name=region)
            ec2_client = boto3.client('ec2', region_name=region)
        
        print(f"Scanning region: {region}")
        
        # Get all RDS instances with pagination
        instances = get_rds_instances_with_pagination(rds_client)
        
        if not instances:
            print(f"  No RDS instances found in {region}")
            return []
        
        print(f"  Found {len(instances)} RDS instances")
        
        # Analyze each instance
        analyzed_instances = []
        for instance in instances:
            instance_info = analyze_rds_security(instance, region, ec2_client)
            analyzed_instances.append(instance_info)
        
        return analyzed_instances
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"  Access denied for region {region} - skipping")
        else:
            print(f"  Error in region {region}: {e.response['Error']['Message']}")
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

def send_sns_alert(instances: List[Dict], sns_topic_arn: str) -> None:
    """Send SNS alert for critical and high risk RDS findings."""
    try:
        import boto3
        from datetime import datetime
        
        sns_client = boto3.client('sns')
        
        # Filter for critical and high risk instances
        critical_instances = [i for i in instances if i['RiskLevel'] == 'Critical']
        high_risk_instances = [i for i in instances if i['RiskLevel'] == 'High']
        
        if not critical_instances and not high_risk_instances:
            print("📧 No critical or high risk RDS findings to alert")
            return
        
        # Get current timestamp and account info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            sts_client = boto3.client('sts')
            account_id = sts_client.get_caller_identity().get('Account', 'Unknown')
        except:
            account_id = 'Unknown'
        
        # Calculate summary stats
        summary_stats = {
            'total_instances': len(instances),
            'public_instances': len([i for i in instances if i['PubliclyAccessible']]),
            'critical_risk': len(critical_instances),
            'high_risk': len(high_risk_instances),
            'unencrypted_instances': len([i for i in instances if not i['StorageEncrypted']])
        }
        
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
                commands = generate_remediation_commands(instance)
                if commands:
                    message_parts.append(f"# Commands for {instance['DBInstanceIdentifier']}:")
                    for cmd in commands[:2]:  # Show first 2 commands
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
            "For detailed analysis, run the CLI audit again or check the exported remediation commands.",
            "",
            "This alert was generated by the RDS Security Audit CLI tool."
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
        print(f"📧 Notified about {len(critical_instances)} critical and {len(high_risk_instances)} high risk RDS instances")
        
    except Exception as e:
        print(f"❌ Failed to send SNS notification: {str(e)}")

def scan_all_regions_parallel(regions_to_scan: List[str], session=None, max_workers: int = 10) -> List[Dict]:
    """
    Scan RDS instances across regions using parallel threading.
    
    Args:
        regions_to_scan: List of AWS regions to scan
        session: AWS session to use
        max_workers: Maximum number of worker threads
        
    Returns:
        List of analyzed RDS instances from all regions
    """
    all_instances = []
    print_lock = threading.Lock()
    
    def scan_region_with_logging(region):
        """Scan a single region with thread-safe logging."""
        try:
            with print_lock:
                print(f"Scanning region: {region}")
            
            region_instances = check_public_rds_in_region(region, session)
            
            with print_lock:
                if region_instances:
                    print(f"  Found {len(region_instances)} RDS instances in {region}")
                else:
                    print(f"  No RDS instances found in {region}")
            
            return region_instances
            
        except Exception as e:
            with print_lock:
                print(f"  Error scanning region {region}: {e}")
            return []
    
    if len(regions_to_scan) > 1:
        print(f"🚀 Using parallel processing with {min(max_workers, len(regions_to_scan))} workers...")
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=min(max_workers, len(regions_to_scan))) as executor:
            # Submit all region scanning tasks
            future_to_region = {
                executor.submit(scan_region_with_logging, region): region
                for region in regions_to_scan
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    region_instances = future.result()
                    all_instances.extend(region_instances)
                except Exception as e:
                    with print_lock:
                        print(f"Error processing results for region {region}: {e}")
    else:
        # Single region, no need for parallel processing
        for region in regions_to_scan:
            region_instances = check_public_rds_in_region(region, session)
            all_instances.extend(region_instances)
    
    print(f"Parallel scanning complete. Total instances found: {len(all_instances)}")
    return all_instances

def export_to_csv(instances: List[Dict], filename: str):
    """Export instance data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Region', 'DBInstanceIdentifier', 'Engine', 'EngineVersion', 'DBInstanceClass',
            'PubliclyAccessible', 'Endpoint', 'Port', 'StorageEncrypted', 'MultiAZ',
            'BackupRetentionPeriod', 'VpcId', 'SubnetGroup', 'RiskLevel', 'SecurityIssues'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for instance in instances:
            row = instance.copy()
            # Convert security issues to string
            issues = []
            for issue in instance.get('SecurityIssues', []):
                issues.append(f"{issue['Issue']} ({issue['Risk']})")
            row['SecurityIssues'] = '; '.join(issues)
            writer.writerow(row)

def export_to_json(instances: List[Dict], filename: str):
    """Export instance data to JSON."""
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(instances, jsonfile, indent=2, default=str)

def print_summary_report(instances: List[Dict]):
    """Print comprehensive summary report."""
    total_instances = len(instances)
    public_instances = [i for i in instances if i['PubliclyAccessible']]
    encrypted_instances = [i for i in instances if i['StorageEncrypted']]
    
    # Risk analysis
    critical_risk = [i for i in instances if i['RiskLevel'] == 'Critical']
    high_risk = [i for i in instances if i['RiskLevel'] == 'High']
    medium_risk = [i for i in instances if i['RiskLevel'] == 'Medium']
    
    print(f"\n{'='*80}")
    print("RDS SECURITY ASSESSMENT SUMMARY")
    print(f"{'='*80}")
    print(f"Total RDS Instances: {total_instances}")
    print(f"Publicly Accessible: {len(public_instances)}")
    print(f"Encrypted Storage: {len(encrypted_instances)}")
    print(f"Critical Risk: {len(critical_risk)}")
    print(f"High Risk: {len(high_risk)}")
    print(f"Medium Risk: {len(medium_risk)}")
    
    if public_instances:
        print(f"\n{'='*80}")
        print("PUBLICLY ACCESSIBLE INSTANCES (IMMEDIATE ATTENTION REQUIRED)")
        print(f"{'='*80}")
        
        print(f"\n{'Identifier':25} {'Region':12} {'Engine':10} {'Risk':8} {'Endpoint'}")
        print("-" * 90)
        
        # Sort by risk level
        sorted_instances = sorted(public_instances, 
                                key=lambda x: (x['RiskLevel'] != 'Critical', x['RiskLevel'] != 'High'))
        
        for instance in sorted_instances:
            risk_indicator = {
                'Critical': '🔴',
                'High': '🟡', 
                'Medium': '🟠',
                'Low': '🟢'
            }.get(instance['RiskLevel'], '❓')
            
            print(f"{instance['DBInstanceIdentifier']:25} "
                  f"{instance['Region']:12} "
                  f"{instance['Engine']:10} "
                  f"{risk_indicator} {instance['RiskLevel']:6} "
                  f"{instance['Endpoint']}")
            
            # Show security issues
            for issue in instance.get('SecurityIssues', []):
                print(f"  └── {issue['Issue']} - {issue['Protocol']} {issue['Ports']}")
            
            # Show remediation commands for high-risk instances
            if instance['RiskLevel'] in ['Critical', 'High']:
                remediation_commands = generate_remediation_commands(instance)
                if remediation_commands:
                    print(f"  📋 Remediation commands:")
                    for i, command in enumerate(remediation_commands, 1):
                        print(f"    {i}. {command.split('#')[1].strip() if '#' in command else 'Fix command'}")
    
    # Show unencrypted instances
    unencrypted = [i for i in instances if not i['StorageEncrypted']]
    if unencrypted:
        print(f"\n{'='*80}")
        print("UNENCRYPTED INSTANCES")
        print(f"{'='*80}")
        for instance in unencrypted:
            print(f"  {instance['DBInstanceIdentifier']} ({instance['Region']}) - {instance['Engine']}")
    
    print(f"\n{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive RDS security audit with multi-region support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Scan specific region
  ./check_public_rds.py --region us-east-1
  
  # Use specific AWS profile
  ./check_public_rds.py --profile production --all-regions
  
  # Scan all regions
  ./check_public_rds.py --all-regions
  
  # Export detailed report with profile
  ./check_public_rds.py --profile staging --all-regions --export-csv rds_security_report.csv
  
  # Show only public instances for production environment
  ./check_public_rds.py --profile production --all-regions --public-only
  
  # Export remediation commands for high-risk instances
  ./check_public_rds.py --all-regions --export-remediation fix_rds_security.sh
  
  # Send SNS alerts for critical/high-risk instances
  ./check_public_rds.py --all-regions --sns-topic arn:aws:sns:us-east-1:123456789012:rds-security-alerts
  
  # Use parallel processing with custom worker count
  ./check_public_rds.py --all-regions --parallel --max-workers 15

SECURITY CHECKS:
- Public accessibility
- Security group configuration
- Storage encryption
- Backup settings
- Multi-AZ deployment
- Engine version analysis

PERFORMANCE FEATURES:
- Parallel region scanning for faster multi-region audits
- Configurable worker thread limits
- Thread-safe logging and progress tracking
"""
    )
    parser.add_argument('--region', help='Specific AWS region to check')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Check all available regions')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--public-only', action='store_true',
                       help='Show only publicly accessible instances')
    parser.add_argument('--export-remediation', help='Export remediation commands to file')
    parser.add_argument('--sns-topic', help='SNS topic ARN for security alerts')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--parallel', action='store_true',
                       help='Use parallel processing for multi-region scans (default: enabled for --all-regions)')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Maximum number of worker threads for parallel processing (default: 10)')
    
    args = parser.parse_args()

    # Validate arguments
    if not args.region and not args.all_regions:
        print("Error: Must specify either --region or --all-regions")
        sys.exit(1)

    # Create AWS session with profile if specified
    session = None
    if args.profile:
        try:
            session = boto3.Session(profile_name=args.profile)
            print(f"Using AWS profile: {args.profile}")
        except ProfileNotFound:
            print(f"Error: AWS profile '{args.profile}' not found.")
            print("Available profiles can be listed with: aws configure list-profiles")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading AWS profile '{args.profile}': {e}")
            sys.exit(1)

    # Validate credentials
    if not validate_aws_credentials(session):
        sys.exit(1)

    try:

        # Determine regions to scan
        regions_to_scan = []
        if args.all_regions:
            # Get all available regions
            ec2_client = session.client('ec2') if session else boto3.client('ec2')
            regions_to_scan = get_available_regions(ec2_client)
            print(f"Scanning {len(regions_to_scan)} regions for RDS instances...")
        else:
            regions_to_scan = [args.region]
            print(f"Scanning region: {args.region}")

        print("=" * 60)

        # Determine if we should use parallel processing
        use_parallel = args.parallel or (args.all_regions and len(regions_to_scan) > 1)
        
        # Validate max_workers
        max_workers = max(1, min(args.max_workers, 20))  # Limit between 1 and 20
        
        # Scan all regions
        if use_parallel:
            all_instances = scan_all_regions_parallel(regions_to_scan, session, max_workers)
        else:
            all_instances = []
            for region in regions_to_scan:
                region_instances = check_public_rds_in_region(region, session)
                all_instances.extend(region_instances)

        if not all_instances:
            print("No RDS instances found in any scanned regions.")
            return

        # Filter results if requested
        display_instances = all_instances
        if args.public_only:
            display_instances = [i for i in all_instances if i['PubliclyAccessible']]

        # Print summary report
        print_summary_report(all_instances)

        # Export to files if requested
        if args.export_csv:
            export_to_csv(all_instances, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(all_instances, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        if args.export_remediation:
            # Generate remediation commands for all high-risk instances
            high_risk_instances = [i for i in all_instances if i['RiskLevel'] in ['Critical', 'High']]
            if high_risk_instances:
                with open(args.export_remediation, 'w', encoding='utf-8') as f:
                    f.write("#!/bin/bash\n")
                    f.write("# RDS Security Remediation Commands\n")
                    f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("# Review each command before execution!\n\n")
                    
                    for instance in high_risk_instances:
                        f.write(f"# === {instance['DBInstanceIdentifier']} ({instance['Region']}) ===\n")
                        f.write(f"# Risk Level: {instance['RiskLevel']}\n")
                        f.write(f"# Issues: {len(instance.get('SecurityIssues', []))}\n\n")
                        
                        commands = generate_remediation_commands(instance)
                        for command in commands:
                            f.write(f"{command}\n\n")
                        f.write("# " + "="*50 + "\n\n")
                
                print(f"🔧 Remediation commands exported to: {args.export_remediation}")
            else:
                print("📝 No high-risk instances found - no remediation commands to export")

        # Send SNS alerts if requested
        if args.sns_topic:
            critical_and_high_instances = [i for i in all_instances if i['RiskLevel'] in ['Critical', 'High']]
            if critical_and_high_instances:
                print(f"\n📧 Sending SNS alert for {len(critical_and_high_instances)} high-risk instances...")
                send_sns_alert(all_instances, args.sns_topic)
            else:
                print("\n📧 No critical or high-risk instances - no SNS alert sent")

        # Return appropriate exit code for automation
        public_instances = [i for i in all_instances if i['PubliclyAccessible']]
        critical_instances = [i for i in all_instances if i['RiskLevel'] == 'Critical']
        
        if critical_instances:
            print(f"\n🚨 CRITICAL: Found {len(critical_instances)} critical risk RDS instances!")
            sys.exit(2)
        elif public_instances:
            print(f"\n⚠️  WARNING: Found {len(public_instances)} publicly accessible RDS instances!")
            sys.exit(1)
        else:
            print(f"\n✅ All RDS instances are properly secured!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access RDS. Required permissions:")
            print("- rds:DescribeDBInstances")
            print("- ec2:DescribeSecurityGroups")
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

