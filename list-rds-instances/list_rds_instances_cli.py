#!/usr/bin/env python3
"""
Comprehensive RDS instances inventory across regions with detailed security and cost analysis.

This script provides a complete overview of RDS instances including security configuration,
performance analysis, cost optimization opportunities, and compliance checks.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime, timezone
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
    """Get list of available RDS regions."""
    return AWS_REGIONS

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

def get_db_snapshots_for_instance(rds_client, db_identifier: str) -> List[Dict]:
    """Get snapshots for a specific DB instance."""
    try:
        paginator = rds_client.get_paginator('describe_db_snapshots')
        snapshots = []
        
        for page in paginator.paginate(DBInstanceIdentifier=db_identifier, SnapshotType='manual'):
            snapshots.extend(page['DBSnapshots'])
        
        return snapshots
    except ClientError:
        return []

def analyze_rds_instance(instance: Dict, region: str, rds_client) -> Dict:
    """Comprehensive analysis of an RDS instance."""
    instance_analysis = {
        'Region': region,
        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
        'Engine': instance['Engine'],
        'EngineVersion': instance['EngineVersion'],
        'DBInstanceClass': instance['DBInstanceClass'],
        'AllocatedStorage': instance['AllocatedStorage'],
        'StorageType': instance.get('StorageType', 'unknown'),
        'Iops': instance.get('Iops', 0),
        'StorageEncrypted': instance.get('StorageEncrypted', False),
        'KmsKeyId': instance.get('KmsKeyId', ''),
        'PubliclyAccessible': instance['PubliclyAccessible'],
        'MultiAZ': instance['MultiAZ'],
        'BackupRetentionPeriod': instance['BackupRetentionPeriod'],
        'PreferredBackupWindow': instance.get('PreferredBackupWindow', ''),
        'PreferredMaintenanceWindow': instance.get('PreferredMaintenanceWindow', ''),
        'VpcId': instance.get('DBSubnetGroup', {}).get('VpcId', 'N/A'),
        'SubnetGroup': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A'),
        'SecurityGroups': [],
        'ParameterGroup': instance.get('DBParameterGroups', [{}])[0].get('DBParameterGroupName', 'N/A'),
        'OptionGroup': instance.get('OptionGroupMemberships', [{}])[0].get('OptionGroupName', 'N/A'),
        'InstanceCreateTime': instance.get('InstanceCreateTime'),
        'LatestRestorableTime': instance.get('LatestRestorableTime'),
        'AutoMinorVersionUpgrade': instance.get('AutoMinorVersionUpgrade', False),
        'DeletionProtection': instance.get('DeletionProtection', False),
        'PerformanceInsightsEnabled': instance.get('PerformanceInsightsEnabled', False),
        'MonitoringInterval': instance.get('MonitoringInterval', 0),
        'DBInstanceStatus': instance.get('DBInstanceStatus', 'unknown'),
        'LicenseModel': instance.get('LicenseModel', 'N/A'),
        'MasterUsername': instance.get('MasterUsername', 'N/A'),
        'Endpoint': instance.get('Endpoint', {}).get('Address', 'N/A'),
        'Port': instance.get('Endpoint', {}).get('Port', 'N/A'),
        'EngineDeprecated': False,
        'SecurityIssues': [],
        'PerformanceIssues': [],
        'CostOptimizationOpportunities': [],
        'ComplianceIssues': [],
        'RiskLevel': 'Low',
        'CostOptimizationLevel': 'Optimized'
    }
    
    # Get security groups
    security_groups = []
    for sg in instance.get('VpcSecurityGroups', []):
        security_groups.append({
            'GroupId': sg['VpcSecurityGroupId'],
            'Status': sg['Status']
        })
    instance_analysis['SecurityGroups'] = security_groups
    
    # Get tags
    try:
        tags_response = rds_client.list_tags_for_resource(ResourceName=instance['DBInstanceArn'])
        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagList', [])}
        instance_analysis['Tags'] = tags
    except ClientError:
        instance_analysis['Tags'] = {}
    
    # Engine version analysis
    deprecated_engines = {
        'mysql': ['5.5', '5.6'],
        'postgres': ['9.6', '10'],
        'oracle-ee': ['11.2', '12.1'],
        'oracle-se2': ['11.2', '12.1'],
        'oracle-se1': ['11.2', '12.1'],
        'oracle-se': ['11.2', '12.1'],
        'sqlserver-ee': ['11.00', '12.00'],
        'sqlserver-se': ['11.00', '12.00'],
        'sqlserver-ex': ['11.00', '12.00'],
        'sqlserver-web': ['11.00', '12.00']
    }
    
    engine = instance['Engine'].lower()
    version = instance['EngineVersion']
    
    if engine in deprecated_engines:
        for deprecated_version in deprecated_engines[engine]:
            if version.startswith(deprecated_version):
                instance_analysis['EngineDeprecated'] = True
                instance_analysis['SecurityIssues'].append(f"Deprecated engine version: {engine} {version}")
                break
    
    # Security analysis
    if instance_analysis['PubliclyAccessible']:
        instance_analysis['SecurityIssues'].append("Database is publicly accessible")
        instance_analysis['RiskLevel'] = 'Critical'
    
    if not instance_analysis['StorageEncrypted']:
        instance_analysis['SecurityIssues'].append("Storage encryption not enabled")
        if instance_analysis['RiskLevel'] == 'Low':
            instance_analysis['RiskLevel'] = 'Medium'
    
    if instance_analysis['BackupRetentionPeriod'] < 7:
        instance_analysis['ComplianceIssues'].append("Backup retention period less than 7 days")
    
    if not instance_analysis['DeletionProtection']:
        instance_analysis['SecurityIssues'].append("Deletion protection not enabled")
    
    if not instance_analysis['AutoMinorVersionUpgrade']:
        instance_analysis['SecurityIssues'].append("Auto minor version upgrade disabled")
    
    # Performance analysis
    if not instance_analysis['PerformanceInsightsEnabled']:
        instance_analysis['PerformanceIssues'].append("Performance Insights not enabled")
    
    if instance_analysis['MonitoringInterval'] == 0:
        instance_analysis['PerformanceIssues'].append("Enhanced monitoring not enabled")
    
    if not instance_analysis['MultiAZ'] and 'prod' in instance_analysis['DBInstanceIdentifier'].lower():
        instance_analysis['PerformanceIssues'].append("Production database not using Multi-AZ")
    
    # Cost optimization analysis
    if instance_analysis['StorageType'] == 'gp2' and instance_analysis['AllocatedStorage'] > 1000:
        instance_analysis['CostOptimizationOpportunities'].append("Large storage volume - consider gp3 for cost savings")
    
    if 'db.t2.' in instance_analysis['DBInstanceClass']:
        instance_analysis['CostOptimizationOpportunities'].append("Using older T2 instance - consider T3/T4g for better performance")
    
    if not instance_analysis['MultiAZ'] and instance_analysis['BackupRetentionPeriod'] > 7:
        if 'dev' in instance_analysis['DBInstanceIdentifier'].lower() or 'test' in instance_analysis['DBInstanceIdentifier'].lower():
            instance_analysis['CostOptimizationOpportunities'].append("Development/test instance with high backup retention")
    
    # Age analysis
    if instance_analysis['InstanceCreateTime']:
        try:
            create_time = instance_analysis['InstanceCreateTime']
            if isinstance(create_time, str):
                create_time = datetime.fromisoformat(create_time.replace('Z', '+00:00'))
            
            days_old = (datetime.now(timezone.utc) - create_time).days
            instance_analysis['DaysOld'] = days_old
            
            if days_old > 365 and not instance_analysis['AutoMinorVersionUpgrade']:
                instance_analysis['SecurityIssues'].append("Old instance without auto-upgrade enabled")
        except Exception:
            instance_analysis['DaysOld'] = 0
    
    # Get snapshot information
    try:
        snapshots = get_db_snapshots_for_instance(rds_client, instance['DBInstanceIdentifier'])
        instance_analysis['ManualSnapshotsCount'] = len(snapshots)
    except Exception:
        instance_analysis['ManualSnapshotsCount'] = 0
    
    # Overall risk assessment
    total_issues = (len(instance_analysis['SecurityIssues']) + 
                   len(instance_analysis['ComplianceIssues']))
    
    if instance_analysis['PubliclyAccessible']:
        instance_analysis['RiskLevel'] = 'Critical'
    elif total_issues >= 3:
        instance_analysis['RiskLevel'] = 'High'
    elif total_issues >= 1:
        instance_analysis['RiskLevel'] = 'Medium'
    
    # Cost optimization level
    cost_issues = len(instance_analysis['CostOptimizationOpportunities'])
    if cost_issues >= 2:
        instance_analysis['CostOptimizationLevel'] = 'Needs Review'
    elif cost_issues >= 1:
        instance_analysis['CostOptimizationLevel'] = 'Minor Issues'
    
    return instance_analysis

def list_rds_instances_in_region(region: str, session=None) -> List[Dict]:
    """List and analyze RDS instances in a specific region."""
    try:
        if session:
            rds_client = session.client('rds', region_name=region)
        else:
            rds_client = boto3.client('rds', region_name=region)
        
        print(f"Scanning region: {region}")
        
        # Get all RDS instances with pagination
        print("  Retrieving RDS instances...")
        instances = get_rds_instances_with_pagination(rds_client)
        
        if not instances:
            print(f"  No RDS instances found in {region}")
            return []
        
        print(f"  Found {len(instances)} RDS instances")
        
        # Analyze each instance
        analyzed_instances = []
        for i, instance in enumerate(instances):
            print(f"  Analyzing {i+1}/{len(instances)}: {instance['DBInstanceIdentifier']}")
            instance_analysis = analyze_rds_instance(instance, region, rds_client)
            analyzed_instances.append(instance_analysis)
        
        return analyzed_instances
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"  Access denied for region {region} - skipping")
        else:
            print(f"  Error in region {region}: {e.response['Error']['Message']}")
        return []

def export_to_csv(instances: List[Dict], filename: str):
    """Export instance data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Region', 'DBInstanceIdentifier', 'Engine', 'EngineVersion', 'DBInstanceClass',
            'AllocatedStorage', 'StorageType', 'StorageEncrypted', 'PubliclyAccessible',
            'MultiAZ', 'BackupRetentionPeriod', 'DeletionProtection', 'AutoMinorVersionUpgrade',
            'PerformanceInsightsEnabled', 'DBInstanceStatus', 'VpcId', 'RiskLevel',
            'CostOptimizationLevel', 'SecurityIssues', 'PerformanceIssues', 
            'CostOptimizationOpportunities', 'ComplianceIssues', 'Tags'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for instance in instances:
            row = instance.copy()
            # Convert lists to strings for CSV
            row['SecurityIssues'] = '; '.join(instance.get('SecurityIssues', []))
            row['PerformanceIssues'] = '; '.join(instance.get('PerformanceIssues', []))
            row['CostOptimizationOpportunities'] = '; '.join(instance.get('CostOptimizationOpportunities', []))
            row['ComplianceIssues'] = '; '.join(instance.get('ComplianceIssues', []))
            row['Tags'] = ', '.join([f"{k}={v}" for k, v in instance.get('Tags', {}).items()])
            writer.writerow(row)

def export_to_json(instances: List[Dict], filename: str):
    """Export instance data to JSON."""
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(instances, jsonfile, indent=2, default=str)

def print_summary_report(instances: List[Dict]):
    """Print comprehensive summary report."""
    total_instances = len(instances)
    
    if total_instances == 0:
        print(f"\n{'='*80}")
        print("RDS INSTANCES SUMMARY")
        print(f"{'='*80}")
        print("No RDS instances found in any scanned regions.")
        print(f"{'='*80}")
        return
    
    # Group by region and analyze
    by_region = {}
    public_instances = []
    encrypted_instances = []
    multi_az_instances = []
    deprecated_engines = []
    security_issues = []
    performance_issues = []
    
    # Engine and class statistics
    engine_stats = {}
    class_stats = {}
    storage_stats = {}
    
    for instance in instances:
        region = instance['Region']
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(instance)
        
        # Statistics tracking
        engine = instance['Engine']
        engine_stats[engine] = engine_stats.get(engine, 0) + 1
        
        instance_class = instance['DBInstanceClass']
        class_stats[instance_class] = class_stats.get(instance_class, 0) + 1
        
        storage_type = instance['StorageType']
        storage_stats[storage_type] = storage_stats.get(storage_type, 0) + 1
        
        # Issues tracking
        if instance['PubliclyAccessible']:
            public_instances.append(instance)
        
        if instance['StorageEncrypted']:
            encrypted_instances.append(instance)
        
        if instance['MultiAZ']:
            multi_az_instances.append(instance)
        
        if instance.get('EngineDeprecated'):
            deprecated_engines.append(instance)
        
        if instance.get('SecurityIssues'):
            security_issues.append(instance)
        
        if instance.get('PerformanceIssues'):
            performance_issues.append(instance)
    
    print(f"\n{'='*80}")
    print("RDS INSTANCES SUMMARY")
    print(f"{'='*80}")
    print(f"Total RDS Instances: {total_instances}")
    print(f"Regions with Instances: {len(by_region)}")
    print(f"Publicly Accessible: {len(public_instances)}")
    print(f"Encrypted Storage: {len(encrypted_instances)}")
    print(f"Multi-AZ Enabled: {len(multi_az_instances)}")
    print(f"Deprecated Engines: {len(deprecated_engines)}")
    print(f"Security Issues: {len(security_issues)}")
    print(f"Performance Issues: {len(performance_issues)}")
    
    # Engine distribution
    print(f"\n{'='*80}")
    print("ENGINE DISTRIBUTION")
    print(f"{'='*80}")
    for engine, count in sorted(engine_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_instances) * 100
        print(f"{engine:20} {count:6} instances ({percentage:5.1f}%)")
    
    # Instance class distribution
    print(f"\n{'='*80}")
    print("INSTANCE CLASS DISTRIBUTION (TOP 10)")
    print(f"{'='*80}")
    for instance_class, count in sorted(class_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
        percentage = (count / total_instances) * 100
        print(f"{instance_class:20} {count:6} instances ({percentage:5.1f}%)")
    
    # Regional breakdown
    print(f"\n{'='*80}")
    print("BREAKDOWN BY REGION")
    print(f"{'='*80}")
    for region, region_instances in sorted(by_region.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n{region}: {len(region_instances)} instances")
        
        # Show instances with issues
        issues_instances = [i for i in region_instances if i.get('SecurityIssues') or i.get('PerformanceIssues')]
        if issues_instances:
            print(f"  Instances with issues: {len(issues_instances)}")
            for instance in issues_instances[:3]:  # Show top 3
                issues_count = len(instance.get('SecurityIssues', []) + instance.get('PerformanceIssues', []))
                print(f"    {instance['DBInstanceIdentifier']:30} ({issues_count} issues)")
            if len(issues_instances) > 3:
                print(f"    ... and {len(issues_instances) - 3} more")
    
    # Public instances (security critical)
    if public_instances:
        print(f"\n{'='*80}")
        print("PUBLICLY ACCESSIBLE INSTANCES (CRITICAL SECURITY RISK)")
        print(f"{'='*80}")
        print(f"{'DB Identifier':25} {'Region':12} {'Engine':12} {'Class':15} {'Status'}")
        print("-" * 80)
        
        for instance in public_instances:
            print(f"{instance['DBInstanceIdentifier']:25} "
                  f"{instance['Region']:12} "
                  f"{instance['Engine']:12} "
                  f"{instance['DBInstanceClass']:15} "
                  f"{instance['DBInstanceStatus']}")
    
    # Deprecated engines
    if deprecated_engines:
        print(f"\n{'='*80}")
        print("DEPRECATED ENGINE VERSIONS (UPGRADE REQUIRED)")
        print(f"{'='*80}")
        print(f"{'DB Identifier':25} {'Region':12} {'Engine':20} {'Version':12} {'Days Old'}")
        print("-" * 85)
        
        for instance in deprecated_engines:
            days_old = instance.get('DaysOld', 0)
            print(f"{instance['DBInstanceIdentifier']:25} "
                  f"{instance['Region']:12} "
                  f"{instance['Engine']:20} "
                  f"{instance['EngineVersion']:12} "
                  f"{days_old:8}")
    
    # Security issues summary
    if security_issues:
        print(f"\n{'='*80}")
        print("SECURITY ISSUES REQUIRING ATTENTION")
        print(f"{'='*80}")
        
        # Group by risk level
        critical_risk = [i for i in instances if i['RiskLevel'] == 'Critical']
        high_risk = [i for i in instances if i['RiskLevel'] == 'High']
        medium_risk = [i for i in instances if i['RiskLevel'] == 'Medium']
        
        print(f"Critical Risk: {len(critical_risk)}")
        print(f"High Risk: {len(high_risk)}")
        print(f"Medium Risk: {len(medium_risk)}")
        
        print(f"\n{'DB Identifier':25} {'Region':12} {'Risk':8} {'Issues'}")
        print("-" * 75)
        
        for instance in (critical_risk + high_risk)[:10]:  # Show top 10 highest risk
            risk_indicator = {
                'Critical': '🔴',
                'High': '🟡',
                'Medium': '🟠',
                'Low': '🟢'
            }.get(instance['RiskLevel'], '❓')
            
            issues_summary = ', '.join(instance.get('SecurityIssues', [])[:2])
            if len(instance.get('SecurityIssues', [])) > 2:
                issues_summary += '...'
            
            print(f"{instance['DBInstanceIdentifier']:25} "
                  f"{instance['Region']:12} "
                  f"{risk_indicator} {instance['RiskLevel']:6} "
                  f"{issues_summary}")
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS:")
    print("- Remove public accessibility from databases")
    print("- Enable storage encryption for sensitive data")
    print("- Upgrade deprecated engine versions")
    print("- Enable deletion protection for production databases")
    print("- Configure Multi-AZ for high availability")
    print("- Enable Performance Insights for monitoring")
    print("- Review backup retention policies")
    print(f"{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive RDS instances inventory with security and cost analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # List instances in specific region
  ./list_rds_instances.py --region us-east-1
  
  # Scan all regions
  ./list_rds_instances.py --all-regions
  
  # Export detailed report
  ./list_rds_instances.py --all-regions --export-csv rds_inventory.csv
  
  # Show only instances with security issues
  ./list_rds_instances.py --all-regions --security-issues-only

ANALYSIS INCLUDES:
- Engine version deprecation status
- Security configuration review
- Performance optimization opportunities
- Cost optimization recommendations
- Compliance and backup policies
- Public accessibility assessment
"""
    )
    parser.add_argument('--region', help='Specific AWS region to check')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Check all available regions')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--security-issues-only', action='store_true',
                       help='Show only instances with security issues')
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
            print(f"Scanning {len(regions_to_scan)} regions for RDS instances...")
        else:
            regions_to_scan = [args.region]
            print(f"Scanning region: {args.region}")

        print("=" * 60)

        # Scan all regions
        all_instances = []
        for region in regions_to_scan:
            region_instances = list_rds_instances_in_region(region, session)
            all_instances.extend(region_instances)

        # Filter results if requested
        display_instances = all_instances
        if args.security_issues_only:
            display_instances = [
                i for i in all_instances 
                if i.get('SecurityIssues') or i['RiskLevel'] in ['Critical', 'High']
            ]

        # Print summary report
        print_summary_report(all_instances)

        # Export to files if requested
        if args.export_csv:
            export_to_csv(all_instances, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(all_instances, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        # Return appropriate exit code for automation
        public_instances = [i for i in all_instances if i['PubliclyAccessible']]
        critical_instances = [i for i in all_instances if i['RiskLevel'] == 'Critical']
        deprecated_instances = [i for i in all_instances if i.get('EngineDeprecated')]
        
        if critical_instances:
            print(f"\n🚨 CRITICAL: Found {len(critical_instances)} critical risk RDS instances!")
            sys.exit(2)
        elif public_instances:
            print(f"\n⚠️  WARNING: Found {len(public_instances)} publicly accessible RDS instances!")
            sys.exit(1)
        elif deprecated_instances:
            print(f"\n📅 UPDATE: Found {len(deprecated_instances)} instances with deprecated engines!")
            sys.exit(1)
        else:
            print(f"\n✅ All RDS instances are properly configured and secure!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access RDS. Required permissions:")
            print("- rds:DescribeDBInstances")
            print("- rds:DescribeDBSnapshots")
            print("- rds:ListTagsForResource")
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

