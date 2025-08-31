#!/usr/bin/env python3
"""
List RDS Instances Inventory - Lambda Version
Serverless function for automated RDS database inventory and monitoring
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

def get_instance_tags(rds_client, resource_arn: str) -> Dict[str, str]:
    """Get tags for an RDS instance."""
    tags = {}
    try:
        response = rds_client.list_tags_for_resource(ResourceName=resource_arn)
        for tag in response.get('TagList', []):
            tags[tag['Key']] = tag['Value']
    except ClientError as e:
        logger.warning(f"Error getting tags for {resource_arn}: {e}")
    return tags

def calculate_estimated_monthly_cost(instance_class: str, storage_gb: int, multi_az: bool, engine: str) -> float:
    """Calculate estimated monthly cost for RDS instance (approximate)."""
    # This is a simplified cost calculation - actual costs vary by region and specific pricing
    
    # Basic instance cost per hour (simplified mapping)
    instance_costs = {
        'db.t3.micro': 0.017,
        'db.t3.small': 0.034,
        'db.t3.medium': 0.068,
        'db.t3.large': 0.136,
        'db.t3.xlarge': 0.272,
        'db.t3.2xlarge': 0.544,
        'db.m5.large': 0.192,
        'db.m5.xlarge': 0.384,
        'db.m5.2xlarge': 0.768,
        'db.m5.4xlarge': 1.536,
        'db.r5.large': 0.240,
        'db.r5.xlarge': 0.480,
        'db.r5.2xlarge': 0.960,
        'db.r5.4xlarge': 1.920,
    }
    
    # Get base instance cost (default to t3.medium if not found)
    base_cost_per_hour = instance_costs.get(instance_class, 0.068)
    
    # Multi-AZ doubles the instance cost
    if multi_az:
        base_cost_per_hour *= 2
    
    # Storage cost (approximate $0.115 per GB-month for GP2)
    storage_cost_per_month = storage_gb * 0.115
    
    # Hours in a month (approximate)
    hours_per_month = 730
    
    # Total monthly cost
    total_monthly_cost = (base_cost_per_hour * hours_per_month) + storage_cost_per_month
    
    return round(total_monthly_cost, 2)

def list_rds_instances_in_region(region: str) -> Dict:
    """List RDS instances in a specific region with detailed information."""
    try:
        rds_client = boto3.client('rds', region_name=region)
        
        logger.info(f"Listing RDS instances in region: {region}")
        
        instances = []
        clusters = []
        
        # Get RDS instances
        paginator = rds_client.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                # Get tags
                tags = get_instance_tags(rds_client, instance['DBInstanceArn'])
                
                # Calculate estimated cost
                storage_gb = instance.get('AllocatedStorage', 0)
                estimated_cost = calculate_estimated_monthly_cost(
                    instance.get('DBInstanceClass', ''),
                    storage_gb,
                    instance.get('MultiAZ', False),
                    instance.get('Engine', '')
                )
                
                instance_info = {
                    'DBInstanceIdentifier': instance.get('DBInstanceIdentifier', 'Unknown'),
                    'DBInstanceArn': instance.get('DBInstanceArn', 'Unknown'),
                    'DBInstanceClass': instance.get('DBInstanceClass', 'Unknown'),
                    'Engine': instance.get('Engine', 'Unknown'),
                    'EngineVersion': instance.get('EngineVersion', 'Unknown'),
                    'DBInstanceStatus': instance.get('DBInstanceStatus', 'Unknown'),
                    'MasterUsername': instance.get('MasterUsername', 'Unknown'),
                    'Endpoint': instance.get('Endpoint', {}).get('Address', 'Unknown'),
                    'Port': instance.get('Endpoint', {}).get('Port', 'Unknown'),
                    'AllocatedStorage': storage_gb,
                    'StorageType': instance.get('StorageType', 'Unknown'),
                    'StorageEncrypted': instance.get('StorageEncrypted', False),
                    'KmsKeyId': instance.get('KmsKeyId', ''),
                    'InstanceCreateTime': instance.get('InstanceCreateTime', '').isoformat() if instance.get('InstanceCreateTime') else 'Unknown',
                    'AvailabilityZone': instance.get('AvailabilityZone', 'Unknown'),
                    'MultiAZ': instance.get('MultiAZ', False),
                    'PubliclyAccessible': instance.get('PubliclyAccessible', False),
                    'BackupRetentionPeriod': instance.get('BackupRetentionPeriod', 0),
                    'PreferredBackupWindow': instance.get('PreferredBackupWindow', 'Unknown'),
                    'PreferredMaintenanceWindow': instance.get('PreferredMaintenanceWindow', 'Unknown'),
                    'DBSubnetGroupName': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'Unknown'),
                    'VpcId': instance.get('DBSubnetGroup', {}).get('VpcId', 'Unknown'),
                    'SecurityGroups': [sg.get('VpcSecurityGroupId', 'Unknown') for sg in instance.get('VpcSecurityGroups', [])],
                    'ParameterGroupName': instance.get('DBParameterGroups', [{}])[0].get('DBParameterGroupName', 'Unknown') if instance.get('DBParameterGroups') else 'Unknown',
                    'OptionGroupName': instance.get('OptionGroupMemberships', [{}])[0].get('OptionGroupName', 'Unknown') if instance.get('OptionGroupMemberships') else 'Unknown',
                    'AutoMinorVersionUpgrade': instance.get('AutoMinorVersionUpgrade', False),
                    'ReadReplicaSourceDBInstanceIdentifier': instance.get('ReadReplicaSourceDBInstanceIdentifier', ''),
                    'ReadReplicaDBInstanceIdentifiers': instance.get('ReadReplicaDBInstanceIdentifiers', []),
                    'LicenseModel': instance.get('LicenseModel', 'Unknown'),
                    'Iops': instance.get('Iops', 0),
                    'DeletionProtection': instance.get('DeletionProtection', False),
                    'PerformanceInsightsEnabled': instance.get('PerformanceInsightsEnabled', False),
                    'MonitoringInterval': instance.get('MonitoringInterval', 0),
                    'Tags': tags,
                    'EstimatedMonthlyCost': estimated_cost
                }
                instances.append(instance_info)
        
        # Get RDS clusters (Aurora)
        try:
            cluster_paginator = rds_client.get_paginator('describe_db_clusters')
            
            for page in cluster_paginator.paginate():
                for cluster in page['DBClusters']:
                    # Get tags
                    tags = get_instance_tags(rds_client, cluster['DBClusterArn'])
                    
                    cluster_info = {
                        'DBClusterIdentifier': cluster.get('DBClusterIdentifier', 'Unknown'),
                        'DBClusterArn': cluster.get('DBClusterArn', 'Unknown'),
                        'Engine': cluster.get('Engine', 'Unknown'),
                        'EngineVersion': cluster.get('EngineVersion', 'Unknown'),
                        'Status': cluster.get('Status', 'Unknown'),
                        'MasterUsername': cluster.get('MasterUsername', 'Unknown'),
                        'Endpoint': cluster.get('Endpoint', 'Unknown'),
                        'ReaderEndpoint': cluster.get('ReaderEndpoint', 'Unknown'),
                        'Port': cluster.get('Port', 'Unknown'),
                        'DatabaseName': cluster.get('DatabaseName', 'Unknown'),
                        'ClusterCreateTime': cluster.get('ClusterCreateTime', '').isoformat() if cluster.get('ClusterCreateTime') else 'Unknown',
                        'BackupRetentionPeriod': cluster.get('BackupRetentionPeriod', 0),
                        'PreferredBackupWindow': cluster.get('PreferredBackupWindow', 'Unknown'),
                        'PreferredMaintenanceWindow': cluster.get('PreferredMaintenanceWindow', 'Unknown'),
                        'AvailabilityZones': cluster.get('AvailabilityZones', []),
                        'VpcSecurityGroups': [sg.get('VpcSecurityGroupId', 'Unknown') for sg in cluster.get('VpcSecurityGroups', [])],
                        'DBSubnetGroup': cluster.get('DBSubnetGroup', 'Unknown'),
                        'StorageEncrypted': cluster.get('StorageEncrypted', False),
                        'KmsKeyId': cluster.get('KmsKeyId', ''),
                        'DBClusterMembers': [{'DBInstanceIdentifier': member.get('DBInstanceIdentifier', 'Unknown'), 
                                            'IsClusterWriter': member.get('IsClusterWriter', False)} 
                                           for member in cluster.get('DBClusterMembers', [])],
                        'DeletionProtection': cluster.get('DeletionProtection', False),
                        'MultiAZ': cluster.get('MultiAZ', False),
                        'Tags': tags
                    }
                    clusters.append(cluster_info)
        
        except ClientError as e:
            if e.response['Error']['Code'] not in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Error getting clusters in {region}: {e}")
        
        # Calculate statistics
        total_instances = len(instances)
        total_clusters = len(clusters)
        
        # Engine distribution
        engines = {}
        instance_classes = {}
        storage_types = {}
        
        for instance in instances:
            engine = instance.get('Engine', 'Unknown')
            engines[engine] = engines.get(engine, 0) + 1
            
            instance_class = instance.get('DBInstanceClass', 'Unknown')
            instance_classes[instance_class] = instance_classes.get(instance_class, 0) + 1
            
            storage_type = instance.get('StorageType', 'Unknown')
            storage_types[storage_type] = storage_types.get(storage_type, 0) + 1
        
        # Security metrics
        publicly_accessible = len([i for i in instances if i.get('PubliclyAccessible', False)])
        encrypted_instances = len([i for i in instances if i.get('StorageEncrypted', False)])
        multi_az_instances = len([i for i in instances if i.get('MultiAZ', False)])
        deletion_protected = len([i for i in instances if i.get('DeletionProtection', False)])
        
        # Cost metrics
        total_estimated_cost = sum(i.get('EstimatedMonthlyCost', 0) for i in instances)
        total_storage_gb = sum(i.get('AllocatedStorage', 0) for i in instances)
        
        region_results = {
            'region': region,
            'db_instances': instances[:50],  # Limit for response size
            'db_clusters': clusters[:50],  # Limit for response size
            'statistics': {
                'total_db_instances': total_instances,
                'total_db_clusters': total_clusters,
                'total_databases': total_instances + total_clusters,
                'engine_distribution': engines,
                'instance_class_distribution': instance_classes,
                'storage_type_distribution': storage_types,
                'publicly_accessible_instances': publicly_accessible,
                'encrypted_instances': encrypted_instances,
                'multi_az_instances': multi_az_instances,
                'deletion_protected_instances': deletion_protected,
                'total_allocated_storage_gb': total_storage_gb,
                'total_estimated_monthly_cost': total_estimated_cost,
                'average_cost_per_instance': round(total_estimated_cost / max(total_instances, 1), 2),
                'security_score': round(((encrypted_instances + deletion_protected + (total_instances - publicly_accessible)) / max(total_instances * 3, 1)) * 100, 1)
            },
            'errors': []
        }
        
        logger.info(f"Completed listing for {region}: {total_instances} instances, {total_clusters} clusters")
        return region_results
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'db_instances': [],
            'db_clusters': [],
            'statistics': {
                'total_db_instances': 0,
                'total_db_clusters': 0,
                'total_databases': 0,
                'engine_distribution': {},
                'instance_class_distribution': {},
                'storage_type_distribution': {},
                'publicly_accessible_instances': 0,
                'encrypted_instances': 0,
                'multi_az_instances': 0,
                'deletion_protected_instances': 0,
                'total_allocated_storage_gb': 0,
                'total_estimated_monthly_cost': 0,
                'average_cost_per_instance': 0,
                'security_score': 0
            },
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def list_rds_instances_parallel(scan_all_regions_flag: bool, max_workers: int = 10) -> List[Dict]:
    """
    List RDS instances across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Listing RDS instances in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Listing RDS instances in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region listing tasks
        future_to_region = {
            executor.submit(list_rds_instances_in_region, region): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed listing for {region}: "
                           f"{result['statistics']['total_databases']} databases")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'db_instances': [],
                    'db_clusters': [],
                    'statistics': {
                        'total_db_instances': 0,
                        'total_db_clusters': 0,
                        'total_databases': 0,
                        'engine_distribution': {},
                        'instance_class_distribution': {},
                        'storage_type_distribution': {},
                        'publicly_accessible_instances': 0,
                        'encrypted_instances': 0,
                        'multi_az_instances': 0,
                        'deletion_protected_instances': 0,
                        'total_allocated_storage_gb': 0,
                        'total_estimated_monthly_cost': 0,
                        'average_cost_per_instance': 0,
                        'security_score': 0
                    },
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel RDS instances listing complete")
    return all_results

def send_security_notifications(summary_stats: Dict, results: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk RDS security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Get key metrics
        public_instances = summary_stats['total_publicly_accessible_instances']
        security_score = summary_stats['overall_security_score']
        total_instances = summary_stats['total_db_instances']
        unencrypted_instances = total_instances - summary_stats['total_encrypted_instances']
        
        # Determine if notification is needed
        needs_notification = (public_instances > 0 or 
                            security_score < 85 or  # Lower threshold than other services
                            unencrypted_instances > 0)
        
        if not needs_notification:
            logger.info("No critical or high risk RDS security findings to notify")
            return
        
        # Determine risk level and subject
        if public_instances > 0 and unencrypted_instances > 0:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL RDS Security Alert - {public_instances} Public Unencrypted Databases"
        elif public_instances > 0:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL RDS Security Alert - {public_instances} Publicly Accessible Databases"
        elif security_score < 50:
            risk_level = "CRITICAL"
            subject = f"🚨 CRITICAL RDS Security Alert - Security Score {security_score}%"
        elif security_score < 70 or unencrypted_instances > 0:
            risk_level = "HIGH"
            subject = f"⚠️ HIGH RDS Security Alert - Security Issues Detected"
        else:
            risk_level = "MEDIUM"
            subject = f"🟡 RDS Security Alert - Security Score {security_score}%"
        
        # Build notification message
        message_parts = [
            f"RDS DATABASE SECURITY ASSESSMENT ALERT",
            f"Risk Level: {risk_level}",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total RDS instances: {total_instances}",
            f"• Total RDS clusters: {summary_stats['total_db_clusters']}",
            f"• Publicly accessible instances: {public_instances}",
            f"• Unencrypted instances: {unencrypted_instances}",
            f"• Multi-AZ instances: {summary_stats['total_multi_az_instances']}",
            f"• Deletion protected instances: {summary_stats['total_deletion_protected_instances']}",
            f"• Overall security score: {security_score}%",
            f"• Estimated monthly cost: ${summary_stats['total_estimated_monthly_cost']:,.2f}",
            f""
        ]
        
        # Add public instances details if any
        if public_instances > 0:
            message_parts.append("🔴 PUBLICLY ACCESSIBLE INSTANCES:")
            public_count = 0
            for result in results:
                for instance in result.get('db_instances', []):
                    if instance.get('PubliclyAccessible', False) and public_count < 10:  # Limit to 10 instances
                        message_parts.append(f"  • {instance['DBInstanceIdentifier']} ({result['region']})")
                        message_parts.append(f"    - Engine: {instance.get('Engine', 'Unknown')} {instance.get('EngineVersion', '')}")
                        message_parts.append(f"    - Endpoint: {instance.get('Endpoint', 'Unknown')}")
                        message_parts.append(f"    - Encryption: {'✅ Enabled' if instance.get('StorageEncrypted') else '❌ DISABLED'}")
                        message_parts.append(f"    - Backup: {instance.get('BackupRetentionPeriod', 0)} days retention")
                        message_parts.append(f"    - ⚠️  PUBLIC ACCESS - IMMEDIATE REVIEW REQUIRED!")
                        public_count += 1
            message_parts.append("")
        
        # Add security analysis breakdown
        if total_instances > 0:
            encryption_percentage = (summary_stats['total_encrypted_instances'] / total_instances) * 100
            multi_az_percentage = (summary_stats['total_multi_az_instances'] / total_instances) * 100
            protection_percentage = (summary_stats['total_deletion_protected_instances'] / total_instances) * 100
            
            message_parts.extend([
                "SECURITY CONFIGURATION ANALYSIS:",
                f"• Encryption coverage: {encryption_percentage:.1f}% ({summary_stats['total_encrypted_instances']}/{total_instances})",
                f"• Multi-AZ coverage: {multi_az_percentage:.1f}% ({summary_stats['total_multi_az_instances']}/{total_instances})",
                f"• Deletion protection: {protection_percentage:.1f}% ({summary_stats['total_deletion_protected_instances']}/{total_instances})",
                f"• Public accessibility: {(public_instances/total_instances)*100:.1f}% ({public_instances}/{total_instances})",
                ""
            ])
        
        # Add engine distribution
        if summary_stats['global_engine_distribution']:
            message_parts.append("DATABASE ENGINE DISTRIBUTION:")
            for engine, count in summary_stats['global_engine_distribution'].items():
                message_parts.append(f"  • {engine}: {count} instances")
            message_parts.append("")
        
        # Add cost analysis
        message_parts.extend([
            "COST ANALYSIS:",
            f"• Total monthly cost: ${summary_stats['total_estimated_monthly_cost']:,.2f}",
            f"• Average cost per instance: ${summary_stats['average_cost_per_instance']:,.2f}",
            f"• Total storage: {summary_stats['total_allocated_storage_gb']:,} GB",
            ""
        ])
        
        # Add security risks section
        message_parts.extend([
            "SECURITY RISKS:",
            "• Public instances are exposed to internet-based attacks",
            "• Unencrypted databases violate data protection compliance",
            "• Single-AZ instances lack high availability protection", 
            "• Non-protected instances risk accidental deletion",
            "• Weak backup retention increases data loss risk",
            ""
        ])
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Review and restrict public accessibility for all databases",
            "2. Enable encryption at rest for all unencrypted instances",
            "3. Enable Multi-AZ for production workloads",
            "4. Enable deletion protection for critical databases",
            "5. Configure appropriate backup retention periods",
            "6. Review and harden security group configurations",
            "",
            "RDS SECURITY COMMANDS:",
            "# Disable public access",
            "aws rds modify-db-instance --db-instance-identifier DB_NAME \\",
            "  --no-publicly-accessible --region REGION",
            "",
            "# Enable deletion protection",
            "aws rds modify-db-instance --db-instance-identifier DB_NAME \\",
            "  --deletion-protection --region REGION",
            "",
            "# Modify backup retention",
            "aws rds modify-db-instance --db-instance-identifier DB_NAME \\",
            "  --backup-retention-period 7 --region REGION",
            "",
            "# Create encrypted snapshot and restore",
            "aws rds create-db-snapshot --db-instance-identifier DB_NAME \\",
            "  --db-snapshot-identifier DB_NAME-snapshot",
            "aws rds copy-db-snapshot --source-db-snapshot-identifier DB_NAME-snapshot \\",
            "  --target-db-snapshot-identifier DB_NAME-encrypted --kms-key-id alias/aws/rds",
            "",
            "SECURITY BEST PRACTICES:",
            "• Use VPC security groups with least privilege access",
            "• Enable automated backups with appropriate retention",
            "• Implement database activity streaming to CloudWatch",
            "• Use IAM database authentication where supported",
            "• Enable Performance Insights for monitoring",
            "• Regular security patching through maintenance windows",
            "",
            "COMPLIANCE FRAMEWORKS:",
            "• PCI DSS: Requires encryption and access controls",
            "• HIPAA: Mandates encryption and audit trails",
            "• SOC 2: Requires security monitoring and controls",
            "• GDPR: Mandates data protection and encryption",
            "",
            "For detailed RDS security guidance, see AWS RDS Security Best Practices documentation.",
            "",
            "This alert was generated by the automated RDS Security Assessment function."
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
        logger.info(f"Notified about {public_instances} public instances and {security_score}% security score")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the inventory."""
    # Aggregate distributions
    global_engine_distribution = {}
    global_instance_class_distribution = {}
    global_storage_type_distribution = {}
    
    for result in results:
        stats = result['statistics']
        
        # Aggregate engine distribution
        for engine, count in stats.get('engine_distribution', {}).items():
            global_engine_distribution[engine] = global_engine_distribution.get(engine, 0) + count
        
        # Aggregate instance class distribution
        for instance_class, count in stats.get('instance_class_distribution', {}).items():
            global_instance_class_distribution[instance_class] = global_instance_class_distribution.get(instance_class, 0) + count
        
        # Aggregate storage type distribution
        for storage_type, count in stats.get('storage_type_distribution', {}).items():
            global_storage_type_distribution[storage_type] = global_storage_type_distribution.get(storage_type, 0) + count
    
    total_instances = sum(r['statistics']['total_db_instances'] for r in results)
    total_clusters = sum(r['statistics']['total_db_clusters'] for r in results)
    total_databases = total_instances + total_clusters
    total_cost = sum(r['statistics']['total_estimated_monthly_cost'] for r in results)
    total_storage = sum(r['statistics']['total_allocated_storage_gb'] for r in results)
    
    # Security metrics
    total_publicly_accessible = sum(r['statistics']['publicly_accessible_instances'] for r in results)
    total_encrypted = sum(r['statistics']['encrypted_instances'] for r in results)
    total_multi_az = sum(r['statistics']['multi_az_instances'] for r in results)
    total_deletion_protected = sum(r['statistics']['deletion_protected_instances'] for r in results)
    
    # Overall security score
    if total_instances > 0:
        overall_security_score = round(((total_encrypted + total_deletion_protected + (total_instances - total_publicly_accessible)) / (total_instances * 3)) * 100, 1)
    else:
        overall_security_score = 100
    
    return {
        'total_regions_processed': len(results),
        'total_db_instances': total_instances,
        'total_db_clusters': total_clusters,
        'total_databases': total_databases,
        'global_engine_distribution': global_engine_distribution,
        'global_instance_class_distribution': global_instance_class_distribution,
        'global_storage_type_distribution': global_storage_type_distribution,
        'total_publicly_accessible_instances': total_publicly_accessible,
        'total_encrypted_instances': total_encrypted,
        'total_multi_az_instances': total_multi_az,
        'total_deletion_protected_instances': total_deletion_protected,
        'total_allocated_storage_gb': total_storage,
        'total_estimated_monthly_cost': round(total_cost, 2),
        'average_cost_per_instance': round(total_cost / max(total_instances, 1), 2),
        'average_databases_per_region': round(total_databases / max(len(results), 1), 1),
        'overall_security_score': overall_security_score,
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for RDS instances inventory
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with inventory results
    """
    try:
        logger.info("Starting RDS instances inventory")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        
        logger.info(f"Configuration - Scan all regions: {scan_all_regions_flag}, Max workers: {max_workers}")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Inventorying RDS instances in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform inventory using parallel processing
        results = list_rds_instances_parallel(scan_all_regions_flag, max_workers)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = (summary_stats['total_publicly_accessible_instances'] > 0 or 
                          summary_stats['overall_security_score'] < 70 or
                          summary_stats['total_errors'] > 0)
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Inventory completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Databases found: {summary_stats['total_databases']}, "
                   f"Estimated monthly cost: ${summary_stats['total_estimated_monthly_cost']}")
        
        if summary_stats['total_databases'] == 0:
            logger.info("No RDS databases found in scanned regions")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(summary_stats, results, account_id)
            logger.warning(f"RDS SECURITY ALERT: {summary_stats['total_publicly_accessible_instances']} public instances, "
                         f"security score: {summary_stats['overall_security_score']}%")
        else:
            logger.info(f"RDS Security Status: {summary_stats['total_publicly_accessible_instances']} public instances, "
                       f"security score: {summary_stats['overall_security_score']}% - All Good!")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'RDS instances inventory completed successfully',
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
        logger.error(f"RDS instances inventory failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'RDS instances inventory failed',
                'executionId': context.aws_request_id
            }
        }