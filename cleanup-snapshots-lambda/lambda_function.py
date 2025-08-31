#!/usr/bin/env python3
"""
Cleanup EBS Snapshots - Lambda Version
Serverless function for automated EBS snapshot cleanup
"""

import json
import boto3
import os
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any, Tuple
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

def is_snapshot_used_by_ami(ec2_client, snapshot_id: str) -> Tuple[bool, str]:
    """Check if snapshot is used by any AMI."""
    try:
        # Check both public and private AMIs
        response = ec2_client.describe_images(
            Owners=['self'],
            Filters=[
                {'Name': 'block-device-mapping.snapshot-id', 'Values': [snapshot_id]}
            ]
        )
        
        if response['Images']:
            ami_ids = [img['ImageId'] for img in response['Images']]
            return True, f"Used by AMI(s): {', '.join(ami_ids)}"
        
        return False, ""
    except ClientError as e:
        logger.warning(f"Error checking AMI usage for {snapshot_id}: {e}")
        return False, ""

def is_snapshot_used_by_launch_template(ec2_client, snapshot_id: str) -> Tuple[bool, str]:
    """Check if snapshot is used by any launch template."""
    try:
        response = ec2_client.describe_launch_templates()
        
        for template in response['LaunchTemplates']:
            template_id = template['LaunchTemplateId']
            
            # Get latest version of launch template
            versions_response = ec2_client.describe_launch_template_versions(
                LaunchTemplateId=template_id
            )
            
            for version in versions_response['LaunchTemplateVersions']:
                launch_template_data = version.get('LaunchTemplateData', {})
                block_device_mappings = launch_template_data.get('BlockDeviceMappings', [])
                
                for mapping in block_device_mappings:
                    ebs = mapping.get('Ebs', {})
                    if ebs.get('SnapshotId') == snapshot_id:
                        return True, f"Used by Launch Template: {template['LaunchTemplateName']} (version {version['VersionNumber']})"
        
        return False, ""
    except ClientError as e:
        logger.warning(f"Error checking launch template usage for {snapshot_id}: {e}")
        return False, ""

def has_protection_tags(tags: Dict[str, str]) -> Tuple[bool, str]:
    """Check for protection tags that should prevent deletion."""
    protection_tags = [
        'Production', 'Prod', 'PRODUCTION', 'PROD',
        'DoNotDelete', 'do-not-delete', 'DO_NOT_DELETE',
        'Critical', 'CRITICAL', 'Important', 'IMPORTANT',
        'Backup', 'BACKUP', 'backup',
        'Keep', 'KEEP', 'Preserve', 'PRESERVE',
        'Protected', 'PROTECTED', 'protected'
    ]
    
    for key, value in tags.items():
        # Check protection tag keys (case-sensitive for keys)
        if key in protection_tags:
            return True, f"Has protection tag: {key}={value}"
        
        # Check protection tag values (case-insensitive)
        if value.lower() in ['production', 'prod', 'critical', 'important', 'keep', 'preserve', 'protected']:
            return True, f"Has protection tag: {key}={value}"
        
        # Check for environment tags
        if key.lower() in ['environment', 'env', 'stage'] and value.lower() in ['production', 'prod', 'staging', 'stage']:
            return True, f"Production/Staging environment tag: {key}={value}"
    
    return False, ""

def is_snapshot_recent_backup(snapshot: Dict, days_threshold: int = 7) -> Tuple[bool, str]:
    """Check if snapshot appears to be a recent backup based on description or timing."""
    description = snapshot.get('Description', '').lower()
    
    # Check for backup-related keywords in description
    backup_keywords = ['backup', 'automatic', 'scheduled', 'daily', 'weekly', 'monthly']
    if any(keyword in description for keyword in backup_keywords):
        return True, f"Appears to be a backup: {snapshot.get('Description', '')}"
    
    # Check if it's very recent (less than threshold days)
    age_days = (datetime.datetime.now(datetime.timezone.utc) - snapshot['StartTime']).days
    if age_days < days_threshold:
        return True, f"Too recent ({age_days} days old) - might be important"
    
    return False, ""

def is_managed_by_aws_backup(ec2_client, snapshot: Dict) -> Tuple[bool, str]:
    """Check if snapshot is managed by AWS Backup service."""
    try:
        # Check for AWS Backup tags
        tags = {t['Key']: t['Value'] for t in snapshot.get('Tags', [])}
        
        # AWS Backup adds specific tags
        if 'aws:backup:source-resource' in tags:
            return True, f"Managed by AWS Backup (source: {tags['aws:backup:source-resource']})"
        
        # Check description for AWS Backup patterns
        description = snapshot.get('Description', '')
        if 'AWS Backup' in description or 'aws/backup' in description:
            return True, "Created by AWS Backup service"
        
        return False, ""
    except Exception as e:
        logger.warning(f"Error checking AWS Backup management: {e}")
        return False, ""

def check_source_volume_exists(ec2_client, snapshot: Dict) -> Tuple[bool, str]:
    """Check if the source volume still exists and is in use."""
    try:
        volume_id = snapshot.get('VolumeId')
        if not volume_id:
            return False, "No source volume ID"
        
        # Check if volume exists
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        if response['Volumes']:
            volume = response['Volumes'][0]
            if volume['State'] == 'in-use':
                # Get attached instance info
                attachments = volume.get('Attachments', [])
                if attachments:
                    instance_id = attachments[0].get('InstanceId', 'Unknown')
                    return True, f"Source volume {volume_id} is attached to instance {instance_id}"
            return False, f"Source volume {volume_id} exists but not in use"
        return False, ""
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidVolume.NotFound':
            return False, "Source volume no longer exists"
        return False, ""

def is_golden_ami_snapshot(ec2_client, snapshot: Dict) -> Tuple[bool, str]:
    """Check if snapshot is from a golden/master AMI."""
    try:
        tags = {t['Key']: t['Value'] for t in snapshot.get('Tags', [])}
        description = snapshot.get('Description', '').lower()
        
        # Check for golden AMI indicators in tags
        golden_indicators = ['golden', 'master', 'base', 'template', 'standard']
        for key, value in tags.items():
            if any(indicator in key.lower() or indicator in value.lower() for indicator in golden_indicators):
                return True, f"Golden/Master AMI snapshot: {key}={value}"
        
        # Check description
        if any(indicator in description for indicator in golden_indicators):
            return True, f"Golden/Master AMI snapshot based on description"
        
        return False, ""
    except Exception as e:
        logger.warning(f"Error checking golden AMI status: {e}")
        return False, ""

def is_active_dr_backup(snapshot: Dict) -> Tuple[bool, str]:
    """Check if snapshot is part of active DR strategy."""
    try:
        tags = {t['Key']: t['Value'] for t in snapshot.get('Tags', [])}
        description = snapshot.get('Description', '').lower()
        
        # DR-related keywords
        dr_keywords = ['disaster', 'recovery', 'dr-', 'failover', 'replication', 'standby']
        
        # Check tags
        for key, value in tags.items():
            if any(keyword in key.lower() or keyword in value.lower() for keyword in dr_keywords):
                return True, f"DR backup snapshot: {key}={value}"
        
        # Check description
        if any(keyword in description for keyword in dr_keywords):
            return True, "DR backup based on description"
        
        return False, ""
    except Exception as e:
        logger.warning(f"Error checking DR backup status: {e}")
        return False, ""

def is_part_of_incremental_chain(ec2_client, snapshot: Dict) -> Tuple[bool, str]:
    """Check if snapshot is part of an incremental backup chain."""
    try:
        # Get the parent snapshot ID if this is an incremental snapshot
        parent_snapshot_id = snapshot.get('ParentSnapshotId')
        if parent_snapshot_id:
            return True, f"Part of incremental chain (parent: {parent_snapshot_id})"
        
        # Check if other snapshots reference this one as parent
        snapshot_id = snapshot['SnapshotId']
        response = ec2_client.describe_snapshots(
            OwnerIds=['self'],
            Filters=[{'Name': 'parent-snapshot', 'Values': [snapshot_id]}]
        )
        
        if response['Snapshots']:
            child_count = len(response['Snapshots'])
            return True, f"Has {child_count} incremental snapshots depending on it"
        
        return False, ""
    except Exception as e:
        logger.warning(f"Error checking incremental chain: {e}")
        return False, ""

def has_application_protection(snapshot: Dict) -> Tuple[bool, str]:
    """Check for application-specific protection patterns."""
    try:
        tags = {t['Key']: t['Value'] for t in snapshot.get('Tags', [])}
        description = snapshot.get('Description', '').lower()
        
        # Application-specific patterns
        app_patterns = [
            'database', 'db-', 'mysql', 'postgres', 'oracle', 'mongodb',
            'elasticsearch', 'redis', 'kafka', 'cassandra',
            'application', 'app-', 'service-', 'microservice',
            'jenkins', 'gitlab', 'artifactory', 'nexus'
        ]
        
        # Check tags
        for key, value in tags.items():
            if any(pattern in key.lower() or pattern in value.lower() for pattern in app_patterns):
                return True, f"Application-specific snapshot: {key}={value}"
        
        # Check description
        if any(pattern in description for pattern in app_patterns):
            return True, "Application-specific snapshot based on description"
        
        return False, ""
    except Exception as e:
        logger.warning(f"Error checking application protection: {e}")
        return False, ""

def analyze_snapshot_safety(ec2_client, snapshot: Dict) -> Tuple[bool, List[str]]:
    """Comprehensive safety analysis for a snapshot."""
    snapshot_id = snapshot['SnapshotId']
    tags = {t['Key']: t['Value'] for t in snapshot.get('Tags', [])}
    reasons = []
    
    # Check AMI usage
    is_ami_used, ami_reason = is_snapshot_used_by_ami(ec2_client, snapshot_id)
    if is_ami_used:
        reasons.append(ami_reason)
    
    # Check launch template usage
    is_lt_used, lt_reason = is_snapshot_used_by_launch_template(ec2_client, snapshot_id)
    if is_lt_used:
        reasons.append(lt_reason)
    
    # Check protection tags
    has_protection, protection_reason = has_protection_tags(tags)
    if has_protection:
        reasons.append(protection_reason)
    
    # Check if it's a recent backup
    is_backup, backup_reason = is_snapshot_recent_backup(snapshot)
    if is_backup:
        reasons.append(backup_reason)
    
    # Enhanced safety checks
    # Check AWS Backup management
    is_aws_backup, aws_backup_reason = is_managed_by_aws_backup(ec2_client, snapshot)
    if is_aws_backup:
        reasons.append(aws_backup_reason)
    
    # Check if source volume exists and is in use
    volume_exists, volume_reason = check_source_volume_exists(ec2_client, snapshot)
    if volume_exists:
        reasons.append(volume_reason)
    
    # Check for golden AMI
    is_golden, golden_reason = is_golden_ami_snapshot(ec2_client, snapshot)
    if is_golden:
        reasons.append(golden_reason)
    
    # Check DR backup status
    is_dr, dr_reason = is_active_dr_backup(snapshot)
    if is_dr:
        reasons.append(dr_reason)
    
    # Check incremental chain
    is_incremental, incremental_reason = is_part_of_incremental_chain(ec2_client, snapshot)
    if is_incremental:
        reasons.append(incremental_reason)
    
    # Check application protection
    has_app_protection, app_reason = has_application_protection(snapshot)
    if has_app_protection:
        reasons.append(app_reason)
    
    # Safe to delete if no reasons found
    return len(reasons) == 0, reasons

def get_snapshots_with_pagination(ec2_client) -> List[Dict]:
    """Get all snapshots with pagination."""
    snapshots = []
    
    try:
        paginator = ec2_client.get_paginator('describe_snapshots')
        
        for page in paginator.paginate(OwnerIds=['self']):
            snapshots.extend(page['Snapshots'])
        
        return snapshots
    except ClientError as e:
        logger.error(f"Error retrieving snapshots: {e.response['Error']['Message']}")
        return []

def calculate_savings(snapshots_to_delete: List[Dict]) -> float:
    """Calculate estimated monthly savings from deleting snapshots."""
    total_size_gb = sum(snapshot['VolumeSize'] for snapshot in snapshots_to_delete)
    # AWS EBS snapshot pricing is approximately $0.05 per GB-month
    monthly_savings = total_size_gb * 0.05
    return monthly_savings

def log_audit_trail(operation: str, details: Dict) -> None:
    """Log audit trail for all snapshot operations."""
    try:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        audit_entry = {
            'timestamp': timestamp,
            'operation': operation,
            'details': details
        }
        
        # Log to CloudWatch Logs
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")
    except Exception as e:
        logger.warning(f"Could not write audit log: {e}")

def cleanup_snapshots_in_region(region: str, days_old: int, dry_run: bool, require_untagged: bool, max_deletions: int = None) -> Dict:
    """Clean up snapshots in a specific region."""
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        
        logger.info(f"Processing region: {region}")
        
        # Get all snapshots
        all_snapshots = get_snapshots_with_pagination(ec2_client)
        
        if not all_snapshots:
            logger.info(f"No snapshots found in {region}")
            return {
                'region': region,
                'snapshots_analyzed': 0,
                'snapshots_deleted': 0,
                'snapshots_protected': 0,
                'total_size_deleted_gb': 0,
                'estimated_savings': 0.0,
                'errors': []
            }
        
        logger.info(f"Found {len(all_snapshots)} snapshots in {region}")
        
        # Filter by age
        cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_old)
        old_snapshots = [s for s in all_snapshots if s['StartTime'] < cutoff_date]
        
        logger.info(f"Found {len(old_snapshots)} snapshots older than {days_old} days in {region}")
        
        snapshots_to_delete = []
        protected_snapshots = []
        errors = []
        
        for snapshot in old_snapshots:
            # Skip if require_untagged is True and snapshot has tags
            if require_untagged and snapshot.get('Tags'):
                protected_snapshots.append({
                    'snapshot_id': snapshot['SnapshotId'],
                    'reason': 'Has tags (require_untagged=True)'
                })
                continue
            
            # Analyze safety
            is_safe, safety_reasons = analyze_snapshot_safety(ec2_client, snapshot)
            
            if is_safe:
                snapshots_to_delete.append(snapshot)
            else:
                protected_snapshots.append({
                    'snapshot_id': snapshot['SnapshotId'],
                    'reasons': safety_reasons
                })
        
        # Apply rate limiting if specified
        snapshots_to_process = snapshots_to_delete
        if max_deletions and len(snapshots_to_delete) > max_deletions:
            logger.info(f"Rate limiting: Processing {max_deletions} out of {len(snapshots_to_delete)} snapshots in {region}")
            snapshots_to_process = snapshots_to_delete[:max_deletions]
            
            # Log rate limiting decision
            log_audit_trail('rate_limit_applied', {
                'region': region,
                'total_candidates': len(snapshots_to_delete),
                'max_deletions': max_deletions,
                'processing': len(snapshots_to_process)
            })

        # Delete snapshots (or simulate if dry_run)
        deleted_count = 0
        total_size_deleted = 0
        
        for snapshot in snapshots_to_process:
            try:
                if not dry_run:
                    ec2_client.delete_snapshot(SnapshotId=snapshot['SnapshotId'])
                    logger.info(f"Deleted snapshot {snapshot['SnapshotId']} in {region}")
                    
                    # Log successful deletion
                    log_audit_trail('snapshot_deleted', {
                        'snapshot_id': snapshot['SnapshotId'],
                        'region': region,
                        'volume_size_gb': snapshot['VolumeSize'],
                        'age_days': (datetime.datetime.now(datetime.timezone.utc) - snapshot['StartTime']).days,
                        'description': snapshot.get('Description', '')[:100]
                    })
                else:
                    logger.info(f"DRY RUN: Would delete snapshot {snapshot['SnapshotId']} in {region}")
                
                deleted_count += 1
                total_size_deleted += snapshot['VolumeSize']
                
            except ClientError as e:
                error_msg = f"Error deleting {snapshot['SnapshotId']}: {e.response['Error']['Message']}"
                logger.error(error_msg)
                errors.append(error_msg)
                
                # Log failed deletion
                log_audit_trail('snapshot_deletion_failed', {
                    'snapshot_id': snapshot['SnapshotId'],
                    'region': region,
                    'error': e.response['Error']['Message'],
                    'volume_size_gb': snapshot['VolumeSize']
                })
        
        estimated_savings = calculate_savings(snapshots_to_process)
        
        # Prepare deletion confirmation data
        deletion_details = []
        for snapshot in snapshots_to_process[:10]:  # First 10 for response size
            deletion_details.append({
                'snapshot_id': snapshot['SnapshotId'],
                'volume_size_gb': snapshot['VolumeSize'],
                'creation_date': snapshot['StartTime'].isoformat() if snapshot.get('StartTime') else 'Unknown',
                'description': snapshot.get('Description', '')[:100],  # Limit description length
                'age_days': (datetime.datetime.now(datetime.timezone.utc) - snapshot['StartTime']).days if snapshot.get('StartTime') else 0
            })
        
        # Enhanced dry-run reporting (safety analysis summary)
        safety_analysis = {
            'total_snapshots_analyzed': len(old_snapshots),
            'safe_to_delete': len(snapshots_to_delete),
            'protected_by_safety_checks': len(protected_snapshots),
            'safety_check_breakdown': {},
            'would_be_deleted_count': len(snapshots_to_process),
            'would_be_deleted_size_gb': sum(s['VolumeSize'] for s in snapshots_to_process),
            'estimated_monthly_savings': estimated_savings
        }
        
        # Analyze protection reasons
        protection_reasons = {}
        for snapshot, reasons in protected_snapshots:
            for reason in reasons:
                protection_reasons[reason] = protection_reasons.get(reason, 0) + 1
        safety_analysis['safety_check_breakdown'] = protection_reasons
        
        return {
            'region': region,
            'snapshots_analyzed': len(old_snapshots),
            'snapshots_deleted': deleted_count,
            'snapshots_protected': len(protected_snapshots),
            'total_size_deleted_gb': total_size_deleted,
            'estimated_savings': estimated_savings,
            'errors': errors,
            'protected_details': protected_snapshots[:10],  # Limit details for response size
            'deletion_summary': {
                'total_to_delete': len(snapshots_to_process),
                'total_size_gb': sum(s['VolumeSize'] for s in snapshots_to_process),
                'estimated_monthly_savings': estimated_savings,
                'deletion_details': deletion_details,
                'more_snapshots': len(snapshots_to_process) > 10,
                'rate_limited': max_deletions and len(snapshots_to_delete) > max_deletions,
                'total_candidates': len(snapshots_to_delete) if max_deletions else None
            },
            'safety_analysis': safety_analysis
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'snapshots_analyzed': 0,
            'snapshots_deleted': 0,
            'snapshots_protected': 0,
            'total_size_deleted_gb': 0,
            'estimated_savings': 0.0,
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def cleanup_snapshots_parallel(scan_all_regions_flag: bool, days_old: int, dry_run: bool, 
                              require_untagged: bool, max_workers: int = 10, max_deletions: int = None) -> List[Dict]:
    """
    Clean up snapshots across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Processing all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Processing current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region cleanup tasks
        future_to_region = {
            executor.submit(cleanup_snapshots_in_region, region, days_old, dry_run, require_untagged, max_deletions): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed processing {region}: {result['snapshots_deleted']} deleted, "
                           f"{result['snapshots_protected']} protected")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'snapshots_analyzed': 0,
                    'snapshots_deleted': 0,
                    'snapshots_protected': 0,
                    'total_size_deleted_gb': 0,
                    'estimated_savings': 0.0,
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel cleanup complete")
    return all_results

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the cleanup operation."""
    return {
        'total_regions_processed': len(results),
        'total_snapshots_analyzed': sum(r['snapshots_analyzed'] for r in results),
        'total_snapshots_deleted': sum(r['snapshots_deleted'] for r in results),
        'total_snapshots_protected': sum(r['snapshots_protected'] for r in results),
        'total_size_deleted_gb': sum(r['total_size_deleted_gb'] for r in results),
        'total_estimated_savings': sum(r['estimated_savings'] for r in results),
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for EBS snapshot cleanup
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with cleanup results
    """
    try:
        logger.info("Starting EBS snapshot cleanup")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        days_old = params.get('days_old', int(os.environ.get('DAYS_OLD', '30')))
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        dry_run = params.get('dry_run',
                           os.environ.get('DRY_RUN', 'true').lower() == 'true')
        require_untagged = params.get('require_untagged',
                                    os.environ.get('REQUIRE_UNTAGGED', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        max_deletions = params.get('max_deletions', int(os.environ.get('MAX_DELETIONS', '0')) or None)
        
        logger.info(f"Configuration - Days old: {days_old}, Scan all regions: {scan_all_regions_flag}, "
                   f"Dry run: {dry_run}, Require untagged: {require_untagged}, Max workers: {max_workers}, "
                   f"Max deletions: {max_deletions or 'unlimited'}")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Cleaning up snapshots in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform cleanup using parallel processing
        results = cleanup_snapshots_parallel(scan_all_regions_flag, days_old, dry_run, 
                                           require_untagged, max_workers, max_deletions)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = summary_stats['total_errors'] > 0
        status_code = 201 if alerts_triggered else 200
        
        # Determine operation mode message
        operation_mode = "DRY RUN" if dry_run else "ACTUAL DELETION"
        
        # Log summary
        logger.info(f"Cleanup completed ({operation_mode}). "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Snapshots deleted: {summary_stats['total_snapshots_deleted']}, "
                   f"Estimated savings: ${summary_stats['total_estimated_savings']:.2f}/month")
        
        if alerts_triggered:
            logger.warning(f"CLEANUP ALERT: {summary_stats['total_errors']} errors occurred during cleanup!")
        
        if summary_stats['total_snapshots_deleted'] > 0:
            logger.info(f"SUCCESS: {operation_mode} - Cleaned up {summary_stats['total_snapshots_deleted']} snapshots "
                       f"totaling {summary_stats['total_size_deleted_gb']} GB")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'EBS snapshot cleanup completed successfully ({operation_mode})',
                'results': {
                    'region_results': results,
                    'summary': summary_stats,
                    'cleanup_parameters': {
                        'days_old': days_old,
                        'scan_all_regions': scan_all_regions_flag,
                        'dry_run': dry_run,
                        'require_untagged': require_untagged,
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
        logger.error(f"EBS snapshot cleanup failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'EBS snapshot cleanup failed',
                'executionId': context.aws_request_id
            }
        }