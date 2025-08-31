#!/usr/bin/env python3
"""
Clean up old, untagged EBS snapshots in AWS with comprehensive safety checks.

Usage:
  export AWS_PROFILE=yourprofile
  ./cleanup_snapshots.py --days 30 --dry-run

IMPORTANT: This script has multiple safety checks to prevent accidental deletion
of important snapshots. Review the output carefully before running without --dry-run.
"""

import boto3
import argparse
import datetime
import sys
import json
import os
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict, Tuple

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
            ami_id = response['Images'][0]['ImageId']
            ami_name = response['Images'][0].get('Name', 'Unknown')
            return True, f"Used by AMI {ami_id} ({ami_name})"
        
        return False, ""
    except ClientError as e:
        print(f"Warning: Could not check AMI usage for {snapshot_id}: {e}")
        return True, "Could not verify AMI usage - assuming used for safety"

def is_snapshot_used_by_launch_template(ec2_client, snapshot_id: str) -> Tuple[bool, str]:
    """Check if snapshot is referenced in launch templates."""
    try:
        paginator = ec2_client.get_paginator('describe_launch_templates')
        
        for page in paginator.paginate():
            for template in page['LaunchTemplates']:
                template_id = template['LaunchTemplateId']
                
                # Get template versions
                versions_response = ec2_client.describe_launch_template_versions(
                    LaunchTemplateId=template_id
                )
                
                for version in versions_response['LaunchTemplateVersions']:
                    launch_template_data = version.get('LaunchTemplateData', {})
                    block_mappings = launch_template_data.get('BlockDeviceMappings', [])
                    
                    for mapping in block_mappings:
                        ebs = mapping.get('Ebs', {})
                        if ebs.get('SnapshotId') == snapshot_id:
                            template_name = template.get('LaunchTemplateName', template_id)
                            return True, f"Used by Launch Template {template_name} (version {version['VersionNumber']})"
        
        return False, ""
    except ClientError as e:
        print(f"Warning: Could not check launch template usage for {snapshot_id}: {e}")
        return True, "Could not verify launch template usage - assuming used for safety"

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
        print(f"Warning: Error checking AWS Backup management: {e}")
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
        print(f"Warning: Error checking golden AMI status: {e}")
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
        print(f"Warning: Error checking DR backup status: {e}")
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
        print(f"Warning: Error checking incremental chain: {e}")
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
        print(f"Warning: Error checking application protection: {e}")
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
        print(f"Error retrieving snapshots: {e.response['Error']['Message']}")
        return []

def calculate_savings(snapshots_to_delete: List[Dict]) -> float:
    """Calculate estimated monthly savings from deleting snapshots."""
    total_size_gb = sum(snapshot['VolumeSize'] for snapshot in snapshots_to_delete)
    # AWS EBS snapshot pricing is approximately $0.05 per GB-month
    monthly_savings = total_size_gb * 0.05
    return monthly_savings

def log_audit_trail(operation: str, details: Dict, log_file: str = 'snapshot_cleanup_audit.log') -> None:
    """Log audit trail for all snapshot operations."""
    try:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        audit_entry = {
            'timestamp': timestamp,
            'operation': operation,
            'details': details
        }
        
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file) if os.path.dirname(log_file) else '.'
        os.makedirs(log_dir, exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(audit_entry) + '\n')
    except Exception as e:
        print(f"Warning: Could not write audit log: {e}")

def confirm_deletion(snapshots_to_delete: List[Dict]) -> bool:
    """Interactive confirmation for deletion."""
    if not snapshots_to_delete:
        print("No snapshots selected for deletion.")
        return False
    
    total_size = sum(s['VolumeSize'] for s in snapshots_to_delete)
    estimated_savings = calculate_savings(snapshots_to_delete)
    
    print(f"\n{'='*60}")
    print("DELETION CONFIRMATION")
    print(f"{'='*60}")
    print(f"Snapshots to delete: {len(snapshots_to_delete)}")
    print(f"Total size: {total_size} GB")
    print(f"Estimated monthly savings: ${estimated_savings:.2f}")
    print(f"{'='*60}")
    
    # Show first 10 snapshots as examples
    print("\nSnapshots to be deleted (showing first 10):")
    for i, snapshot in enumerate(snapshots_to_delete[:10]):
        print(f"  {i+1}. {snapshot['SnapshotId']} - {snapshot['VolumeSize']}GB - {snapshot['StartTime'].strftime('%Y-%m-%d')}")
    
    if len(snapshots_to_delete) > 10:
        print(f"  ... and {len(snapshots_to_delete) - 10} more")
    
    print(f"\n{'='*60}")
    print("WARNING: This action cannot be undone!")
    print("Make sure you have reviewed the safety analysis above.")
    print(f"{'='*60}")
    
    while True:
        response = input("\nType 'DELETE' to confirm deletion, or 'CANCEL' to abort: ").strip()
        if response == 'DELETE':
            return True
        elif response == 'CANCEL':
            return False
        else:
            print("Please type exactly 'DELETE' or 'CANCEL'")

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

def main():
    parser = argparse.ArgumentParser(
        description="Delete old EBS snapshots with comprehensive safety checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SAFETY FEATURES:
- Checks if snapshots are used by AMIs
- Checks if snapshots are used by Launch Templates  
- Looks for protection tags (Production, DoNotDelete, etc.)
- Identifies recent backups
- Requires explicit confirmation for deletion
- Supports dry-run mode for testing

EXAMPLES:
  # Dry run to see what would be deleted
  ./cleanup_snapshots.py --days 30 --dry-run
  
  # Use specific AWS profile
  ./cleanup_snapshots.py --profile production --days 30 --dry-run
  
  # Delete untagged snapshots older than 60 days with profile
  ./cleanup_snapshots.py --profile staging --days 60
  
  # More aggressive cleanup (only untagged, unused snapshots)
  ./cleanup_snapshots.py --profile production --days 7 --require-untagged
  
  # Specify region and profile
  ./cleanup_snapshots.py --profile production --region us-west-2 --days 30 --dry-run
  
  # Scan all regions with dry-run
  ./cleanup_snapshots.py --profile production --all-regions --days 30 --dry-run
  
  # Clean up all regions (not recommended without dry-run first)
  ./cleanup_snapshots.py --profile staging --all-regions --days 60 --require-untagged
"""
    )
    parser.add_argument('--days', type=int, default=30, 
                       help='Delete snapshots older than this many days (default: 30)')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be deleted without actually deleting')
    parser.add_argument('--require-untagged', action='store_true',
                       help='Only consider completely untagged snapshots (safer)')
    parser.add_argument('--region', help='AWS region (default: current session region)')
    parser.add_argument('--all-regions', action='store_true',
                       help='Scan all AWS regions (overrides --region)')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--force', action='store_true',
                       help='Skip interactive confirmation (not recommended)')
    parser.add_argument('--max-deletions', type=int, 
                       help='Maximum number of snapshots to delete per execution (safety limit)')
    parser.add_argument('--audit-log', type=str, default='snapshot_cleanup_audit.log',
                       help='Path to audit log file (default: snapshot_cleanup_audit.log)')
    
    args = parser.parse_args()

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

    # Validate days parameter
    if args.days < 1:
        print("Error: --days must be at least 1")
        sys.exit(1)
    
    if args.days < 7:
        print("Warning: Deleting snapshots less than 7 days old is risky!")
        if not args.force:
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                sys.exit(0)

    try:
        # Determine regions to scan
        regions_to_scan = []
        if args.all_regions:
            regions_to_scan = AWS_REGIONS
            print(f"Scanning all {len(AWS_REGIONS)} AWS regions")
        else:
            if args.region:
                regions_to_scan = [args.region]
            else:
                # Use current session region
                if session:
                    temp_client = session.client('ec2')
                else:
                    temp_client = boto3.client('ec2')
                regions_to_scan = [temp_client.meta.region_name]
            print(f"Scanning region: {regions_to_scan[0]}")

        print(f"Age threshold: {args.days} days")
        print(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE DELETION'}")
        print("=" * 50)

        # Calculate cutoff date
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=args.days)
        print(f"Will consider snapshots created before: {cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Process each region
        all_safe_to_delete = []
        all_unsafe_to_delete = []
        total_snapshots_analyzed = 0

        for region_idx, region in enumerate(regions_to_scan):
            print(f"\n{'='*60}")
            print(f"SCANNING REGION: {region} ({region_idx + 1}/{len(regions_to_scan)})")
            print(f"{'='*60}")

            try:
                # Create EC2 client for this region
                if session:
                    ec2_client = session.client('ec2', region_name=region)
                else:
                    ec2_client = boto3.client('ec2', region_name=region)

                # Get all snapshots with pagination
                print("Retrieving snapshots...")
                all_snapshots = get_snapshots_with_pagination(ec2_client)
                
                if not all_snapshots:
                    print("No snapshots found in this region.")
                    continue
                
                print(f"Found {len(all_snapshots)} total snapshots")

                # Filter by age
                old_snapshots = []
                for snapshot in all_snapshots:
                    if snapshot['StartTime'] < cutoff:
                        old_snapshots.append(snapshot)

                print(f"Found {len(old_snapshots)} snapshots older than {args.days} days")

                if args.require_untagged:
                    # Further filter to only untagged snapshots
                    old_snapshots = [s for s in old_snapshots if not s.get('Tags')]
                    print(f"Found {len(old_snapshots)} untagged snapshots older than {args.days} days")

                if not old_snapshots:
                    print("No snapshots match the criteria in this region.")
                    continue

                # Analyze safety for each snapshot
                print(f"\nAnalyzing snapshot safety...")
                safe_to_delete = []
                unsafe_to_delete = []
                
                # Calculate ETA
                start_time = datetime.datetime.now()

                for i, snapshot in enumerate(old_snapshots):
                    snapshot_id = snapshot['SnapshotId']
                    # Show progress with percentage
                    progress_pct = ((i + 1) / len(old_snapshots)) * 100
                    print(f"\rAnalyzing {i+1}/{len(old_snapshots)} ({progress_pct:.1f}%): {snapshot_id}", end=" ... ")
                    
                    is_safe, reasons = analyze_snapshot_safety(ec2_client, snapshot)
                    
                    if is_safe:
                        # Add region info to snapshot
                        snapshot['Region'] = region
                        safe_to_delete.append(snapshot)
                        print("SAFE")
                    else:
                        snapshot['Region'] = region
                        unsafe_to_delete.append((snapshot, reasons))
                        print("UNSAFE")

                # Add to global lists
                all_safe_to_delete.extend(safe_to_delete)
                all_unsafe_to_delete.extend(unsafe_to_delete)
                total_snapshots_analyzed += len(old_snapshots)

                # Report region results
                print(f"\nRegion {region} results:")
                print(f"  Snapshots analyzed: {len(old_snapshots)}")
                print(f"  Safe to delete: {len(safe_to_delete)}")
                print(f"  Unsafe to delete: {len(unsafe_to_delete)}")

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'UnauthorizedOperation':
                    print(f"No permission to access region {region}, skipping...")
                    continue
                else:
                    print(f"Error in region {region}: {e.response['Error']['Message']}")
                    continue

        # Global report results
        print(f"\n{'='*60}")
        print("GLOBAL ANALYSIS RESULTS")
        print(f"{'='*60}")
        print(f"Regions scanned: {len(regions_to_scan)}")
        print(f"Total snapshots analyzed: {total_snapshots_analyzed}")
        print(f"Safe to delete: {len(all_safe_to_delete)}")
        print(f"Unsafe to delete: {len(all_unsafe_to_delete)}")

        if all_unsafe_to_delete:
            print(f"\nSnapshots NOT safe to delete (showing first 10):")
            for snapshot, reasons in all_unsafe_to_delete[:10]:
                print(f"  {snapshot['SnapshotId']} ({snapshot['Region']}): {'; '.join(reasons)}")
            if len(all_unsafe_to_delete) > 10:
                print(f"  ... and {len(all_unsafe_to_delete) - 10} more")

        if not all_safe_to_delete:
            print("\nNo snapshots are safe to delete across all regions. This is normal and expected.")
            print("The safety checks are designed to be conservative.")
            return

        # Show snapshots that would be deleted
        total_size = sum(s['VolumeSize'] for s in all_safe_to_delete)
        estimated_savings = calculate_savings(all_safe_to_delete)
        
        print(f"\nSnapshots safe to delete ({len(all_safe_to_delete)} total, {total_size} GB):")
        for i, snapshot in enumerate(all_safe_to_delete[:10]):  # Show first 10
            age_days = (datetime.datetime.now(datetime.timezone.utc) - snapshot['StartTime']).days
            print(f"  {i+1}. {snapshot['SnapshotId']} ({snapshot['Region']}) - {snapshot['VolumeSize']}GB - {age_days} days old")
        
        if len(all_safe_to_delete) > 10:
            print(f"  ... and {len(all_safe_to_delete) - 10} more")
        
        print(f"\nEstimated monthly savings: ${estimated_savings:.2f}")

        if args.dry_run:
            print(f"\nDRY RUN: No snapshots were deleted.")
            print("Remove --dry-run flag to perform actual deletion.")
            return

        # Apply rate limiting if specified
        snapshots_to_process = all_safe_to_delete
        if args.max_deletions and len(all_safe_to_delete) > args.max_deletions:
            print(f"\nRate limiting: Processing {args.max_deletions} out of {len(all_safe_to_delete)} snapshots")
            print("Run the script again to process more snapshots.")
            snapshots_to_process = all_safe_to_delete[:args.max_deletions]
            
            # Log rate limiting decision
            log_audit_trail('rate_limit_applied', {
                'total_candidates': len(all_safe_to_delete),
                'max_deletions': args.max_deletions,
                'processing': len(snapshots_to_process)
            }, args.audit_log)

        # Confirm deletion
        if not args.force:
            if not confirm_deletion(snapshots_to_process):
                print("Deletion cancelled by user.")
                log_audit_trail('deletion_cancelled', {
                    'cancelled_by': 'user',
                    'candidates': len(snapshots_to_process)
                }, args.audit_log)
                return

        # Log operation start
        log_audit_trail('deletion_started', {
            'snapshots_to_delete': len(snapshots_to_process),
            'total_size_gb': sum(s['VolumeSize'] for s in snapshots_to_process),
            'dry_run': False,
            'user_confirmed': not args.force
        }, args.audit_log)

        # Perform deletion by region
        print(f"\nDeleting {len(snapshots_to_process)} snapshots across regions...")
        deleted_count = 0
        failed_count = 0

        # Group snapshots by region for efficient deletion
        snapshots_by_region = {}
        for snapshot in snapshots_to_process:
            region = snapshot['Region']
            if region not in snapshots_by_region:
                snapshots_by_region[region] = []
            snapshots_by_region[region].append(snapshot)

        for region, snapshots in snapshots_by_region.items():
            print(f"\nDeleting {len(snapshots)} snapshots in region {region}...")
            
            # Create region-specific client
            if session:
                ec2_client = session.client('ec2', region_name=region)
            else:
                ec2_client = boto3.client('ec2', region_name=region)

            for i, snapshot in enumerate(snapshots):
                snapshot_id = snapshot['SnapshotId']
                progress_pct = ((i + 1) / len(snapshots)) * 100
                print(f"\rDeleting {i+1}/{len(snapshots)} ({progress_pct:.1f}%): {snapshot_id}", end=" ... ")
                
                try:
                    ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                    print("SUCCESS")
                    deleted_count += 1
                    
                    # Log successful deletion
                    log_audit_trail('snapshot_deleted', {
                        'snapshot_id': snapshot_id,
                        'region': region,
                        'volume_size_gb': snapshot['VolumeSize'],
                        'age_days': (datetime.datetime.now(datetime.timezone.utc) - snapshot['StartTime']).days,
                        'description': snapshot.get('Description', '')[:100]
                    }, args.audit_log)
                    
                except ClientError as e:
                    error_msg = e.response['Error']['Message']
                    print(f"FAILED: {error_msg}")
                    failed_count += 1
                    
                    # Log failed deletion
                    log_audit_trail('snapshot_deletion_failed', {
                        'snapshot_id': snapshot_id,
                        'region': region,
                        'error': error_msg,
                        'volume_size_gb': snapshot['VolumeSize']
                    }, args.audit_log)

        print(f"\n{'='*60}")
        print("DELETION SUMMARY")
        print(f"{'='*60}")
        print(f"Regions processed: {len(snapshots_by_region)}")
        print(f"Successfully deleted: {deleted_count}")
        print(f"Failed to delete: {failed_count}")
        print(f"Estimated monthly savings: ${estimated_savings:.2f}")
        print(f"{'='*60}")
        
        # Log final summary
        log_audit_trail('deletion_completed', {
            'regions_processed': len(snapshots_by_region),
            'successfully_deleted': deleted_count,
            'failed_to_delete': failed_count,
            'estimated_monthly_savings': estimated_savings,
            'total_candidates': len(all_safe_to_delete),
            'actually_processed': len(snapshots_to_process)
        }, args.audit_log)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidParameterValue':
            print(f"Error: Invalid region specified.")
        elif error_code == 'UnauthorizedOperation':
            print("Error: Insufficient permissions. Required permissions:")
            print("- ec2:DescribeSnapshots")
            print("- ec2:DescribeImages") 
            print("- ec2:DescribeLaunchTemplates")
            print("- ec2:DescribeLaunchTemplateVersions")
            print("- ec2:DeleteSnapshot")
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

