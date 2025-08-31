#!/usr/bin/env python3
"""
Stop EC2 instances that have been idle (low CPU usage) for several hours.

IMPORTANT: This script includes comprehensive safety checks to prevent stopping
critical infrastructure. Always run with --dry-run first to review candidates.
"""

import boto3
import datetime
import argparse
import sys
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict, Tuple, Optional

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

def has_protection_tags(instance: Dict) -> Tuple[bool, str]:
    """Check if instance has protection tags that should prevent stopping."""
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    
    # Protection tag keys
    protection_tags = [
        'Production', 'Prod', 'PRODUCTION', 'PROD',
        'DoNotStop', 'do-not-stop', 'DO_NOT_STOP',
        'Critical', 'CRITICAL', 'Important', 'IMPORTANT',
        'AlwaysOn', 'always-on', 'ALWAYS_ON',
        'Keep', 'KEEP', 'Preserve', 'PRESERVE'
    ]
    
    for key, value in tags.items():
        # Check protection tag keys
        if key in protection_tags:
            return True, f"Has protection tag: {key}={value}"
        
        # Check protection tag values
        if value.lower() in ['production', 'prod', 'critical', 'important', 'always-on', 'keep', 'preserve']:
            return True, f"Has protection tag: {key}={value}"
        
        # Check environment tags
        if key.lower() in ['environment', 'env', 'stage'] and value.lower() in ['production', 'prod', 'staging', 'stage']:
            return True, f"Production/Staging environment: {key}={value}"
        
        # Check auto-scaling tags
        if key.startswith('aws:autoscaling'):
            return True, f"Part of Auto Scaling Group: {key}={value}"
    
    return False, ""

def is_instance_critical_type(instance: Dict) -> Tuple[bool, str]:
    """Check if instance type suggests it's critical or expensive."""
    instance_type = instance.get('InstanceType', '')
    
    # Expensive instance families that should not be stopped without careful consideration
    expensive_families = [
        'p4', 'p3', 'p2',  # GPU instances
        'x1', 'x1e',       # High memory instances  
        'r5', 'r4',        # Memory optimized (when large)
        'c5n', 'c5',       # Compute optimized (when large)
        'm5', 'm4'         # General purpose (when large)
    ]
    
    # Size indicators for expensive instances
    large_sizes = ['xlarge', '2xlarge', '4xlarge', '8xlarge', '16xlarge', '24xlarge']
    
    for family in expensive_families:
        if instance_type.startswith(family):
            for size in large_sizes:
                if size in instance_type:
                    return True, f"Expensive instance type: {instance_type}"
    
    # Always protect GPU instances
    if any(family in instance_type for family in ['p4', 'p3', 'p2', 'g4', 'g3']):
        return True, f"GPU instance type: {instance_type}"
    
    return False, ""

def has_attached_volumes(ec2_client, instance: Dict) -> Tuple[bool, str]:
    """Check if instance has important EBS volumes attached."""
    try:
        volumes = []
        for bdm in instance.get('BlockDeviceMappings', []):
            if 'Ebs' in bdm:
                volumes.append(bdm['Ebs']['VolumeId'])
        
        if not volumes:
            return False, ""
        
        # Check volume properties
        volume_response = ec2_client.describe_volumes(VolumeIds=volumes)
        
        for volume in volume_response['Volumes']:
            # Check for large volumes (might contain important data)
            if volume['Size'] > 100:  # GB
                return True, f"Has large EBS volume: {volume['VolumeId']} ({volume['Size']}GB)"
            
            # Check for encrypted volumes (likely important)
            if volume.get('Encrypted', False):
                return True, f"Has encrypted EBS volume: {volume['VolumeId']}"
        
        return False, ""
        
    except ClientError as e:
        print(f"Warning: Could not check volumes for {instance['InstanceId']}: {e}")
        return True, "Could not verify volume status - assuming important for safety"

def check_network_activity(cloudwatch_client, instance_id: str, hours: int) -> Tuple[bool, str]:
    """Check network activity to determine if instance is truly idle."""
    try:
        end_time = datetime.datetime.utcnow()
        start_time = end_time - datetime.timedelta(hours=hours)
        
        # Check both network in and out
        for metric_name in ['NetworkIn', 'NetworkOut']:
            response = cloudwatch_client.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName=metric_name,
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            datapoints = response.get('Datapoints', [])
            if datapoints:
                total_bytes = sum(dp['Sum'] for dp in datapoints)
                # If more than 100MB of network activity, consider not idle
                if total_bytes > 100 * 1024 * 1024:  # 100MB
                    return True, f"High {metric_name}: {total_bytes / (1024*1024):.1f}MB"
        
        return False, ""
        
    except ClientError as e:
        print(f"Warning: Could not check network activity for {instance_id}: {e}")
        return True, "Could not verify network activity - assuming active for safety"

def get_instance_name(instance: Dict) -> str:
    """Get instance name from tags."""
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    return tags.get('Name', instance['InstanceId'])

def calculate_instance_cost_savings(instance: Dict) -> float:
    """Calculate estimated daily cost savings for stopping an instance."""
    instance_type = instance.get('InstanceType', '')
    
    # Rough AWS EC2 on-demand pricing estimates (USD per hour)
    # These are approximations for cost optimization purposes
    pricing_map = {
        # Nano instances
        't3.nano': 0.0052, 't2.nano': 0.0058,
        # Micro instances  
        't3.micro': 0.0104, 't2.micro': 0.0116,
        # Small instances
        't3.small': 0.0208, 't2.small': 0.023,
        # Medium instances
        't3.medium': 0.0416, 't2.medium': 0.046,
        # Large instances
        't3.large': 0.0832, 't2.large': 0.092,
        't3.xlarge': 0.1664, 't2.xlarge': 0.184,
        't3.2xlarge': 0.3328, 't2.2xlarge': 0.368,
        # Compute optimized
        'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
        'c5.4xlarge': 0.68, 'c5.9xlarge': 1.53, 'c5.12xlarge': 2.04,
        'c5.18xlarge': 3.06, 'c5.24xlarge': 4.08,
        # Memory optimized
        'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
        'r5.4xlarge': 1.008, 'r5.8xlarge': 2.016, 'r5.12xlarge': 3.024,
        'r5.16xlarge': 4.032, 'r5.24xlarge': 6.048,
        # General purpose
        'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
        'm5.4xlarge': 0.768, 'm5.8xlarge': 1.536, 'm5.12xlarge': 2.304,
        'm5.16xlarge': 3.072, 'm5.24xlarge': 4.608,
    }
    
    # Get hourly cost (default to t3.medium if not found)
    hourly_cost = pricing_map.get(instance_type, 0.0416)
    
    # Calculate daily savings (24 hours)
    daily_savings = hourly_cost * 24
    
    return round(daily_savings, 2)

def calculate_total_cost_savings(instances: List[Dict]) -> Dict[str, float]:
    """Calculate total cost savings estimates for multiple instances."""
    daily_total = 0
    
    for instance in instances:
        daily_total += calculate_instance_cost_savings(instance)
    
    return {
        'daily_savings': round(daily_total, 2),
        'monthly_savings': round(daily_total * 30, 2),
        'annual_savings': round(daily_total * 365, 2)
    }

def is_instance_recently_launched(instance: Dict, hours_threshold: int = 24) -> Tuple[bool, str]:
    """Check if instance was launched recently."""
    launch_time = instance.get('LaunchTime')
    if launch_time:
        age = datetime.datetime.now(datetime.timezone.utc) - launch_time
        if age.total_seconds() < hours_threshold * 3600:
            return True, f"Recently launched ({age.days}d {age.seconds//3600}h ago)"
    
    return False, ""

def analyze_instance_safety(ec2_client, cloudwatch_client, instance: Dict, hours: int) -> Tuple[bool, List[str]]:
    """Comprehensive safety analysis for an instance."""
    instance_id = instance['InstanceId']
    reasons = []
    
    # Check protection tags
    has_protection, protection_reason = has_protection_tags(instance)
    if has_protection:
        reasons.append(protection_reason)
    
    # Check instance type
    is_critical_type, type_reason = is_instance_critical_type(instance)
    if is_critical_type:
        reasons.append(type_reason)
    
    # Check attached volumes
    has_volumes, volume_reason = has_attached_volumes(ec2_client, instance)
    if has_volumes:
        reasons.append(volume_reason)
    
    # Check recent launch
    is_recent, recent_reason = is_instance_recently_launched(instance)
    if is_recent:
        reasons.append(recent_reason)
    
    # Check network activity
    has_network, network_reason = check_network_activity(cloudwatch_client, instance_id, hours)
    if has_network:
        reasons.append(network_reason)
    
    # Safe to stop if no reasons found
    return len(reasons) == 0, reasons

def get_cpu_utilization(cloudwatch_client, instance_id: str, hours: int) -> Tuple[Optional[float], List[float]]:
    """Get CPU utilization metrics for an instance."""
    try:
        end_time = datetime.datetime.utcnow()
        start_time = end_time - datetime.timedelta(hours=hours)
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average']
        )
        
        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return None, []
        
        values = [dp['Average'] for dp in datapoints]
        avg_cpu = sum(values) / len(values)
        
        return avg_cpu, values
        
    except ClientError as e:
        print(f"Warning: Could not get CPU metrics for {instance_id}: {e}")
        return None, []

def get_instances_with_pagination(ec2_client) -> List[Dict]:
    """Get all running instances with pagination."""
    instances = []
    
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        ):
            for reservation in page['Reservations']:
                instances.extend(reservation['Instances'])
        
        return instances
        
    except ClientError as e:
        print(f"Error retrieving instances: {e.response['Error']['Message']}")
        return []

def confirm_stop_instances(instances_to_stop: List[Dict]) -> bool:
    """Interactive confirmation for stopping instances."""
    if not instances_to_stop:
        print("No instances selected for stopping.")
        return False
    
    print(f"\n{'='*60}")
    print("INSTANCE STOP CONFIRMATION")
    print(f"{'='*60}")
    print(f"Instances to stop: {len(instances_to_stop)}")
    print(f"{'='*60}")
    
    # Show instances that will be stopped
    print("\nInstances to be stopped:")
    for i, instance in enumerate(instances_to_stop[:10]):  # Show first 10
        name = get_instance_name(instance)
        instance_type = instance.get('InstanceType', 'Unknown')
        launch_time = instance.get('LaunchTime', 'Unknown')
        if isinstance(launch_time, datetime.datetime):
            launch_time = launch_time.strftime('%Y-%m-%d %H:%M')
        
        print(f"  {i+1}. {instance['InstanceId']} ({name}) - {instance_type} - launched {launch_time}")
    
    if len(instances_to_stop) > 10:
        print(f"  ... and {len(instances_to_stop) - 10} more")
    
    print(f"\n{'='*60}")
    print("WARNING: Stopping instances will terminate running processes!")
    print("Make sure these instances can be safely stopped.")
    print(f"{'='*60}")
    
    while True:
        response = input("\nType 'STOP' to confirm stopping instances, or 'CANCEL' to abort: ").strip()
        if response == 'STOP':
            return True
        elif response == 'CANCEL':
            return False
        else:
            print("Please type exactly 'STOP' or 'CANCEL'")

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
        description="Stop idle EC2 instances with comprehensive safety checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SAFETY FEATURES:
- Checks for protection tags (Production, DoNotStop, etc.)
- Protects expensive instance types (GPU, large instances)
- Analyzes network activity, not just CPU
- Excludes recently launched instances
- Checks for important EBS volumes
- Requires explicit confirmation
- Supports dry-run mode for testing

EXAMPLES:
  # Dry run to see what would be stopped
  ./stop_idle_ec2.py --region us-east-1 --dry-run
  
  # Stop instances idle for 6+ hours with CPU < 2%
  ./stop_idle_ec2.py --region us-east-1 --hours 6 --threshold 2.0
  
  # Only consider instances with specific include tag
  ./stop_idle_ec2.py --region us-east-1 --include-tag-key Environment --include-tag-value Development
  
  # Scan all regions with dry-run
  ./stop_idle_ec2.py --all-regions --dry-run
  
  # Stop idle instances across all regions (be careful!)
  ./stop_idle_ec2.py --profile development --all-regions --hours 12 --threshold 10.0
"""
    )
    parser.add_argument('--region', help='AWS region (overridden by --all-regions)')
    parser.add_argument('--all-regions', action='store_true', help='Scan all AWS regions')
    parser.add_argument('--threshold', type=float, default=5.0, 
                       help='CPU threshold percentage (default: 5.0)')
    parser.add_argument('--hours', type=int, default=6, 
                       help='Lookback period in hours (default: 6)')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be stopped without actually stopping')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--force', action='store_true',
                       help='Skip interactive confirmation (not recommended)')
    parser.add_argument('--include-tag-key', help='Only consider instances with this tag key')
    parser.add_argument('--include-tag-value', help='Only consider instances with this tag value')
    parser.add_argument('--exclude-tag-key', help='Exclude instances with this tag key')
    parser.add_argument('--exclude-tag-value', help='Exclude instances with this tag value')
    
    args = parser.parse_args()

    # Validate region arguments
    if not args.region and not args.all_regions:
        parser.error("Either --region or --all-regions must be specified")

    # Validate inputs
    if args.threshold < 0 or args.threshold > 100:
        print("Error: Threshold must be between 0 and 100")
        sys.exit(1)
    
    if args.hours < 1 or args.hours > 168:  # Max 1 week
        print("Error: Hours must be between 1 and 168 (1 week)")
        sys.exit(1)
    
    if args.hours < 3:
        print("Warning: Looking back less than 3 hours may not provide reliable idle detection!")
        if not args.force:
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                sys.exit(0)

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
            regions_to_scan = AWS_REGIONS
            print(f"Scanning all {len(AWS_REGIONS)} AWS regions")
        else:
            regions_to_scan = [args.region]
            print(f"Scanning region: {args.region}")

        print(f"CPU threshold: {args.threshold}%")
        print(f"Lookback period: {args.hours} hours")
        print(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE OPERATION'}")
        print("=" * 50)

        # Process each region
        all_safe_to_stop = []
        all_unsafe_to_stop = []
        total_instances_checked = 0
        total_idle_candidates = 0

        for region in regions_to_scan:
            print(f"\n{'='*60}")
            print(f"SCANNING REGION: {region}")
            print(f"{'='*60}")

            try:
                # Create AWS clients for this region
                if session:
                    ec2_client = session.client('ec2', region_name=region)
                    cloudwatch_client = session.client('cloudwatch', region_name=region)
                else:
                    ec2_client = boto3.client('ec2', region_name=region)
                    cloudwatch_client = boto3.client('cloudwatch', region_name=region)

                print(f"Analyzing EC2 instances in region: {region}")

                # Get all running instances with pagination
                print("Retrieving running instances...")
                instances = get_instances_with_pagination(ec2_client)
                
                if not instances:
                    print("No running instances found in this region.")
                    continue

                print(f"Found {len(instances)} running instances")

                # Apply tag filters if specified
                if args.include_tag_key or args.exclude_tag_key:
                    filtered_instances = []
                    for instance in instances:
                        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        
                        # Include filter
                        if args.include_tag_key:
                            if args.include_tag_key not in tags:
                                continue
                            if args.include_tag_value and tags[args.include_tag_key] != args.include_tag_value:
                                continue
                        
                        # Exclude filter
                        if args.exclude_tag_key:
                            if args.exclude_tag_key in tags:
                                if not args.exclude_tag_value or tags[args.exclude_tag_key] == args.exclude_tag_value:
                                    continue
                        
                        filtered_instances.append(instance)
                    
                    instances = filtered_instances
                    print(f"After tag filtering: {len(instances)} instances")

                if not instances:
                    print("No instances match the tag criteria in this region.")
                    continue

                # Analyze each instance
                print("\nAnalyzing instances for idle status and safety...")
                idle_candidates = []
                safe_to_stop = []
                unsafe_to_stop = []

                for i, instance in enumerate(instances):
                    instance_id = instance['InstanceId']
                    instance_name = get_instance_name(instance)
                    
                    print(f"\nAnalyzing {i+1}/{len(instances)}: {instance_id} ({instance_name})")
                    
                    # Check CPU utilization first
                    avg_cpu, cpu_values = get_cpu_utilization(cloudwatch_client, instance_id, args.hours)
                    
                    if avg_cpu is None:
                        print(f"  No CPU metrics available - skipping")
                        continue
                    
                    print(f"  Average CPU: {avg_cpu:.2f}% over {args.hours} hours")
                    print(f"  CPU range: {min(cpu_values):.1f}% - {max(cpu_values):.1f}%")
                    
                    if avg_cpu >= args.threshold:
                        print(f"  CPU above threshold ({args.threshold}%) - not idle")
                        continue
                    
                    print(f"  CPU below threshold - candidate for stopping")
                    idle_candidates.append(instance)
                    
                    # Perform safety analysis
                    is_safe, reasons = analyze_instance_safety(ec2_client, cloudwatch_client, instance, args.hours)
                    
                    if is_safe:
                        # Add region info to instance
                        instance['Region'] = region
                        safe_to_stop.append(instance)
                        print(f"  Safety analysis: SAFE TO STOP")
                    else:
                        instance['Region'] = region
                        unsafe_to_stop.append((instance, reasons))
                        print(f"  Safety analysis: UNSAFE - {'; '.join(reasons)}")

                # Add to global lists
                all_safe_to_stop.extend(safe_to_stop)
                all_unsafe_to_stop.extend(unsafe_to_stop)
                total_instances_checked += len(instances)
                total_idle_candidates += len(idle_candidates)

                # Report region results
                print(f"\nRegion {region} results:")
                print(f"  Total instances checked: {len(instances)}")
                print(f"  Idle candidates (low CPU): {len(idle_candidates)}")
                print(f"  Safe to stop: {len(safe_to_stop)}")
                print(f"  Unsafe to stop: {len(unsafe_to_stop)}")

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
        print(f"Total instances checked: {total_instances_checked}")
        print(f"Idle candidates (low CPU): {total_idle_candidates}")
        print(f"Safe to stop: {len(all_safe_to_stop)}")
        print(f"Unsafe to stop: {len(all_unsafe_to_stop)}")

        if all_unsafe_to_stop:
            print(f"\nInstances NOT safe to stop (showing first 10):")
            for instance, reasons in all_unsafe_to_stop[:10]:
                name = get_instance_name(instance)
                print(f"  {instance['InstanceId']} ({instance['Region']}) ({name}): {'; '.join(reasons)}")
            if len(all_unsafe_to_stop) > 10:
                print(f"  ... and {len(all_unsafe_to_stop) - 10} more")

        if not all_safe_to_stop:
            print("\nNo instances are safe to stop across all regions.")
            print("This is normal - the safety checks are designed to be conservative.")
            return

        # Calculate cost savings
        cost_savings = calculate_total_cost_savings(all_safe_to_stop)
        
        # Show instances that would be stopped
        print(f"\nInstances safe to stop ({len(all_safe_to_stop)} total):")
        for i, instance in enumerate(all_safe_to_stop[:10]):  # Show first 10
            name = get_instance_name(instance)
            instance_type = instance.get('InstanceType', 'Unknown')
            daily_savings = calculate_instance_cost_savings(instance)
            print(f"  {i+1}. {instance['InstanceId']} ({instance['Region']}) ({name}) - {instance_type} - ${daily_savings:.2f}/day")
        
        if len(all_safe_to_stop) > 10:
            print(f"  ... and {len(all_safe_to_stop) - 10} more")
        
        # Show total cost savings
        print(f"\nESTIMATED COST SAVINGS:")
        print(f"  Daily savings: ${cost_savings['daily_savings']:.2f}")
        print(f"  Monthly savings: ${cost_savings['monthly_savings']:.2f}")
        print(f"  Annual savings: ${cost_savings['annual_savings']:.2f}")

        if args.dry_run:
            print(f"\nDRY RUN: No instances were stopped.")
            print("Remove --dry-run flag to perform actual stopping.")
            return

        # Confirm stopping
        if not args.force:
            if not confirm_stop_instances(all_safe_to_stop):
                print("Operation cancelled by user.")
                return

        # Stop instances by region
        print(f"\nStopping {len(all_safe_to_stop)} instances across regions...")
        
        # Group instances by region for efficient stopping
        instances_by_region = {}
        for instance in all_safe_to_stop:
            region = instance['Region']
            if region not in instances_by_region:
                instances_by_region[region] = []
            instances_by_region[region].append(instance)

        total_stopped = 0
        total_failed = 0

        for region, instances in instances_by_region.items():
            print(f"\nStopping {len(instances)} instances in region {region}...")
            
            # Create region-specific client
            if session:
                ec2_client = session.client('ec2', region_name=region)
            else:
                ec2_client = boto3.client('ec2', region_name=region)

            instance_ids = [instance['InstanceId'] for instance in instances]
            
            try:
                response = ec2_client.stop_instances(InstanceIds=instance_ids)
                
                print("Stop commands sent successfully!")
                print("Stopping instances:")
                for instance_info in response['StoppingInstances']:
                    instance_id = instance_info['InstanceId']
                    current_state = instance_info['CurrentState']['Name']
                    previous_state = instance_info['PreviousState']['Name']
                    print(f"  {instance_id}: {previous_state} -> {current_state}")
                    total_stopped += 1
                    
            except ClientError as e:
                print(f"Error stopping instances in {region}: {e.response['Error']['Message']}")
                total_failed += len(instances)

        print(f"\n{'='*60}")
        print("OPERATION COMPLETE")
        print(f"{'='*60}")
        print(f"Regions processed: {len(instances_by_region)}")
        print(f"Successfully stopped: {total_stopped}")
        print(f"Failed to stop: {total_failed}")
        print(f"Estimated daily cost savings: ${cost_savings['daily_savings']:.2f}")
        print(f"Estimated monthly cost savings: ${cost_savings['monthly_savings']:.2f}")
        print("Note: Instances may take a few minutes to fully stop.")

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidParameterValue':
            print(f"Error: Invalid region '{args.region}'. Please check the region name.")
        elif error_code == 'UnauthorizedOperation':
            print("Error: Insufficient permissions. Required permissions:")
            print("- ec2:DescribeInstances")
            print("- ec2:DescribeVolumes")
            print("- ec2:StopInstances")
            print("- cloudwatch:GetMetricStatistics")
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

