#!/usr/bin/env python3
"""
Stop Idle EC2 Instances - Lambda Version
Serverless function for automated cost optimization through idle instance management
"""

import json
import boto3
import os
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any, Tuple
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
    """Get all AWS regions where EC2 is available."""
    return AWS_REGIONS

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

def get_cpu_utilization(cloudwatch_client, instance_id: str, hours: int) -> float:
    """Get average CPU utilization for an instance over the specified hours."""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1 hour periods
            Statistics=['Average']
        )
        
        if response['Datapoints']:
            # Calculate average CPU utilization
            total_cpu = sum(point['Average'] for point in response['Datapoints'])
            avg_cpu = total_cpu / len(response['Datapoints'])
            return round(avg_cpu, 2)
        else:
            # No data available (instance might be new or not reporting metrics)
            return -1.0
    except ClientError as e:
        logger.warning(f"Error getting CPU metrics for {instance_id}: {e}")
        return -1.0

def check_network_activity(cloudwatch_client, instance_id: str, hours: int) -> Tuple[bool, str]:
    """Check network activity to determine if instance is truly idle."""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
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
        logger.warning(f"Could not check network activity for {instance_id}: {e}")
        return True, "Could not verify network activity - assuming active for safety"

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
        logger.warning(f"Could not check volumes for {instance['InstanceId']}: {e}")
        return True, "Could not verify volume status - assuming important for safety"

def analyze_instance_for_stopping(instance: Dict, ec2_client, cloudwatch_client, cpu_threshold: float, monitoring_hours: int) -> Dict:
    """Analyze an instance to determine if it should be stopped."""
    instance_id = instance['InstanceId']
    instance_analysis = {
        'InstanceId': instance_id,
        'InstanceType': instance.get('InstanceType', 'Unknown'),
        'State': instance['State']['Name'],
        'LaunchTime': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else 'Unknown',
        'PrivateIpAddress': instance.get('PrivateIpAddress', 'Unknown'),
        'PublicIpAddress': instance.get('PublicIpAddress', 'None'),
        'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
        'AvgCpuUtilization': -1.0,
        'MonitoringHours': monitoring_hours,
        'CpuThreshold': cpu_threshold,
        'ShouldStop': False,
        'StopReasons': [],
        'ProtectionReasons': [],
        'RiskLevel': 'Low'
    }
    
    # Only analyze running instances
    if instance['State']['Name'] != 'running':
        instance_analysis['ProtectionReasons'].append(f"Instance is {instance['State']['Name']}")
        return instance_analysis
    
    # Check protection tags
    has_protection, protection_reason = has_protection_tags(instance)
    if has_protection:
        instance_analysis['ProtectionReasons'].append(protection_reason)
        instance_analysis['RiskLevel'] = 'High'
        return instance_analysis
    
    # Check if it's a critical instance type
    is_critical, critical_reason = is_instance_critical_type(instance)
    if is_critical:
        instance_analysis['ProtectionReasons'].append(critical_reason)
        instance_analysis['RiskLevel'] = 'High'
        return instance_analysis
    
    # Check attached volumes
    has_volumes, volume_reason = has_attached_volumes(ec2_client, instance)
    if has_volumes:
        instance_analysis['ProtectionReasons'].append(volume_reason)
        instance_analysis['RiskLevel'] = 'High'
        return instance_analysis
    
    # Get CPU utilization
    cpu_util = get_cpu_utilization(cloudwatch_client, instance_id, monitoring_hours)
    instance_analysis['AvgCpuUtilization'] = cpu_util
    
    if cpu_util == -1.0:
        instance_analysis['ProtectionReasons'].append("No CPU metrics available")
        instance_analysis['RiskLevel'] = 'Medium'
        return instance_analysis
    
    # Determine if instance should be stopped
    if cpu_util <= cpu_threshold:
        instance_analysis['ShouldStop'] = True
        instance_analysis['StopReasons'].append(f"Low CPU utilization: {cpu_util}% (threshold: {cpu_threshold}%)")
        
        # Additional safety checks for low CPU instances
        if cpu_util < 1.0:
            instance_analysis['StopReasons'].append("Extremely low CPU usage - likely idle")
        
        # Check launch time - don't stop very new instances
        if instance.get('LaunchTime'):
            launch_time = instance['LaunchTime']
            hours_running = (datetime.now(timezone.utc) - launch_time).total_seconds() / 3600
            if hours_running < monitoring_hours:
                instance_analysis['ShouldStop'] = False
                instance_analysis['ProtectionReasons'].append(f"Instance too new: {hours_running:.1f} hours old")
                instance_analysis['RiskLevel'] = 'Medium'
                return instance_analysis
        
        # Check network activity - if high network activity, don't stop
        has_network, network_reason = check_network_activity(cloudwatch_client, instance_id, monitoring_hours)
        if has_network:
            instance_analysis['ShouldStop'] = False
            instance_analysis['ProtectionReasons'].append(network_reason)
            instance_analysis['RiskLevel'] = 'Medium'
    
    return instance_analysis

def stop_idle_instances_in_region(region: str, cpu_threshold: float, monitoring_hours: int, dry_run: bool) -> Dict:
    """Stop idle EC2 instances in a specific region."""
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        cloudwatch_client = boto3.client('cloudwatch', region_name=region)
        
        logger.info(f"Analyzing EC2 instances in region: {region}")
        
        # Get all running instances
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        instances = []
        for reservation in response['Reservations']:
            instances.extend(reservation['Instances'])
        
        if not instances:
            logger.info(f"No running instances found in {region}")
            return {
                'region': region,
                'instances_analyzed': [],
                'statistics': {
                    'total_instances': 0,
                    'instances_stopped': 0,
                    'instances_protected': 0,
                    'average_cpu_utilization': 0,
                    'cost_savings_estimate': 0
                },
                'errors': []
            }
        
        logger.info(f"Found {len(instances)} running instances in {region}")
        
        # Analyze each instance
        analyzed_instances = []
        instances_to_stop = []
        protected_instances = 0
        total_cpu = 0
        cpu_count = 0
        
        for instance in instances:
            analysis = analyze_instance_for_stopping(instance, ec2_client, cloudwatch_client, cpu_threshold, monitoring_hours)
            analyzed_instances.append(analysis)
            
            if analysis['ShouldStop'] and not analysis['ProtectionReasons']:
                instances_to_stop.append(analysis)
            elif analysis['ProtectionReasons']:
                protected_instances += 1
            
            if analysis['AvgCpuUtilization'] >= 0:
                total_cpu += analysis['AvgCpuUtilization']
                cpu_count += 1
        
        # Stop instances if not in dry run mode
        actually_stopped = 0
        stop_errors = []
        
        if instances_to_stop and not dry_run:
            logger.info(f"Stopping {len(instances_to_stop)} idle instances in {region}")
            instance_ids = [inst['InstanceId'] for inst in instances_to_stop]
            
            try:
                stop_response = ec2_client.stop_instances(InstanceIds=instance_ids)
                actually_stopped = len(stop_response['StoppingInstances'])
                logger.info(f"Successfully initiated stop for {actually_stopped} instances in {region}")
            except ClientError as e:
                error_msg = f"Error stopping instances in {region}: {e.response['Error']['Message']}"
                logger.error(error_msg)
                stop_errors.append(error_msg)
        elif instances_to_stop and dry_run:
            logger.info(f"DRY RUN: Would stop {len(instances_to_stop)} idle instances in {region}")
        
        # Calculate statistics
        avg_cpu = round(total_cpu / max(cpu_count, 1), 2)
        # Rough estimate: assume t3.medium cost savings ($0.05/hour * 24 hours * instances)
        cost_savings_estimate = len(instances_to_stop) * 0.05 * 24
        
        region_results = {
            'region': region,
            'instances_analyzed': analyzed_instances[:50],  # Limit for response size
            'statistics': {
                'total_instances': len(instances),
                'instances_to_stop': len(instances_to_stop),
                'instances_stopped': actually_stopped,
                'instances_protected': protected_instances,
                'average_cpu_utilization': avg_cpu,
                'daily_cost_savings_estimate': round(cost_savings_estimate, 2)
            },
            'errors': stop_errors
        }
        
        logger.info(f"Completed analysis for {region}: {len(instances)} instances, {len(instances_to_stop)} candidates for stopping")
        return region_results
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'instances_analyzed': [],
            'statistics': {
                'total_instances': 0,
                'instances_to_stop': 0,
                'instances_stopped': 0,
                'instances_protected': 0,
                'average_cpu_utilization': 0,
                'daily_cost_savings_estimate': 0
            },
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def stop_idle_instances_parallel(scan_all_regions_flag: bool, cpu_threshold: float, monitoring_hours: int, dry_run: bool, max_workers: int = 10) -> List[Dict]:
    """
    Stop idle EC2 instances across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Analyzing idle EC2 instances in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Analyzing idle EC2 instances in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region analysis tasks
        future_to_region = {
            executor.submit(stop_idle_instances_in_region, region, cpu_threshold, monitoring_hours, dry_run): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed analysis for {region}: "
                           f"{result['statistics']['total_instances']} instances, "
                           f"{result['statistics']['instances_to_stop']} candidates")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'instances_analyzed': [],
                    'statistics': {
                        'total_instances': 0,
                        'instances_to_stop': 0,
                        'instances_stopped': 0,
                        'instances_protected': 0,
                        'average_cpu_utilization': 0,
                        'daily_cost_savings_estimate': 0
                    },
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel idle EC2 analysis complete")
    return all_results

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the idle instance analysis."""
    total_instances = sum(r['statistics'].get('total_instances', 0) for r in results)
    total_to_stop = sum(r['statistics'].get('instances_to_stop', 0) for r in results)
    total_stopped = sum(r['statistics'].get('instances_stopped', 0) for r in results)
    total_protected = sum(r['statistics'].get('instances_protected', 0) for r in results)
    total_cost_savings = sum(r['statistics'].get('daily_cost_savings_estimate', 0) for r in results)
    
    # Calculate weighted average CPU utilization
    total_cpu = 0
    cpu_instances = 0
    for result in results:
        total_inst = result['statistics'].get('total_instances', 0)
        if total_inst > 0:
            total_cpu += result['statistics'].get('average_cpu_utilization', 0) * total_inst
            cpu_instances += total_inst
    
    avg_cpu = round(total_cpu / max(cpu_instances, 1), 2)
    
    return {
        'total_regions_processed': len(results),
        'total_instances_analyzed': total_instances,
        'total_instances_to_stop': total_to_stop,
        'total_instances_stopped': total_stopped,
        'total_instances_protected': total_protected,
        'overall_average_cpu_utilization': avg_cpu,
        'daily_cost_savings_estimate': round(total_cost_savings, 2),
        'monthly_cost_savings_estimate': round(total_cost_savings * 30, 2),
        'annual_cost_savings_estimate': round(total_cost_savings * 365, 2),
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for stopping idle EC2 instances
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with execution results
    """
    try:
        logger.info("Starting idle EC2 instances analysis and stopping")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        dry_run = params.get('dry_run', os.environ.get('DRY_RUN', 'true').lower() == 'true')
        cpu_threshold = params.get('cpu_threshold', float(os.environ.get('CPU_THRESHOLD', '5')))
        monitoring_hours = params.get('monitoring_hours', int(os.environ.get('MONITORING_HOURS', '24')))
        
        logger.info(f"Configuration - Scan all regions: {scan_all_regions_flag}, "
                   f"Max workers: {max_workers}, Dry run: {dry_run}, "
                   f"CPU threshold: {cpu_threshold}%, Monitoring hours: {monitoring_hours}")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Analyzing EC2 instances in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform analysis using parallel processing
        results = stop_idle_instances_parallel(scan_all_regions_flag, cpu_threshold, monitoring_hours, dry_run, max_workers)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = (summary_stats['total_instances_to_stop'] > 0 or 
                          summary_stats['total_errors'] > 0)
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        mode = "DRY RUN" if dry_run else "EXECUTION"
        logger.info(f"{mode} completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Instances analyzed: {summary_stats['total_instances_analyzed']}, "
                   f"Candidates for stopping: {summary_stats['total_instances_to_stop']}, "
                   f"Actually stopped: {summary_stats['total_instances_stopped']}")
        
        if summary_stats['total_instances_analyzed'] == 0:
            logger.info("No running EC2 instances found in scanned regions")
        
        if alerts_triggered and summary_stats['total_instances_to_stop'] > 0:
            logger.warning(f"COST OPTIMIZATION OPPORTUNITY: {summary_stats['total_instances_to_stop']} idle instances found, "
                         f"potential daily savings: ${summary_stats['daily_cost_savings_estimate']}")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'Idle EC2 instances analysis completed successfully',
                'results': {
                    'region_results': results,
                    'summary': summary_stats,
                    'execution_parameters': {
                        'scan_all_regions': scan_all_regions_flag,
                        'max_workers': max_workers,
                        'dry_run': dry_run,
                        'cpu_threshold': cpu_threshold,
                        'monitoring_hours': monitoring_hours,
                        'account_id': account_id,
                        'caller_arn': caller_arn
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"Idle EC2 instances analysis failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Idle EC2 instances analysis failed',
                'executionId': context.aws_request_id
            }
        }