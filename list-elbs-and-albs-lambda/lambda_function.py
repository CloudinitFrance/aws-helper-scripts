#!/usr/bin/env python3
"""
List ELBs and ALBs Inventory - Lambda Version
Serverless function for automated load balancer inventory and documentation
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
    """Get all AWS regions where ELB is available."""
    return AWS_REGIONS

def list_classic_elbs(elb_client) -> List[Dict]:
    """List Classic ELBs with pagination and error handling."""
    classic_elbs = []
    
    try:
        paginator = elb_client.get_paginator('describe_load_balancers')
        
        for page in paginator.paginate():
            for elb in page['LoadBalancerDescriptions']:
                listeners = []
                for listener_desc in elb.get('ListenerDescriptions', []):
                    listener = listener_desc.get('Listener', {})
                    listeners.append({
                        'Protocol': listener.get('Protocol', 'Unknown'),
                        'LoadBalancerPort': listener.get('LoadBalancerPort', 'Unknown'),
                        'InstancePort': listener.get('InstancePort', 'Unknown'),
                        'InstanceProtocol': listener.get('InstanceProtocol', 'Unknown')
                    })
                
                elb_info = {
                    'LoadBalancerName': elb['LoadBalancerName'],
                    'DNSName': elb.get('DNSName', 'Unknown'),
                    'Scheme': elb.get('Scheme', 'Unknown'),
                    'AvailabilityZones': elb.get('AvailabilityZones', []),
                    'VPCId': elb.get('VPCId'),
                    'SecurityGroups': elb.get('SecurityGroups', []),
                    'Listeners': listeners,
                    'InstancesCount': len(elb.get('Instances', [])),
                    'HealthCheck': {
                        'Target': elb.get('HealthCheck', {}).get('Target'),
                        'Interval': elb.get('HealthCheck', {}).get('Interval'),
                        'Timeout': elb.get('HealthCheck', {}).get('Timeout'),
                        'HealthyThreshold': elb.get('HealthCheck', {}).get('HealthyThreshold'),
                        'UnhealthyThreshold': elb.get('HealthCheck', {}).get('UnhealthyThreshold')
                    }
                }
                classic_elbs.append(elb_info)
        
        return classic_elbs
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code not in ['AccessDenied', 'UnauthorizedOperation']:
            logger.error(f"Error listing Classic ELBs: {e.response['Error']['Message']}")
        return []

def get_target_groups_for_listener(elbv2_client, listener_arn: str) -> List[str]:
    """Get target group ARNs for a listener."""
    target_group_arns = []
    
    try:
        rules_response = elbv2_client.describe_rules(ListenerArn=listener_arn)
        
        for rule in rules_response.get('Rules', []):
            for action in rule.get('Actions', []):
                if action.get('Type') == 'forward':
                    if 'TargetGroupArn' in action:
                        target_group_arns.append(action['TargetGroupArn'])
                    elif 'ForwardConfig' in action:
                        for tg in action['ForwardConfig'].get('TargetGroups', []):
                            if 'TargetGroupArn' in tg:
                                target_group_arns.append(tg['TargetGroupArn'])
    
    except ClientError as e:
        logger.warning(f"Error getting target groups for listener {listener_arn}: {e}")
    
    return target_group_arns

def get_target_group_details(elbv2_client, tg_arn: str) -> Optional[Dict]:
    """Get target group details."""
    try:
        tg_response = elbv2_client.describe_target_groups(TargetGroupArns=[tg_arn])
        if tg_response['TargetGroups']:
            tg = tg_response['TargetGroups'][0]
            
            # Get target health
            targets_count = 0
            healthy_targets = 0
            try:
                health_response = elbv2_client.describe_target_health(TargetGroupArn=tg_arn)
                targets_count = len(health_response.get('TargetHealthDescriptions', []))
                healthy_targets = len([t for t in health_response.get('TargetHealthDescriptions', []) 
                                     if t.get('TargetHealth', {}).get('State') == 'healthy'])
            except ClientError:
                pass
            
            return {
                'TargetGroupName': tg.get('TargetGroupName', 'Unknown'),
                'Protocol': tg.get('Protocol', 'Unknown'),
                'Port': tg.get('Port', 'Unknown'),
                'VpcId': tg.get('VpcId', 'Unknown'),
                'TargetType': tg.get('TargetType', 'Unknown'),
                'HealthCheckProtocol': tg.get('HealthCheckProtocol', 'Unknown'),
                'HealthCheckPath': tg.get('HealthCheckPath', 'Unknown'),
                'TargetsCount': targets_count,
                'HealthyTargets': healthy_targets
            }
    except ClientError as e:
        logger.warning(f"Error getting target group details for {tg_arn}: {e}")
    
    return None

def list_albs_nlbs(elbv2_client) -> List[Dict]:
    """List Application/Network Load Balancers with pagination and error handling."""
    alb_nlbs = []
    
    try:
        paginator = elbv2_client.get_paginator('describe_load_balancers')
        
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                lb_arn = lb['LoadBalancerArn']
                
                # Get listeners
                listeners = []
                try:
                    listener_paginator = elbv2_client.get_paginator('describe_listeners')
                    
                    for listener_page in listener_paginator.paginate(LoadBalancerArn=lb_arn):
                        for listener in listener_page['Listeners']:
                            # Get target groups for this listener
                            target_group_arns = get_target_groups_for_listener(elbv2_client, listener['ListenerArn'])
                            target_groups = []
                            
                            for tg_arn in target_group_arns:
                                tg_details = get_target_group_details(elbv2_client, tg_arn)
                                if tg_details:
                                    target_groups.append(tg_details)
                            
                            listener_info = {
                                'Protocol': listener.get('Protocol', 'Unknown'),
                                'Port': listener.get('Port', 'Unknown'),
                                'DefaultActions': len(listener.get('DefaultActions', [])),
                                'TargetGroups': target_groups
                            }
                            listeners.append(listener_info)
                
                except ClientError as e:
                    logger.warning(f"Error getting listeners for {lb_arn}: {e}")
                
                lb_info = {
                    'LoadBalancerName': lb['LoadBalancerName'],
                    'LoadBalancerArn': lb_arn,
                    'DNSName': lb.get('DNSName', 'Unknown'),
                    'Type': lb.get('Type', 'Unknown'),
                    'Scheme': lb.get('Scheme', 'Unknown'),
                    'State': lb.get('State', {}).get('Code', 'Unknown'),
                    'VpcId': lb.get('VpcId', 'Unknown'),
                    'AvailabilityZones': [az.get('ZoneName', 'Unknown') for az in lb.get('AvailabilityZones', [])],
                    'SecurityGroups': lb.get('SecurityGroups', []),
                    'IpAddressType': lb.get('IpAddressType', 'Unknown'),
                    'Listeners': listeners,
                    'ListenersCount': len(listeners)
                }
                alb_nlbs.append(lb_info)
        
        return alb_nlbs
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code not in ['AccessDenied', 'UnauthorizedOperation']:
            logger.error(f"Error listing ALBs/NLBs: {e.response['Error']['Message']}")
        return []

def inventory_load_balancers_in_region(region: str) -> Dict:
    """Inventory load balancers in a specific region."""
    try:
        # Create clients for this region
        elb_client = boto3.client('elb', region_name=region)
        elbv2_client = boto3.client('elbv2', region_name=region)
        
        logger.info(f"Inventorying load balancers in region: {region}")
        
        # Get Classic ELBs
        classic_elbs = list_classic_elbs(elb_client)
        
        # Get ALBs/NLBs
        alb_nlbs = list_albs_nlbs(elbv2_client)
        
        # Calculate statistics
        total_listeners = sum(len(elb.get('Listeners', [])) for elb in classic_elbs)
        total_listeners += sum(elb.get('ListenersCount', 0) for elb in alb_nlbs)
        
        total_target_groups = 0
        total_targets = 0
        healthy_targets = 0
        
        for lb in alb_nlbs:
            for listener in lb.get('Listeners', []):
                target_groups = listener.get('TargetGroups', [])
                total_target_groups += len(target_groups)
                for tg in target_groups:
                    total_targets += tg.get('TargetsCount', 0)
                    healthy_targets += tg.get('HealthyTargets', 0)
        
        region_results = {
            'region': region,
            'classic_elbs': classic_elbs,
            'alb_nlbs': alb_nlbs,
            'statistics': {
                'total_load_balancers': len(classic_elbs) + len(alb_nlbs),
                'classic_elbs_count': len(classic_elbs),
                'alb_nlbs_count': len(alb_nlbs),
                'total_listeners': total_listeners,
                'total_target_groups': total_target_groups,
                'total_targets': total_targets,
                'healthy_targets': healthy_targets,
                'internet_facing': len([lb for lb in classic_elbs + alb_nlbs if lb.get('Scheme') == 'internet-facing']),
                'internal': len([lb for lb in classic_elbs + alb_nlbs if lb.get('Scheme') == 'internal'])
            },
            'errors': []
        }
        
        logger.info(f"Completed inventory for {region}: {region_results['statistics']['total_load_balancers']} load balancers found")
        return region_results
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'classic_elbs': [],
            'alb_nlbs': [],
            'statistics': {
                'total_load_balancers': 0,
                'classic_elbs_count': 0,
                'alb_nlbs_count': 0,
                'total_listeners': 0,
                'total_target_groups': 0,
                'total_targets': 0,
                'healthy_targets': 0
            },
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def inventory_load_balancers_parallel(scan_all_regions_flag: bool, max_workers: int = 10) -> List[Dict]:
    """
    Inventory load balancers across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Inventorying load balancers in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Inventorying load balancers in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region inventory tasks
        future_to_region = {
            executor.submit(inventory_load_balancers_in_region, region): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed inventory for {region}: "
                           f"{result['statistics']['total_load_balancers']} load balancers")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'classic_elbs': [],
                    'alb_nlbs': [],
                    'statistics': {
                        'total_load_balancers': 0,
                        'classic_elbs_count': 0,
                        'alb_nlbs_count': 0,
                        'total_listeners': 0,
                        'total_target_groups': 0,
                        'total_targets': 0,
                        'healthy_targets': 0
                    },
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel load balancer inventory complete")
    return all_results

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the inventory."""
    return {
        'total_regions_processed': len(results),
        'total_load_balancers': sum(r['statistics']['total_load_balancers'] for r in results),
        'total_classic_elbs': sum(r['statistics']['classic_elbs_count'] for r in results),
        'total_alb_nlbs': sum(r['statistics']['alb_nlbs_count'] for r in results),
        'total_listeners': sum(r['statistics']['total_listeners'] for r in results),
        'total_target_groups': sum(r['statistics']['total_target_groups'] for r in results),
        'total_targets': sum(r['statistics']['total_targets'] for r in results),
        'total_healthy_targets': sum(r['statistics']['healthy_targets'] for r in results),
        'total_internet_facing': sum(r['statistics'].get('internet_facing', 0) for r in results),
        'total_internal': sum(r['statistics'].get('internal', 0) for r in results),
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for ELB/ALB inventory
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with inventory results
    """
    try:
        logger.info("Starting ELB/ALB inventory")
        
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
            logger.info(f"Inventorying load balancers in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform inventory using parallel processing
        results = inventory_load_balancers_parallel(scan_all_regions_flag, max_workers)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = summary_stats['total_errors'] > 0
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Inventory completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Load balancers found: {summary_stats['total_load_balancers']}, "
                   f"Target groups: {summary_stats['total_target_groups']}")
        
        if summary_stats['total_load_balancers'] == 0:
            logger.info("No load balancers found in scanned regions")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'ELB/ALB inventory completed successfully',
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
        logger.error(f"ELB/ALB inventory failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'ELB/ALB inventory failed',
                'executionId': context.aws_request_id
            }
        }