#!/usr/bin/env python3
"""
List all ELBs (classic) and ALBs (application) with listeners and
target groups.
"""

import boto3
import argparse
import sys
from botocore.exceptions import (
    ClientError, NoCredentialsError, PartialCredentialsError,
    ProfileNotFound
)


def list_classic_elbs(elb_client):
    """List Classic ELBs with pagination and error handling."""
    print("=== Classic ELBs ===")
    
    try:
        # Use paginator for large number of ELBs
        paginator = elb_client.get_paginator('describe_load_balancers')
        elb_count = 0
        
        for page in paginator.paginate():
            for elb in page['LoadBalancerDescriptions']:
                elb_count += 1
                name = elb['LoadBalancerName']
                print(f"\nLoad Balancer Name: {name}")
                print(f"Scheme: {elb['Scheme']}")
                print(f"DNS Name: {elb['DNSName']}")
                print(f"Availability Zones: {', '.join(elb['AvailabilityZones'])}")
                
                print("Listeners:")
                for listener in elb.get('ListenerDescriptions', []):
                    listener_info = listener.get('Listener', {})
                    proto = listener_info.get('Protocol', 'Unknown')
                    port = listener_info.get('LoadBalancerPort', 'Unknown')
                    instance_port = listener_info.get('InstancePort', 'Unknown')
                    print(f" - {proto} {port} -> instance {instance_port}")
        
        if elb_count == 0:
            print("No Classic ELBs found in this region.")
        else:
            print(f"\nTotal Classic ELBs: {elb_count}")
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: No permission to describe Classic ELBs. Required permission: elasticloadbalancing:DescribeLoadBalancers")
        else:
            print(f"AWS API Error: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"Unexpected error listing Classic ELBs: {e}")

def list_albs(elbv2_client):
    """List Application/Network Load Balancers with pagination and error handling."""
    print("\n=== Application/Network Load Balancers ===")
    
    try:
        # Use paginator for large number of ALBs
        paginator = elbv2_client.get_paginator('describe_load_balancers')
        alb_count = 0
        
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                alb_count += 1
                lb_arn = lb['LoadBalancerArn']
                name = lb['LoadBalancerName']
                lb_type = lb['Type']
                scheme = lb['Scheme']
                state = lb['State']['Code']
                
                print(f"\nLoad Balancer Name: {name} (Type: {lb_type}, Scheme: {scheme}, State: {state})")
                print(f"DNS Name: {lb['DNSName']}")
                
                if lb.get('VpcId'):
                    print(f"VPC ID: {lb['VpcId']}")
                
                # List listeners with error handling
                try:
                    listener_paginator = elbv2_client.get_paginator('describe_listeners')
                    listeners_found = False
                    
                    print("Listeners:")
                    for listener_page in listener_paginator.paginate(LoadBalancerArn=lb_arn):
                        for listener in listener_page['Listeners']:
                            listeners_found = True
                            proto = listener.get('Protocol', 'Unknown')
                            port = listener.get('Port', 'Unknown')
                            print(f" - {proto} port {port}")
                            
                            # List target groups for this listener with safe parsing
                            try:
                                tg_arns = []
                                rules_response = elbv2_client.describe_rules(ListenerArn=listener['ListenerArn'])
                                
                                for rule in rules_response.get('Rules', []):
                                    for action in rule.get('Actions', []):
                                        if action.get('Type') == 'forward':
                                            if 'TargetGroupArn' in action:
                                                tg_arns.append(action['TargetGroupArn'])
                                            elif 'ForwardConfig' in action:
                                                # Handle ALB target groups in ForwardConfig
                                                for tg in action['ForwardConfig'].get('TargetGroups', []):
                                                    if 'TargetGroupArn' in tg:
                                                        tg_arns.append(tg['TargetGroupArn'])
                                
                                if not tg_arns:
                                    print("   No target groups found")
                                else:
                                    # Remove duplicates
                                    tg_arns = list(set(tg_arns))
                                    for tg_arn in tg_arns:
                                        try:
                                            tg_response = elbv2_client.describe_target_groups(TargetGroupArns=[tg_arn])
                                            if tg_response['TargetGroups']:
                                                tg = tg_response['TargetGroups'][0]
                                                tg_name = tg['TargetGroupName']
                                                tg_proto = tg['Protocol']
                                                tg_port = tg['Port']
                                                tg_type = tg.get('TargetType', 'instance')
                                                print(f"   Target Group: {tg_name}, Protocol: {tg_proto}, Port: {tg_port}, Type: {tg_type}")
                                        except ClientError as e:
                                            print(f"   Error describing target group {tg_arn}: {e.response['Error']['Message']}")
                                            
                            except ClientError as e:
                                print(f"   Error listing rules for listener: {e.response['Error']['Message']}")
                    
                    if not listeners_found:
                        print("   No listeners found")
                        
                except ClientError as e:
                    print(f"   Error listing listeners: {e.response['Error']['Message']}")
        
        if alb_count == 0:
            print("No Application/Network Load Balancers found in this region.")
        else:
            print(f"\nTotal ALBs/NLBs: {alb_count}")
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: No permission to describe Load Balancers. Required permission: elasticloadbalancing:DescribeLoadBalancers")
        else:
            print(f"AWS API Error: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"Unexpected error listing ALBs/NLBs: {e}")

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

def main():
    parser = argparse.ArgumentParser(description="List ELB and ALB details")
    parser.add_argument('--region', help='AWS region (overridden by --all-regions)')
    parser.add_argument('--all-regions', action='store_true', help='Scan all AWS regions')
    parser.add_argument('--profile', help='AWS profile to use')
    args = parser.parse_args()

    # Validate region arguments
    if not args.region and not args.all_regions:
        parser.error("Either --region or --all-regions must be specified")

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

        print("=" * 50)

        # Scan each region
        total_classic_elbs = 0
        total_albs = 0

        for region in regions_to_scan:
            print(f"\n{'='*60}")
            print(f"REGION: {region}")
            print(f"{'='*60}")

            try:
                # Create clients for this region
                if session:
                    elb_client = session.client('elb', region_name=region)
                    elbv2_client = session.client('elbv2', region_name=region)
                else:
                    elb_client = boto3.client('elb', region_name=region)
                    elbv2_client = boto3.client('elbv2', region_name=region)

                # List load balancers for this region
                print(f"Listing ELBs and ALBs in region: {region}")
                print("-" * 50)
                
                list_classic_elbs(elb_client)
                list_albs(elbv2_client)

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'UnauthorizedOperation':
                    print(f"No permission to access region {region}, skipping...")
                    continue
                elif error_code == 'InvalidParameterValue':
                    print(f"Invalid region '{region}', skipping...")
                    continue
                else:
                    print(f"Error in region {region}: {e.response['Error']['Message']}")
                    continue

        if args.all_regions:
            print(f"\n{'='*60}")
            print("SCAN COMPLETE")
            print(f"{'='*60}")
            print(f"Scanned {len(regions_to_scan)} regions")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidParameterValue':
            print(f"Error: Invalid region '{args.region}'. Please check the region name.")
        else:
            print(f"AWS API Error: {e.response['Error']['Message']}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

