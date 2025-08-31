#!/usr/bin/env python3
"""
Comprehensive S3 security audit — detect public buckets and security issues.

This script analyzes S3 buckets for public accessibility and other security
configurations that could expose data unintentionally.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict, Optional

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

def get_bucket_region(s3_client, bucket_name: str) -> str:
    """Get the region where a bucket is located."""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        region = response.get('LocationConstraint')
        # get_bucket_location returns None for us-east-1
        return region if region else 'us-east-1'
    except ClientError as e:
        print(f"Warning: Could not get region for {bucket_name}: {e.response['Error']['Message']}")
        return 'unknown'

def check_bucket_public_access_block(s3_client, bucket_name: str) -> Dict:
    """Check bucket public access block configuration."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        return {
            'HasPublicAccessBlock': True,
            'BlockPublicAcls': config.get('BlockPublicAcls', False),
            'IgnorePublicAcls': config.get('IgnorePublicAcls', False),
            'BlockPublicPolicy': config.get('BlockPublicPolicy', False),
            'RestrictPublicBuckets': config.get('RestrictPublicBuckets', False),
            'FullyBlocked': all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ])
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return {
                'HasPublicAccessBlock': False,
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False,
                'FullyBlocked': False
            }
        else:
            print(f"Warning: Could not check public access block for {bucket_name}: {e}")
            return {'HasPublicAccessBlock': False, 'FullyBlocked': False}

def check_bucket_policy(s3_client, bucket_name: str) -> Dict:
    """Check bucket policy for public access."""
    try:
        # Check policy status
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        is_public = policy_status.get('PolicyStatus', {}).get('IsPublic', False)
        
        # Get actual policy
        policy_document = None
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_document = policy_response.get('Policy')
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                print(f"Warning: Could not get policy for {bucket_name}: {e}")
        
        return {
            'HasBucketPolicy': policy_document is not None,
            'IsPublicPolicy': is_public,
            'PolicyDocument': policy_document
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return {'HasBucketPolicy': False, 'IsPublicPolicy': False, 'PolicyDocument': None}
        else:
            print(f"Warning: Could not check bucket policy for {bucket_name}: {e}")
            return {'HasBucketPolicy': False, 'IsPublicPolicy': False}

def check_bucket_acl(s3_client, bucket_name: str) -> Dict:
    """Check bucket ACL for public access."""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        public_read = False
        public_write = False
        authenticated_read = False
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            
            # Check for AllUsers (public)
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                if permission in ['READ', 'FULL_CONTROL']:
                    public_read = True
                if permission in ['WRITE', 'FULL_CONTROL']:
                    public_write = True
            
            # Check for AuthenticatedUsers
            elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                if permission in ['READ', 'FULL_CONTROL']:
                    authenticated_read = True
        
        return {
            'PublicRead': public_read,
            'PublicWrite': public_write,
            'AuthenticatedRead': authenticated_read,
            'IsPublicACL': public_read or public_write
        }
    except ClientError as e:
        print(f"Warning: Could not check ACL for {bucket_name}: {e}")
        return {'PublicRead': False, 'PublicWrite': False, 'AuthenticatedRead': False, 'IsPublicACL': False}

def check_bucket_website(s3_client, bucket_name: str) -> Dict:
    """Check if bucket has website hosting enabled."""
    try:
        response = s3_client.get_bucket_website(Bucket=bucket_name)
        return {
            'HasWebsiteHosting': True,
            'IndexDocument': response.get('IndexDocument', {}).get('Suffix', ''),
            'ErrorDocument': response.get('ErrorDocument', {}).get('Key', '')
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchWebsiteConfiguration':
            return {'HasWebsiteHosting': False}
        else:
            print(f"Warning: Could not check website config for {bucket_name}: {e}")
            return {'HasWebsiteHosting': False}

def check_bucket_encryption(s3_client, bucket_name: str) -> Dict:
    """Check bucket encryption configuration."""
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        
        if rules:
            encryption_rule = rules[0]  # Usually only one rule
            sse_algorithm = encryption_rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'None')
            kms_key_id = encryption_rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
            
            return {
                'HasEncryption': True,
                'EncryptionType': sse_algorithm,
                'KMSKeyId': kms_key_id,
                'BucketKeyEnabled': encryption_rule.get('BucketKeyEnabled', False)
            }
        else:
            return {'HasEncryption': False, 'EncryptionType': 'None'}
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return {'HasEncryption': False, 'EncryptionType': 'None'}
        else:
            print(f"Warning: Could not check encryption for {bucket_name}: {e}")
            return {'HasEncryption': False, 'EncryptionType': 'Unknown'}

def check_bucket_versioning(s3_client, bucket_name: str) -> Dict:
    """Check bucket versioning configuration."""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')
        mfa_delete = response.get('MfaDelete', 'Disabled')
        
        return {
            'VersioningEnabled': status == 'Enabled',
            'VersioningStatus': status,
            'MfaDeleteEnabled': mfa_delete == 'Enabled'
        }
    except ClientError as e:
        print(f"Warning: Could not check versioning for {bucket_name}: {e}")
        return {'VersioningEnabled': False, 'VersioningStatus': 'Unknown'}

def check_bucket_logging(s3_client, bucket_name: str) -> Dict:
    """Check bucket access logging configuration."""
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        logging_enabled = 'LoggingEnabled' in response
        
        if logging_enabled:
            logging_config = response['LoggingEnabled']
            return {
                'LoggingEnabled': True,
                'TargetBucket': logging_config.get('TargetBucket'),
                'TargetPrefix': logging_config.get('TargetPrefix', '')
            }
        else:
            return {'LoggingEnabled': False}
    except ClientError as e:
        print(f"Warning: Could not check logging for {bucket_name}: {e}")
        return {'LoggingEnabled': False}

def get_bucket_size_and_objects(s3_client, bucket_name: str) -> Dict:
    """Get bucket size and object count (sampling for large buckets)."""
    try:
        # Use list_objects_v2 with pagination but limit to avoid timeout
        paginator = s3_client.get_paginator('list_objects_v2')
        
        object_count = 0
        total_size = 0
        sample_limit = 10000  # Limit to first 10k objects for performance
        
        for page in paginator.paginate(Bucket=bucket_name):
            contents = page.get('Contents', [])
            if not contents:
                break
                
            object_count += len(contents)
            total_size += sum(obj.get('Size', 0) for obj in contents)
            
            # Stop after sample limit to avoid timeout
            if object_count >= sample_limit:
                object_count = f"{object_count}+ (sampled)"
                break
        
        return {
            'ObjectCount': object_count,
            'TotalSizeBytes': total_size,
            'TotalSizeMB': round(total_size / (1024 * 1024), 2) if total_size > 0 else 0
        }
    except ClientError as e:
        print(f"Warning: Could not get size info for {bucket_name}: {e}")
        return {'ObjectCount': 'Unknown', 'TotalSizeBytes': 0, 'TotalSizeMB': 0}

def analyze_bucket_security(s3_client, bucket_name: str, creation_date: datetime) -> Dict:
    """Comprehensive security analysis for an S3 bucket."""
    print(f"  Analyzing {bucket_name}...", end=" ")
    
    bucket_info = {
        'BucketName': bucket_name,
        'CreationDate': creation_date,
        'Region': get_bucket_region(s3_client, bucket_name),
        'RiskLevel': 'Low'
    }
    
    # Check all security configurations
    bucket_info.update(check_bucket_public_access_block(s3_client, bucket_name))
    bucket_info.update(check_bucket_policy(s3_client, bucket_name))
    bucket_info.update(check_bucket_acl(s3_client, bucket_name))
    bucket_info.update(check_bucket_website(s3_client, bucket_name))
    bucket_info.update(check_bucket_encryption(s3_client, bucket_name))
    bucket_info.update(check_bucket_versioning(s3_client, bucket_name))
    bucket_info.update(check_bucket_logging(s3_client, bucket_name))
    bucket_info.update(get_bucket_size_and_objects(s3_client, bucket_name))
    
    # Determine if bucket is public
    is_public = False
    public_reasons = []
    
    if bucket_info.get('IsPublicACL'):
        is_public = True
        public_reasons.append('Public ACL')
    
    if bucket_info.get('IsPublicPolicy'):
        is_public = True
        public_reasons.append('Public bucket policy')
    
    if bucket_info.get('HasWebsiteHosting') and not bucket_info.get('FullyBlocked'):
        is_public = True
        public_reasons.append('Website hosting enabled')
    
    bucket_info['IsPublic'] = is_public
    bucket_info['PublicReasons'] = public_reasons
    
    # Determine risk level
    if is_public:
        if bucket_info.get('TotalSizeMB', 0) > 1000:  # Large buckets
            bucket_info['RiskLevel'] = 'Critical'
        elif not bucket_info.get('HasEncryption'):
            bucket_info['RiskLevel'] = 'High'
        else:
            bucket_info['RiskLevel'] = 'Medium'
    else:
        if not bucket_info.get('HasEncryption'):
            bucket_info['RiskLevel'] = 'Medium'
        elif not bucket_info.get('LoggingEnabled'):
            bucket_info['RiskLevel'] = 'Low'
    
    # Print status
    if is_public:
        risk_indicator = {
            'Critical': '🔴',
            'High': '🟡',
            'Medium': '🟠'
        }.get(bucket_info['RiskLevel'], '❓')
        print(f"{risk_indicator} PUBLIC ({', '.join(public_reasons)})")
    else:
        print("✅ Private")
    
    return bucket_info

def get_all_buckets_with_pagination(s3_client) -> List[Dict]:
    """Get all S3 buckets. Note: list_buckets doesn't support pagination but lists all buckets."""
    try:
        response = s3_client.list_buckets()
        return response.get('Buckets', [])
    except ClientError as e:
        print(f"Error retrieving buckets: {e.response['Error']['Message']}")
        return []

def export_to_csv(buckets: List[Dict], filename: str):
    """Export bucket data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'BucketName', 'Region', 'CreationDate', 'IsPublic', 'PublicReasons',
            'RiskLevel', 'HasEncryption', 'EncryptionType', 'VersioningEnabled',
            'LoggingEnabled', 'HasWebsiteHosting', 'ObjectCount', 'TotalSizeMB',
            'HasPublicAccessBlock', 'FullyBlocked'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for bucket in buckets:
            row = bucket.copy()
            # Convert lists to strings for CSV
            row['PublicReasons'] = ', '.join(bucket.get('PublicReasons', []))
            row['CreationDate'] = bucket.get('CreationDate', '').strftime('%Y-%m-%d') if bucket.get('CreationDate') else ''
            writer.writerow(row)

def export_to_json(buckets: List[Dict], filename: str):
    """Export bucket data to JSON."""
    # Convert datetime objects to strings for JSON serialization
    json_data = []
    for bucket in buckets:
        bucket_copy = bucket.copy()
        if bucket_copy.get('CreationDate'):
            bucket_copy['CreationDate'] = bucket_copy['CreationDate'].isoformat()
        json_data.append(bucket_copy)
    
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(json_data, jsonfile, indent=2, default=str)

def print_summary_report(buckets: List[Dict]):
    """Print comprehensive summary report."""
    total_buckets = len(buckets)
    public_buckets = [b for b in buckets if b.get('IsPublic')]
    encrypted_buckets = [b for b in buckets if b.get('HasEncryption')]
    versioned_buckets = [b for b in buckets if b.get('VersioningEnabled')]
    logged_buckets = [b for b in buckets if b.get('LoggingEnabled')]
    
    # Risk analysis
    critical_risk = [b for b in buckets if b.get('RiskLevel') == 'Critical']
    high_risk = [b for b in buckets if b.get('RiskLevel') == 'High']
    medium_risk = [b for b in buckets if b.get('RiskLevel') == 'Medium']
    
    print(f"\n{'='*80}")
    print("S3 SECURITY ASSESSMENT SUMMARY")
    print(f"{'='*80}")
    print(f"Total S3 Buckets: {total_buckets}")
    print(f"Public Buckets: {len(public_buckets)}")
    print(f"Encrypted Buckets: {len(encrypted_buckets)}")
    print(f"Versioned Buckets: {len(versioned_buckets)}")
    print(f"Logged Buckets: {len(logged_buckets)}")
    print(f"Critical Risk: {len(critical_risk)}")
    print(f"High Risk: {len(high_risk)}")
    print(f"Medium Risk: {len(medium_risk)}")
    
    if public_buckets:
        print(f"\n{'='*80}")
        print("PUBLIC BUCKETS (IMMEDIATE ATTENTION REQUIRED)")
        print(f"{'='*80}")
        
        print(f"\n{'Bucket Name':30} {'Region':15} {'Risk':8} {'Size (MB)':12} {'Reasons'}")
        print("-" * 90)
        
        # Sort by risk level
        sorted_buckets = sorted(public_buckets, 
                              key=lambda x: (x['RiskLevel'] != 'Critical', x['RiskLevel'] != 'High'))
        
        for bucket in sorted_buckets:
            risk_indicator = {
                'Critical': '🔴',
                'High': '🟡',
                'Medium': '🟠',
                'Low': '🟢'
            }.get(bucket['RiskLevel'], '❓')
            
            size_mb = bucket.get('TotalSizeMB', 0)
            reasons = ', '.join(bucket.get('PublicReasons', []))
            
            print(f"{bucket['BucketName']:30} "
                  f"{bucket.get('Region', 'Unknown'):15} "
                  f"{risk_indicator} {bucket['RiskLevel']:6} "
                  f"{size_mb:10.1f} "
                  f"{reasons}")
    
    # Show security recommendations
    unencrypted = [b for b in buckets if not b.get('HasEncryption')]
    if unencrypted:
        print(f"\n{'='*80}")
        print("UNENCRYPTED BUCKETS")
        print(f"{'='*80}")
        for bucket in unencrypted[:10]:  # Show first 10
            print(f"  {bucket['BucketName']} ({bucket.get('Region', 'Unknown')})")
        if len(unencrypted) > 10:
            print(f"  ... and {len(unencrypted) - 10} more")
    
    no_versioning = [b for b in buckets if not b.get('VersioningEnabled')]
    if no_versioning:
        print(f"\n{'='*80}")
        print("BUCKETS WITHOUT VERSIONING")
        print(f"{'='*80}")
        print(f"  {len(no_versioning)} buckets without versioning enabled")
    
    print(f"\n{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive S3 security audit with detailed analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic S3 security audit
  ./check_public_s3.py
  
  # Use specific AWS profile
  ./check_public_s3.py --profile production
  
  # Export detailed report with profile
  ./check_public_s3.py --profile staging --export-csv s3_security_report.csv
  
  # Show only public buckets for production environment
  ./check_public_s3.py --profile production --public-only
  
  # Comprehensive audit with JSON export
  ./check_public_s3.py --profile production --export-json s3_audit.json

SECURITY CHECKS:
- Public access via ACL
- Public access via bucket policy
- Public access block configuration
- Website hosting configuration
- Encryption settings
- Versioning status
- Access logging
- Bucket size and object count
"""
    )
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--public-only', action='store_true',
                       help='Show only publicly accessible buckets')
    parser.add_argument('--profile', help='AWS profile to use')
    
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

    try:
        # Create S3 client
        if session:
            s3_client = session.client('s3')
        else:
            s3_client = boto3.client('s3')

        print("Analyzing S3 buckets for security issues...")
        print("Note: S3 buckets are global but may be located in different regions")
        print("=" * 60)

        # Get all buckets
        print("Retrieving S3 buckets...")
        buckets = get_all_buckets_with_pagination(s3_client)
        
        if not buckets:
            print("No S3 buckets found.")
            return

        print(f"Found {len(buckets)} S3 buckets. Analyzing security configurations...")
        print()

        # Analyze each bucket
        analyzed_buckets = []
        for bucket in buckets:
            bucket_name = bucket['Name']
            creation_date = bucket['CreationDate']
            
            bucket_info = analyze_bucket_security(s3_client, bucket_name, creation_date)
            analyzed_buckets.append(bucket_info)

        # Filter results if requested
        display_buckets = analyzed_buckets
        if args.public_only:
            display_buckets = [b for b in analyzed_buckets if b.get('IsPublic')]

        # Print summary report
        print_summary_report(analyzed_buckets)

        # Export to files if requested
        if args.export_csv:
            export_to_csv(analyzed_buckets, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(analyzed_buckets, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        # Return appropriate exit code for automation
        public_buckets = [b for b in analyzed_buckets if b.get('IsPublic')]
        critical_buckets = [b for b in analyzed_buckets if b.get('RiskLevel') == 'Critical']
        
        if critical_buckets:
            print(f"\n🚨 CRITICAL: Found {len(critical_buckets)} critical risk S3 buckets!")
            sys.exit(2)
        elif public_buckets:
            print(f"\n⚠️  WARNING: Found {len(public_buckets)} publicly accessible S3 buckets!")
            sys.exit(1)
        else:
            print(f"\n✅ All S3 buckets are properly secured!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access S3. Required permissions:")
            print("- s3:ListAllMyBuckets")
            print("- s3:GetBucketAcl")
            print("- s3:GetBucketPolicy") 
            print("- s3:GetBucketPolicyStatus")
            print("- s3:GetBucketLocation")
            print("- s3:GetBucketPublicAccessBlock")
            print("- s3:GetBucketWebsite")
            print("- s3:GetBucketEncryption")
            print("- s3:GetBucketVersioning")
            print("- s3:GetBucketLogging")
            print("- s3:ListBucket")
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

