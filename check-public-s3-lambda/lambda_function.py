#!/usr/bin/env python3
"""
Check Public S3 Buckets - Lambda Version
Serverless function for automated S3 security auditing
"""

import json
import boto3
import os
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_bucket_region(s3_client, bucket_name: str) -> str:
    """Get the region where a bucket is located."""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        region = response.get('LocationConstraint')
        # get_bucket_location returns None for us-east-1
        return region if region else 'us-east-1'
    except ClientError as e:
        logger.warning(f"Could not get region for {bucket_name}: {e.response['Error']['Message']}")
        return 'unknown'

def check_bucket_public_access_block(s3_client, bucket_name: str) -> Dict:
    """Check bucket public access block configuration."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get('PublicAccessBlockConfiguration', {})
        
        return {
            'HasPublicAccessBlock': True,
            'BlockPublicAcls': config.get('BlockPublicAcls', False),
            'IgnorePublicAcls': config.get('IgnorePublicAcls', False),
            'BlockPublicPolicy': config.get('BlockPublicPolicy', False),
            'RestrictPublicBuckets': config.get('RestrictPublicBuckets', False),
            'IsFullyBlocked': all([
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
                'IsFullyBlocked': False
            }
        else:
            logger.warning(f"Could not check public access block for {bucket_name}: {e}")
            return {'HasPublicAccessBlock': False, 'IsFullyBlocked': False}

def analyze_bucket_policy(policy_document: str) -> bool:
    """Analyze bucket policy for public access."""
    if not policy_document:
        return False
    
    try:
        policy = json.loads(policy_document)
        statements = policy.get('Statement', [])
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principals = statement.get('Principal', {})
                
                # Check for wildcard principals
                if principals == '*' or principals == {'AWS': '*'}:
                    return True
                
                # Check for specific public principal patterns
                if isinstance(principals, dict):
                    aws_principals = principals.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for principal in aws_principals:
                        if principal == '*' or principal == 'arn:aws:iam::*:root':
                            return True
        
        return False
    except json.JSONDecodeError:
        logger.warning("Could not parse bucket policy JSON")
        return False

def check_bucket_policy(s3_client, bucket_name: str) -> Dict:
    """Check bucket policy for public access."""
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = response.get('Policy', '')
        is_public = analyze_bucket_policy(policy_document)
        
        return {
            'HasBucketPolicy': True,
            'IsPublicPolicy': is_public,
            'PolicyDocument': policy_document
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return {'HasBucketPolicy': False, 'IsPublicPolicy': False, 'PolicyDocument': None}
        else:
            logger.warning(f"Could not check bucket policy for {bucket_name}: {e}")
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
        logger.warning(f"Could not check ACL for {bucket_name}: {e}")
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
            logger.warning(f"Could not check website config for {bucket_name}: {e}")
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
            logger.warning(f"Could not check encryption for {bucket_name}: {e}")
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
        logger.warning(f"Could not check versioning for {bucket_name}: {e}")
        return {'VersioningEnabled': False, 'VersioningStatus': 'Unknown'}

def check_bucket_logging(s3_client, bucket_name: str) -> Dict:
    """Check bucket access logging configuration."""
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        logging_enabled = 'LoggingEnabled' in response
        
        if logging_enabled:
            log_config = response['LoggingEnabled']
            return {
                'AccessLoggingEnabled': True,
                'TargetBucket': log_config.get('TargetBucket', ''),
                'TargetPrefix': log_config.get('TargetPrefix', '')
            }
        else:
            return {'AccessLoggingEnabled': False}
    except ClientError as e:
        logger.warning(f"Could not check logging for {bucket_name}: {e}")
        return {'AccessLoggingEnabled': False}

def analyze_bucket_security(s3_client, bucket_name: str) -> Dict:
    """Perform comprehensive security analysis of a bucket."""
    bucket_info = {
        'BucketName': bucket_name,
        'Region': get_bucket_region(s3_client, bucket_name),
        'IsPublic': False,
        'RiskLevel': 'Low',
        'SecurityIssues': []
    }
    
    try:
        # Check public access block
        public_access_block = check_bucket_public_access_block(s3_client, bucket_name)
        bucket_info['PublicAccessBlock'] = public_access_block
        
        # Check bucket policy
        bucket_policy = check_bucket_policy(s3_client, bucket_name)
        bucket_info['BucketPolicy'] = bucket_policy
        
        # Check bucket ACL
        bucket_acl = check_bucket_acl(s3_client, bucket_name)
        bucket_info['BucketACL'] = bucket_acl
        
        # Check website hosting
        website_config = check_bucket_website(s3_client, bucket_name)
        bucket_info['WebsiteHosting'] = website_config
        
        # Check encryption
        encryption_config = check_bucket_encryption(s3_client, bucket_name)
        bucket_info['Encryption'] = encryption_config
        
        # Check versioning
        versioning_config = check_bucket_versioning(s3_client, bucket_name)
        bucket_info['Versioning'] = versioning_config
        
        # Check logging
        logging_config = check_bucket_logging(s3_client, bucket_name)
        bucket_info['Logging'] = logging_config
        
        # Determine if bucket is public
        is_public_via_policy = bucket_policy.get('IsPublicPolicy', False)
        is_public_via_acl = bucket_acl.get('IsPublicACL', False)
        is_fully_blocked = public_access_block.get('IsFullyBlocked', False)
        
        bucket_info['IsPublic'] = (is_public_via_policy or is_public_via_acl) and not is_fully_blocked
        
        # Assess security issues and risk level
        security_issues = []
        
        if bucket_info['IsPublic']:
            if website_config.get('HasWebsiteHosting', False):
                security_issues.append("Bucket is public and configured for website hosting")
            if not encryption_config.get('HasEncryption', False):
                security_issues.append("Public bucket without encryption")
            if bucket_acl.get('PublicWrite', False):
                security_issues.append("Bucket allows public write access")
                bucket_info['RiskLevel'] = 'Critical'
            elif is_public_via_acl:
                security_issues.append("Bucket is public via ACL")
                bucket_info['RiskLevel'] = 'High'
            elif is_public_via_policy:
                security_issues.append("Bucket is public via bucket policy")
                bucket_info['RiskLevel'] = 'High'
        else:
            # Private bucket checks
            if not encryption_config.get('HasEncryption', False):
                security_issues.append("Bucket not encrypted")
                bucket_info['RiskLevel'] = 'Medium'
            if not versioning_config.get('VersioningEnabled', False):
                security_issues.append("Versioning not enabled")
            if not logging_config.get('AccessLoggingEnabled', False):
                security_issues.append("Access logging not enabled")
        
        bucket_info['SecurityIssues'] = security_issues
        
        # Override risk level for critical issues
        if bucket_acl.get('PublicWrite', False):
            bucket_info['RiskLevel'] = 'Critical'
        elif bucket_info['IsPublic'] and not encryption_config.get('HasEncryption', False):
            bucket_info['RiskLevel'] = 'High'
        elif bucket_info['IsPublic']:
            bucket_info['RiskLevel'] = 'High'
        elif not encryption_config.get('HasEncryption', False):
            bucket_info['RiskLevel'] = 'Medium'
        
    except Exception as e:
        logger.error(f"Error analyzing bucket {bucket_name}: {str(e)}")
        bucket_info['Error'] = str(e)
        bucket_info['RiskLevel'] = 'Unknown'
    
    return bucket_info

def get_all_buckets(s3_client) -> List[str]:
    """Get all S3 buckets in the account."""
    try:
        response = s3_client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]
    except ClientError as e:
        logger.error(f"Error listing buckets: {e.response['Error']['Message']}")
        return []

def filter_buckets(buckets: List[Dict], public_only: bool = True) -> List[Dict]:
    """Filter buckets based on criteria."""
    if public_only:
        return [bucket for bucket in buckets if bucket['IsPublic']]
    return buckets

def calculate_summary_stats(buckets: List[Dict]) -> Dict:
    """Calculate summary statistics for the audit."""
    total_buckets = len(buckets)
    public_buckets = [b for b in buckets if b['IsPublic']]
    encrypted_buckets = [b for b in buckets if b.get('Encryption', {}).get('HasEncryption', False)]
    versioned_buckets = [b for b in buckets if b.get('Versioning', {}).get('VersioningEnabled', False)]
    
    # Risk analysis
    critical_risk = [b for b in buckets if b['RiskLevel'] == 'Critical']
    high_risk = [b for b in buckets if b['RiskLevel'] == 'High']
    medium_risk = [b for b in buckets if b['RiskLevel'] == 'Medium']
    low_risk = [b for b in buckets if b['RiskLevel'] == 'Low']
    
    return {
        'total_buckets': total_buckets,
        'public_buckets': len(public_buckets),
        'encrypted_buckets': len(encrypted_buckets),
        'versioned_buckets': len(versioned_buckets),
        'critical_risk': len(critical_risk),
        'high_risk': len(high_risk),
        'medium_risk': len(medium_risk),
        'low_risk': len(low_risk),
        'unencrypted_buckets': total_buckets - len(encrypted_buckets)
    }

def send_security_notifications(summary_stats: Dict, filtered_buckets: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk buckets
        critical_buckets = [b for b in filtered_buckets if b['RiskLevel'] == 'Critical']
        high_risk_buckets = [b for b in filtered_buckets if b['RiskLevel'] == 'High']
        
        if not critical_buckets and not high_risk_buckets:
            logger.info("No critical or high risk findings to notify")
            return
        
        # Build notification message
        subject = f"🚨 S3 Security Alert - Account {account_id}"
        
        message_parts = [
            f"CRITICAL S3 SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total buckets scanned: {summary_stats['total_buckets']}",
            f"• Public buckets found: {summary_stats['public_buckets']}",
            f"• Critical risk buckets: {summary_stats['critical_risk']}",
            f"• High risk buckets: {summary_stats['high_risk']}",
            f""
        ]
        
        # Add critical findings details
        if critical_buckets:
            message_parts.append("🔴 CRITICAL RISK BUCKETS:")
            for bucket in critical_buckets:
                message_parts.append(f"  • {bucket['BucketName']} ({bucket['Region']})")
                for issue in bucket.get('SecurityIssues', []):
                    message_parts.append(f"    - {issue}")
                if bucket.get('BucketACL', {}).get('PublicWrite', False):
                    message_parts.append(f"    - ⚠️  PUBLIC WRITE ACCESS ENABLED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_buckets:
            message_parts.append("🟠 HIGH RISK BUCKETS:")
            for bucket in high_risk_buckets:
                message_parts.append(f"  • {bucket['BucketName']} ({bucket['Region']})")
                for issue in bucket.get('SecurityIssues', []):
                    message_parts.append(f"    - {issue}")
                if bucket['IsPublic']:
                    message_parts.append(f"    - 🌐 Bucket is publicly accessible")
            message_parts.append("")
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Review and restrict public access on identified buckets",
            "2. Enable S3 Block Public Access at account level if not already done",
            "3. Enable encryption on all buckets containing sensitive data",
            "4. Review and update bucket policies to follow least privilege principle",
            "5. Enable access logging for audit trail",
            "",
            "For detailed bucket analysis, check CloudWatch logs or run the audit manually.",
            "",
            "This alert was generated by the automated S3 Security Audit Lambda function."
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
        logger.info(f"Notified about {len(critical_buckets)} critical and {len(high_risk_buckets)} high risk buckets")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for S3 security auditing
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with audit results
    """
    try:
        logger.info("Starting S3 security audit")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        public_only = params.get('public_only',
                               os.environ.get('PUBLIC_ONLY', 'true').lower() == 'true')
        
        logger.info(f"Configuration - Public only: {public_only}")
        
        # Create S3 client
        s3_client = boto3.client('s3')
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Auditing AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Get all buckets
        logger.info("Retrieving all S3 buckets...")
        bucket_names = get_all_buckets(s3_client)
        
        if not bucket_names:
            logger.warning("No S3 buckets found")
            return {
                'statusCode': 200,
                'body': {
                    'message': 'S3 security audit completed successfully',
                    'results': {
                        'buckets': [],
                        'summary': {
                            'total_buckets': 0,
                            'public_buckets': 0,
                            'encrypted_buckets': 0,
                            'versioned_buckets': 0,
                            'critical_risk': 0,
                            'high_risk': 0,
                            'medium_risk': 0,
                            'low_risk': 0,
                            'unencrypted_buckets': 0
                        },
                        'audit_parameters': {
                            'public_only': public_only,
                            'account_id': account_id
                        }
                    },
                    'executionId': context.aws_request_id,
                    'alerts_triggered': False
                }
            }
        
        logger.info(f"Found {len(bucket_names)} S3 buckets. Analyzing security...")
        
        # Analyze each bucket
        all_buckets = []
        for bucket_name in bucket_names:
            bucket_info = analyze_bucket_security(s3_client, bucket_name)
            all_buckets.append(bucket_info)
        
        # Filter buckets based on criteria
        filtered_buckets = filter_buckets(all_buckets, public_only)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(all_buckets)
        
        # Determine if alerts should be triggered
        alerts_triggered = (summary_stats['critical_risk'] > 0 or 
                          (public_only and summary_stats['public_buckets'] > 0))
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Audit completed. Total buckets: {summary_stats['total_buckets']}, "
                   f"Public buckets: {summary_stats['public_buckets']}, "
                   f"Critical risk: {summary_stats['critical_risk']}")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(summary_stats, filtered_buckets, account_id)
            
            if summary_stats['critical_risk'] > 0:
                logger.warning(f"SECURITY ALERT: Found {summary_stats['critical_risk']} S3 buckets with critical security risks!")
            if public_only and summary_stats['public_buckets'] > 0:
                logger.warning(f"EXPOSURE ALERT: Found {summary_stats['public_buckets']} publicly accessible S3 buckets!")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': 'S3 security audit completed successfully',
                'results': {
                    'buckets': filtered_buckets,
                    'summary': summary_stats,
                    'audit_parameters': {
                        'public_only': public_only,
                        'account_id': account_id,
                        'caller_arn': caller_arn
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"S3 security audit failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'S3 security audit failed',
                'executionId': context.aws_request_id
            }
        }