#!/usr/bin/env python3
"""
IAM Users MFA Compliance Checker - Lambda Version
Serverless function for automated IAM security auditing
"""

import json
import boto3
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_user_last_activity(iam_client, username: str) -> Optional[datetime]:
    """Get the last activity date for a user."""
    try:
        response = iam_client.get_user(UserName=username)
        # Check password last used
        password_last_used = response['User'].get('PasswordLastUsed')
        
        # Get access key last used dates
        access_keys_response = iam_client.list_access_keys(UserName=username)
        access_key_dates = []
        
        for key in access_keys_response['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            try:
                key_info = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used = key_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                if last_used:
                    access_key_dates.append(last_used)
            except ClientError:
                continue
        
        # Return the most recent activity
        all_dates = []
        if password_last_used:
            all_dates.append(password_last_used)
        all_dates.extend(access_key_dates)
        
        return max(all_dates) if all_dates else None
        
    except ClientError as e:
        logger.warning(f"Could not get activity info for {username}: {e}")
        return None

def check_user_mfa_status(iam_client, user: Dict) -> Dict:
    """Check MFA status and details for a user."""
    username = user['UserName']
    user_info = {
        'UserName': username,
        'CreateDate': user['CreateDate'],
        'HasConsoleAccess': False,
        'HasMFA': False,
        'MFADevices': [],
        'LastActivity': None,
        'RiskLevel': 'Low',
        'Groups': [],
        'AttachedPolicies': []
    }
    
    try:
        # Check console access
        try:
            iam_client.get_login_profile(UserName=username)
            user_info['HasConsoleAccess'] = True
        except iam_client.exceptions.NoSuchEntityException:
            user_info['HasConsoleAccess'] = False
        
        # Check MFA devices
        try:
            mfa_response = iam_client.list_mfa_devices(UserName=username)
            mfa_devices = []
            for device in mfa_response['MFADevices']:
                mfa_devices.append({
                    'SerialNumber': device['SerialNumber'],
                    'EnableDate': device['EnableDate']
                })
        except ClientError as e:
            mfa_devices = []
        
        user_info['MFADevices'] = mfa_devices
        user_info['HasMFA'] = len(mfa_devices) > 0
        
        # Get last activity
        user_info['LastActivity'] = get_user_last_activity(iam_client, username)
        
        # Skip groups and policies for Lambda execution efficiency
        user_info['Groups'] = []
        user_info['AttachedPolicies'] = []
        
        # Determine risk level
        if user_info['HasConsoleAccess'] and not user_info['HasMFA']:
            user_info['RiskLevel'] = 'High'
        elif user_info['HasConsoleAccess'] and user_info['HasMFA']:
            user_info['RiskLevel'] = 'Low'
        else:
            user_info['RiskLevel'] = 'Medium'  # No console access but still a user
            
    except Exception as e:
        logger.error(f"Error checking MFA status for {username}: {str(e)}")
        user_info['Error'] = str(e)
    
    return user_info

def get_all_users_with_pagination(iam_client) -> List[Dict]:
    """Get all IAM users with pagination."""
    users = []
    
    try:
        paginator = iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        return users
        
    except ClientError as e:
        logger.error(f"Error retrieving users: {e.response['Error']['Message']}")
        return []

def filter_users_by_criteria(user_data: List[Dict], include_inactive: bool = True, violations_only: bool = False) -> List[Dict]:
    """Filter users based on specified criteria."""
    filtered_users = []
    
    for user in user_data:
        # Skip users with errors
        if 'Error' in user:
            continue
            
        # Filter by violations only
        if violations_only and user['RiskLevel'] != 'High':
            continue
            
        # Filter by activity (if not including inactive)
        if not include_inactive and not user['LastActivity']:
            continue
            
        filtered_users.append(user)
    
    return filtered_users

def calculate_summary_stats(user_data: List[Dict]) -> Dict:
    """Calculate summary statistics for the audit."""
    stats = {
        'total_users': len(user_data),
        'users_with_console_access': 0,
        'users_with_mfa': 0,
        'users_without_mfa': 0,
        'high_risk_users': 0,
        'medium_risk_users': 0,
        'low_risk_users': 0,
        'users_with_recent_activity': 0
    }
    
    for user in user_data:
        if 'Error' in user:
            continue
            
        if user['HasConsoleAccess']:
            stats['users_with_console_access'] += 1
            
        if user['HasMFA']:
            stats['users_with_mfa'] += 1
        else:
            stats['users_without_mfa'] += 1
            
        if user['RiskLevel'] == 'High':
            stats['high_risk_users'] += 1
        elif user['RiskLevel'] == 'Medium':
            stats['medium_risk_users'] += 1
        else:
            stats['low_risk_users'] += 1
            
        if user['LastActivity']:
            stats['users_with_recent_activity'] += 1
    
    return stats

def send_security_notifications(summary_stats: Dict, user_data: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk IAM security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk users
        critical_users = []
        high_risk_users = []
        
        for user in user_data:
            if 'Error' in user:
                continue
                
            # Critical: Console access + no MFA + recent activity (last 30 days)
            if (user['HasConsoleAccess'] and not user['HasMFA'] and 
                user['LastActivity']):
                try:
                    last_activity = user['LastActivity']
                    if isinstance(last_activity, str):
                        last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                    days_since_activity = (datetime.now(timezone.utc) - last_activity).days
                    if days_since_activity <= 30:
                        critical_users.append(user)
                except (ValueError, TypeError):
                    # If we can't parse the date, treat as high risk instead
                    high_risk_users.append(user)
            # High: Console access + no MFA (regardless of activity)
            elif user['HasConsoleAccess'] and not user['HasMFA']:
                high_risk_users.append(user)
        
        if not critical_users and not high_risk_users:
            logger.info("No critical or high risk IAM findings to notify")
            return
        
        # Build notification message
        subject = f"🚨 IAM Security Alert - Account {account_id}"
        
        message_parts = [
            f"CRITICAL IAM SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total IAM users: {summary_stats['total_users']}",
            f"• Users with console access: {summary_stats['users_with_console_access']}",
            f"• Users without MFA: {summary_stats['users_without_mfa']}",
            f"• High risk users: {summary_stats['high_risk_users']}",
            f""
        ]
        
        # Add critical findings details
        if critical_users:
            message_parts.append("🔴 CRITICAL RISK USERS (Console + No MFA + Recent Activity):")
            for user in critical_users:
                try:
                    if user['LastActivity']:
                        last_activity = user['LastActivity']
                        if isinstance(last_activity, str):
                            last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                        activity_days = (datetime.now(timezone.utc) - last_activity).days
                    else:
                        activity_days = 'Unknown'
                except (ValueError, TypeError):
                    activity_days = 'Unknown'
                
                message_parts.append(f"  • {user['UserName']}")
                message_parts.append(f"    - Console access: YES")
                message_parts.append(f"    - MFA enabled: NO")
                message_parts.append(f"    - Last activity: {activity_days} days ago")
                message_parts.append(f"    - ⚠️  IMMEDIATE ACTION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_users:
            message_parts.append("🟠 HIGH RISK USERS (Console Access + No MFA):")
            for user in high_risk_users:
                try:
                    if user['LastActivity']:
                        last_activity = user['LastActivity']
                        if isinstance(last_activity, str):
                            last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                        activity_days = (datetime.now(timezone.utc) - last_activity).days
                        activity_info = f"{activity_days} days ago"
                    else:
                        activity_info = "No recent activity"
                except (ValueError, TypeError):
                    activity_info = "No recent activity"
                
                message_parts.append(f"  • {user['UserName']}")
                message_parts.append(f"    - Console access: YES")
                message_parts.append(f"    - MFA enabled: NO")
                message_parts.append(f"    - Last activity: {activity_info}")
            message_parts.append("")
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Force MFA enrollment for all users with console access",
            "2. Disable console access for service accounts that don't need it",
            "3. Review user access patterns and disable inactive accounts",
            "4. Enable account-level MFA requirement policy",
            "5. Audit user permissions and apply least privilege principle",
            "",
            "REMEDIATION COMMANDS:",
            "# Enable MFA requirement policy",
            "aws iam put-account-password-policy --require-mfa",
            "",
            "# Disable console access for specific user",
            "aws iam delete-login-profile --user-name USERNAME",
            "",
            "For detailed user analysis, check CloudWatch logs or run the audit manually.",
            "",
            "This alert was generated by the automated IAM MFA Compliance Lambda function."
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
        logger.info(f"Notified about {len(critical_users)} critical and {len(high_risk_users)} high risk users")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for IAM MFA compliance checking
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with audit results
    """
    try:
        logger.info("Starting IAM MFA compliance audit")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        include_inactive = params.get('include_inactive', 
                                    os.environ.get('INCLUDE_INACTIVE', 'true').lower() == 'true')
        violations_only = params.get('violations_only',
                                   os.environ.get('VIOLATIONS_ONLY', 'false').lower() == 'true')
        
        logger.info(f"Configuration - Include inactive: {include_inactive}, Violations only: {violations_only}")
        
        # Create IAM client
        iam_client = boto3.client('iam')
        
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
        
        # Get all users
        logger.info("Retrieving all IAM users...")
        all_users = get_all_users_with_pagination(iam_client)
        
        if not all_users:
            logger.warning("No IAM users found")
            return {
                'statusCode': 200,
                'body': {
                    'message': 'IAM MFA compliance audit completed successfully',
                    'results': {
                        'users': [],
                        'summary': {
                            'total_users': 0,
                            'users_with_console_access': 0,
                            'users_with_mfa': 0,
                            'users_without_mfa': 0,
                            'high_risk_users': 0,
                            'medium_risk_users': 0,
                            'low_risk_users': 0,
                            'users_with_recent_activity': 0
                        },
                        'audit_parameters': {
                            'include_inactive': include_inactive,
                            'violations_only': violations_only,
                            'account_id': account_id
                        }
                    },
                    'executionId': context.aws_request_id,
                    'alerts_triggered': False
                }
            }
        
        logger.info(f"Found {len(all_users)} IAM users. Checking MFA status...")
        
        # Check MFA status for each user
        user_data = []
        for user in all_users:
            user_info = check_user_mfa_status(iam_client, user)
            user_data.append(user_info)
        
        # Filter users based on criteria
        filtered_users = filter_users_by_criteria(user_data, include_inactive, violations_only)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(user_data)
        
        # Determine if alerts should be triggered
        alerts_triggered = summary_stats['high_risk_users'] > 0
        status_code = 201 if alerts_triggered else 200
        
        # Format results for JSON serialization
        for user in filtered_users:
            # Convert datetime objects to strings
            if user['CreateDate']:
                user['CreateDate'] = user['CreateDate'].isoformat() if hasattr(user['CreateDate'], 'isoformat') else str(user['CreateDate'])
            if user['LastActivity']:
                user['LastActivity'] = user['LastActivity'].isoformat() if hasattr(user['LastActivity'], 'isoformat') else str(user['LastActivity'])
            
            # Convert MFA device dates
            for device in user['MFADevices']:
                if device['EnableDate']:
                    device['EnableDate'] = device['EnableDate'].isoformat() if hasattr(device['EnableDate'], 'isoformat') else str(device['EnableDate'])
        
        # Log summary
        logger.info(f"Audit completed. Total users: {summary_stats['total_users']}, "
                   f"High risk: {summary_stats['high_risk_users']}, "
                   f"Users with console access: {summary_stats['users_with_console_access']}")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(summary_stats, user_data, account_id)
            logger.warning(f"SECURITY ALERT: Found {summary_stats['high_risk_users']} users with console access but no MFA!")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': 'IAM MFA compliance audit completed successfully',
                'results': {
                    'users': filtered_users,
                    'summary': summary_stats,
                    'audit_parameters': {
                        'include_inactive': include_inactive,
                        'violations_only': violations_only,
                        'account_id': account_id,
                        'caller_arn': caller_arn
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"IAM MFA compliance audit failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'IAM MFA compliance audit failed',
                'executionId': context.aws_request_id
            }
        }