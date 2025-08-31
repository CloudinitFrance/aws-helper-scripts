#!/usr/bin/env python3
"""
List IAM users with console access but no MFA device enabled.

This script checks all users in the AWS account and identifies security risks
from users who can access the console without multi-factor authentication.
"""

import boto3
import argparse
import sys
import csv
import json
from datetime import datetime, timezone
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
        print(f"Warning: Could not get activity info for {username}: {e}")
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
        
        # Skip groups and policies for now - focus on MFA compliance
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
        print(f"Error checking MFA status for {username}: {str(e)}")
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
        print(f"Error retrieving users: {e.response['Error']['Message']}")
        return []

def export_to_csv(user_data: List[Dict], filename: str):
    """Export user data to CSV format."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'UserName', 'HasConsoleAccess', 'HasMFA', 'RiskLevel', 
            'CreateDate', 'LastActivity', 'Groups', 'AttachedPolicies', 'MFADevices'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for user in user_data:
            row = user.copy()
            # Convert lists to strings for CSV
            row['Groups'] = ', '.join(user.get('Groups', []))
            row['AttachedPolicies'] = ', '.join(user.get('AttachedPolicies', []))
            row['MFADevices'] = ', '.join([d['SerialNumber'] for d in user.get('MFADevices', [])])
            row['CreateDate'] = user.get('CreateDate', '').strftime('%Y-%m-%d') if user.get('CreateDate') else ''
            row['LastActivity'] = user.get('LastActivity', '').strftime('%Y-%m-%d') if user.get('LastActivity') else 'Never'
            writer.writerow(row)

def export_to_json(user_data: List[Dict], filename: str):
    """Export user data to JSON format."""
    # Convert datetime objects to strings for JSON serialization
    json_data = []
    for user in user_data:
        user_copy = user.copy()
        if user_copy.get('CreateDate'):
            user_copy['CreateDate'] = user_copy['CreateDate'].isoformat()
        if user_copy.get('LastActivity'):
            user_copy['LastActivity'] = user_copy['LastActivity'].isoformat()
        for device in user_copy.get('MFADevices', []):
            if device.get('EnableDate'):
                device['EnableDate'] = device['EnableDate'].isoformat()
        json_data.append(user_copy)
    
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(json_data, jsonfile, indent=2, default=str)

def print_summary_report(user_data: List[Dict]):
    """Print a comprehensive summary report."""
    total_users = len(user_data)
    console_users = [u for u in user_data if u['HasConsoleAccess']]
    mfa_users = [u for u in user_data if u['HasMFA']]
    console_no_mfa = [u for u in user_data if u['HasConsoleAccess'] and not u['HasMFA']]
    
    # Risk analysis
    critical_risk = [u for u in user_data if u['RiskLevel'] == 'Critical']
    high_risk = [u for u in user_data if u['RiskLevel'] == 'High']
    
    print(f"\n{'='*60}")
    print("IAM MFA COMPLIANCE SUMMARY")
    print(f"{'='*60}")
    print(f"Total IAM Users: {total_users}")
    print(f"Users with Console Access: {len(console_users)}")
    print(f"Users with MFA Enabled: {len(mfa_users)}")
    print(f"Console Users WITHOUT MFA: {len(console_no_mfa)}")
    print(f"Critical Risk Users: {len(critical_risk)}")
    print(f"High Risk Users: {len(high_risk)}")
    
    if console_no_mfa:
        compliance_rate = ((len(console_users) - len(console_no_mfa)) / len(console_users)) * 100
        print(f"MFA Compliance Rate: {compliance_rate:.1f}%")
        
        print(f"\n{'='*60}")
        print("USERS REQUIRING IMMEDIATE ATTENTION")
        print(f"{'='*60}")
        
        print(f"\n{'User Name':25} {'Risk Level':12} {'Groups':20} {'Last Activity'}")
        print("-" * 80)
        
        # Sort by risk level (Critical first)
        sorted_users = sorted(console_no_mfa, key=lambda x: (x['RiskLevel'] != 'Critical', x['RiskLevel'] != 'High'))
        
        for user in sorted_users:
            groups = ', '.join(user.get('Groups', [])[:2])  # Show first 2 groups
            if len(user.get('Groups', [])) > 2:
                groups += '...'
            
            last_activity = 'Never'
            if user.get('LastActivity'):
                days_ago = (datetime.now(timezone.utc) - user['LastActivity']).days
                last_activity = f"{days_ago}d ago"
            
            risk_indicator = "🔴" if user['RiskLevel'] == 'Critical' else "🟡"
            
            print(f"{user['UserName']:25} {risk_indicator} {user['RiskLevel']:10} {groups:20} {last_activity}")
    else:
        print(f"\n✅ All console users have MFA enabled!")
    
    print(f"\n{'='*60}")

def main():
    parser = argparse.ArgumentParser(
        description="Check IAM users for MFA compliance with comprehensive analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic MFA compliance check
  ./check_iam_users_no_mfa.py
  
  # Use specific AWS profile
  ./check_iam_users_no_mfa.py --profile production
  
  # Export detailed report to CSV with profile
  ./check_iam_users_no_mfa.py --profile staging --export-csv mfa_report.csv
  
  # Export to JSON with full details
  ./check_iam_users_no_mfa.py --export-json mfa_report.json
  
  # Show only non-compliant users for production environment
  ./check_iam_users_no_mfa.py --profile production --show-violations-only

NOTES:
- IAM is a global service, so region selection doesn't apply
- This script requires 'iam:ListUsers', 'iam:GetUser', 'iam:ListMFADevices', 
  'iam:GetLoginProfile', 'iam:ListAccessKeys', 'iam:GetAccessKeyLastUsed',
  'iam:GetGroupsForUser', 'iam:ListAttachedUserPolicies' permissions
"""
    )
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--show-violations-only', action='store_true',
                       help='Show only users without MFA (security violations)')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--include-inactive', action='store_true',
                       help='Include users who have never logged in')
    
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
        # Create IAM client
        if session:
            iam_client = session.client('iam')
        else:
            iam_client = boto3.client('iam')

        print("Analyzing IAM users for MFA compliance...")
        print("Note: IAM is a global service - checking all users in the account")
        print("=" * 60)

        # Get all users with pagination
        print("Retrieving IAM users...")
        users = get_all_users_with_pagination(iam_client)
        
        if not users:
            print("No IAM users found.")
            return

        print(f"Found {len(users)} IAM users. Analyzing MFA status...")

        # Analyze each user
        user_data = []
        for i, user in enumerate(users):
            username = user['UserName']
            print(f"Analyzing {i+1}/{len(users)}: {username}", end=" ... ")
            
            try:
                user_info = check_user_mfa_status(iam_client, user)
                user_data.append(user_info)
                
                if user_info.get('Error'):
                    print(f"❌ Error: {user_info['Error']}")
                elif user_info['HasConsoleAccess'] and not user_info['HasMFA']:
                    risk = user_info['RiskLevel']
                    print(f"⚠️  NO MFA ({risk} risk)")
                elif user_info['HasConsoleAccess']:
                    print("✅ MFA enabled")
                else:
                    print("📝 No console access")
            except Exception as e:
                print(f"❌ Unexpected error: {str(e)}")
                # Create a minimal user info entry for failed users
                user_data.append({
                    'UserName': username,
                    'HasConsoleAccess': False,
                    'HasMFA': False,
                    'Error': str(e),
                    'RiskLevel': 'Unknown'
                })

        # Filter results if requested
        display_users = user_data
        if args.show_violations_only:
            display_users = [u for u in user_data if u['HasConsoleAccess'] and not u['HasMFA']]

        if not args.include_inactive:
            display_users = [u for u in display_users if u.get('LastActivity')]

        # Print summary report
        print_summary_report(user_data)

        # Export to files if requested
        if args.export_csv:
            export_to_csv(user_data, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(user_data, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        # Return appropriate exit code for automation
        violations = [u for u in user_data if u['HasConsoleAccess'] and not u['HasMFA']]
        if violations:
            print(f"\n⚠️  Found {len(violations)} MFA compliance violations!")
            sys.exit(1)
        else:
            print(f"\n✅ All users are MFA compliant!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access IAM. Required permissions:")
            print("- iam:ListUsers")
            print("- iam:GetUser") 
            print("- iam:ListMFADevices")
            print("- iam:GetLoginProfile")
            print("- iam:ListAccessKeys")
            print("- iam:GetAccessKeyLastUsed")
            print("- iam:GetGroupsForUser")
            print("- iam:ListAttachedUserPolicies")
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

