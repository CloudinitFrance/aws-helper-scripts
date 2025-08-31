#!/usr/bin/env python3
"""
AWS Lambda Deprecated Runtime Detector
This script dynamically fetches deprecated runtime information from AWS documentation
and scans Lambda functions to identify those that are already deprecated or will be deprecated soon.
"""

import boto3
import requests
import re
import json
import argparse
import sys
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def validate_aws_credentials(session=None):
    """Validate AWS credentials before proceeding."""
    try:
        if session:
            sts = session.client('sts')
        else:
            sts = boto3.client('sts')
        
        response = sts.get_caller_identity()
        print(f"🔐 AWS Account: {response.get('Account', 'Unknown')}")
        print(f"👤 User/Role: {response.get('Arn', 'Unknown')}")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"{Colors.RED}❌ AWS credentials not found or incomplete: {e}{Colors.RESET}")
        print("Please configure your credentials using 'aws configure' or environment variables.")
        return False
    except ClientError as e:
        print(f"{Colors.RED}❌ Error validating credentials: {e.response['Error']['Message']}{Colors.RESET}")
        return False

def parse_date(date_str: str) -> datetime:
    """Parse various date formats from AWS documentation."""
    if not date_str or date_str.strip().lower() in ['not scheduled', 'n/a', '']:
        return datetime.max  # Far future date for "not scheduled"
    
    date_str = date_str.strip()
    
    # Common date formats in AWS docs
    date_formats = [
        '%b %d, %Y',      # Dec 20, 2024
        '%B %d, %Y',      # December 20, 2024
        '%Y-%m-%d',       # 2024-12-20
        '%m/%d/%Y',       # 12/20/2024
        '%d/%m/%Y',       # 20/12/2024
    ]
    
    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    # Try to extract date with regex for partial matches
    date_match = re.search(r'(\w+)\s+(\d{1,2}),?\s+(\d{4})', date_str)
    if date_match:
        month_str, day_str, year_str = date_match.groups()
        try:
            return datetime.strptime(f"{month_str} {day_str}, {year_str}", '%B %d, %Y')
        except ValueError:
            try:
                return datetime.strptime(f"{month_str} {day_str}, {year_str}", '%b %d, %Y')
            except ValueError:
                pass
    
    print(f"⚠️  Could not parse date: {date_str}")
    return datetime.max

def fetch_runtime_information() -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, str]]]:
    """
    Fetch both deprecated and supported runtime information from AWS Lambda documentation.
    Returns tuple of (deprecated_runtimes, supported_runtimes).
    """
    print("📥 Fetching latest runtime information from AWS documentation...")
    
    try:
        url = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        deprecated_runtimes = {}
        supported_runtimes = {}
        
        # Find all tables in the document
        tables = soup.find_all('table')
        
        for table in tables:
            # Get table headers to identify table type
            headers = [th.get_text().strip().lower() for th in table.find_all('th')]
            
            # Check if this table contains runtime information
            if not (any('identifier' in h for h in headers) and any('deprecation' in h for h in headers)):
                continue
            
            # Determine if this is the deprecated or supported runtimes table
            # Look for context clues around the table
            table_context = ""
            prev_elements = []
            current = table.previous_sibling
            count = 0
            while current and count < 10:  # Look at previous 10 elements
                if hasattr(current, 'get_text'):
                    table_context = current.get_text().lower() + " " + table_context
                current = current.previous_sibling
                count += 1
            
            is_deprecated_table = 'deprecated' in table_context and 'following' in table_context
            
            # Parse the table rows
            rows = table.find_all('tr')[1:]  # Skip header row
            
            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 4:  # Ensure we have enough columns
                    try:
                        name = cells[0].get_text().strip()
                        identifier = cells[1].get_text().strip()
                        deprecation_date = cells[3].get_text().strip()
                        
                        # Clean up identifier
                        identifier = re.sub(r'[`\n\r\t]', '', identifier).strip()
                        
                        # Skip empty identifiers or header rows
                        if not identifier or identifier.lower() in ['identifier', 'name']:
                            continue
                        
                        runtime_info = {
                            'name': name,
                            'deprecation_date': deprecation_date,
                            'parsed_date': parse_date(deprecation_date)
                        }
                        
                        if is_deprecated_table:
                            deprecated_runtimes[identifier] = runtime_info
                        else:
                            supported_runtimes[identifier] = runtime_info
                            
                    except Exception as e:
                        print(f"⚠️  Error parsing row: {e}")
                        continue
        
        print(f"✅ Found {len(deprecated_runtimes)} deprecated runtimes")
        print(f"✅ Found {len(supported_runtimes)} supported runtimes")
        
        return deprecated_runtimes, supported_runtimes
        
    except requests.RequestException as e:
        print(f"❌ Error fetching AWS documentation: {e}")
        return {}, {}
    except Exception as e:
        print(f"❌ Error parsing AWS documentation: {e}")
        return {}, {}

def filter_at_risk_runtimes(deprecated_runtimes: Dict, supported_runtimes: Dict, months_ahead: int = 6) -> Dict[str, Dict[str, str]]:
    """
    Filter runtimes that are already deprecated or will be deprecated within the specified months.
    """
    current_date = datetime.now()
    cutoff_date = current_date + timedelta(days=months_ahead * 30)  # Approximate months
    
    at_risk_runtimes = {}
    
    # All deprecated runtimes are at risk
    for runtime_id, info in deprecated_runtimes.items():
        info['status'] = 'DEPRECATED'
        info['urgency'] = 'CRITICAL'
        at_risk_runtimes[runtime_id] = info
    
    # Check supported runtimes that will be deprecated soon
    for runtime_id, info in supported_runtimes.items():
        deprecation_date = info['parsed_date']
        
        if deprecation_date <= current_date:
            # Already deprecated but might be in supported table due to grace period
            info['status'] = 'DEPRECATED'
            info['urgency'] = 'CRITICAL'
            at_risk_runtimes[runtime_id] = info
        elif deprecation_date <= cutoff_date:
            # Will be deprecated within the specified timeframe
            days_until = (deprecation_date - current_date).days
            info['status'] = f'DEPRECATING_IN_{days_until}_DAYS'
            info['urgency'] = 'HIGH' if days_until <= 90 else 'MEDIUM'
            at_risk_runtimes[runtime_id] = info
    
    return at_risk_runtimes

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

def get_all_regions(session=None) -> List[str]:
    """Get all AWS regions where Lambda is available."""
    return AWS_REGIONS

def scan_lambda_functions_in_region(region: str, at_risk_runtimes: Dict[str, Dict[str, str]], session=None) -> List[Dict]:
    """
    Scan Lambda functions in a specific region for at-risk runtimes.
    """
    try:
        if session:
            lambda_client = session.client('lambda', region_name=region)
        else:
            lambda_client = boto3.client('lambda', region_name=region)
        at_risk_functions = []
        
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                runtime = function.get('Runtime', 'N/A')
                
                if runtime in at_risk_runtimes:
                    runtime_info = at_risk_runtimes[runtime]
                    
                    at_risk_functions.append({
                        'region': region,
                        'function_name': function_name,
                        'function_arn': function['FunctionArn'],
                        'runtime': runtime,
                        'runtime_name': runtime_info['name'],
                        'deprecation_date': runtime_info['deprecation_date'],
                        'status': runtime_info['status'],
                        'urgency': runtime_info['urgency'],
                        'last_modified': function['LastModified'],
                        'code_size': function['CodeSize'],
                        'memory_size': function['MemorySize'],
                        'timeout': function['Timeout']
                    })
        
        return at_risk_functions
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"⚠️  No access to Lambda in region {region}")
        else:
            print(f"❌ Error scanning region {region}: {e}")
        return []
    except Exception as e:
        print(f"❌ Unexpected error in region {region}: {e}")
        return []

def scan_all_regions(at_risk_runtimes: Dict[str, Dict[str, str]], scan_all_regions_flag: bool = False, session=None, parallel: bool = True, max_workers: int = 5) -> List[Dict]:
    """
    Scan Lambda functions across regions with optional parallel processing.
    
    Args:
        at_risk_runtimes: Dictionary of at-risk runtime information
        scan_all_regions_flag: Whether to scan all regions or just current
        session: AWS session to use
        parallel: Whether to use parallel processing
        max_workers: Maximum number of worker threads for parallel processing
    
    Returns:
        List of at-risk Lambda functions
    """
    all_at_risk_functions = []
    
    if scan_all_regions_flag:
        print("🌍 Scanning all AWS regions...")
        regions = get_all_regions(session)
    else:
        current_region = (session.region_name if session else boto3.Session().region_name) or 'us-east-1'
        print(f"🏠 Scanning current region: {current_region}")
        regions = [current_region]
    
    if parallel and len(regions) > 1:
        print(f"🚀 Using parallel processing with {max_workers} workers for better performance...")
        all_at_risk_functions = scan_regions_parallel(regions, at_risk_runtimes, session, max_workers)
    else:
        all_at_risk_functions = scan_regions_sequential(regions, at_risk_runtimes, session)
    
    return all_at_risk_functions

def scan_regions_parallel(regions: List[str], at_risk_runtimes: Dict[str, Dict[str, str]], session=None, max_workers: int = 5) -> List[Dict]:
    """
    Scan regions in parallel using ThreadPoolExecutor.
    
    Args:
        regions: List of AWS regions to scan
        at_risk_runtimes: Dictionary of at-risk runtime information
        session: AWS session to use
        max_workers: Maximum number of worker threads
    
    Returns:
        List of at-risk Lambda functions from all regions
    """
    all_at_risk_functions = []
    print_lock = threading.Lock()
    
    def scan_region_with_logging(region):
        """Scan a single region with thread-safe logging."""
        try:
            with print_lock:
                print(f"🔍 Scanning region: {region}")
            
            at_risk_functions = scan_lambda_functions_in_region(region, at_risk_runtimes, session)
            
            with print_lock:
                if at_risk_functions:
                    print(f"  ⚠️  Found {len(at_risk_functions)} functions with at-risk runtimes in {region}")
                else:
                    print(f"  ✅ No at-risk runtimes found in {region}")
            
            return at_risk_functions
            
        except Exception as e:
            with print_lock:
                print(f"❌ Error scanning region {region}: {e}")
            return []
    
    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region scanning tasks
        future_to_region = {
            executor.submit(scan_region_with_logging, region): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_functions = future.result()
                all_at_risk_functions.extend(region_functions)
            except Exception as e:
                with print_lock:
                    print(f"❌ Unexpected error processing results for region {region}: {e}")
    
    return all_at_risk_functions

def scan_regions_sequential(regions: List[str], at_risk_runtimes: Dict[str, Dict[str, str]], session=None) -> List[Dict]:
    """
    Scan regions sequentially (original behavior).
    
    Args:
        regions: List of AWS regions to scan
        at_risk_runtimes: Dictionary of at-risk runtime information
        session: AWS session to use
    
    Returns:
        List of at-risk Lambda functions from all regions
    """
    all_at_risk_functions = []
    
    for region in regions:
        print(f"🔍 Scanning region: {region}")
        at_risk_functions = scan_lambda_functions_in_region(region, at_risk_runtimes, session)
        
        if at_risk_functions:
            print(f"  ⚠️  Found {len(at_risk_functions)} functions with at-risk runtimes")
            all_at_risk_functions.extend(at_risk_functions)
        else:
            print(f"  ✅ No at-risk runtimes found")
    
    return all_at_risk_functions

def build_sns_subject(critical_count: int, high_risk_count: int, medium_risk_count: int, account_id: str) -> str:
    """Build SNS subject line based on findings severity."""
    if critical_count > 0:
        return f"CRITICAL: {critical_count} Lambda functions with deprecated runtimes - Account {account_id}"
    elif high_risk_count > 0:
        return f"HIGH RISK: {high_risk_count} Lambda functions with soon-to-be-deprecated runtimes - Account {account_id}"
    else:
        return f"MEDIUM RISK: {medium_risk_count} Lambda functions require runtime updates - Account {account_id}"

def build_sns_message_header(account_id: str, timestamp: str, total_count: int, critical_count: int, high_risk_count: int, medium_risk_count: int) -> List[str]:
    """Build the header section of the SNS message."""
    return [
        "AWS Lambda Runtime Security Alert",
        f"Account: {account_id}",
        f"Timestamp: {timestamp}",
        "",
        "SUMMARY:",
        f"• Total functions affected: {total_count}",
        f"• Critical (already deprecated): {critical_count}",
        f"• High risk (deprecating within 90 days): {high_risk_count}",
        f"• Medium risk (deprecating within timeframe): {medium_risk_count}",
        ""
    ]

def build_critical_findings_section(critical_functions: List[Dict]) -> List[str]:
    """Build the critical findings section of the SNS message."""
    if not critical_functions:
        return []
    
    section = ["🔴 CRITICAL - DEPRECATED RUNTIMES:"]
    
    # Limit to first 10 for message size
    for func in critical_functions[:10]:
        section.append(f"  • {func['function_name']} ({func['region']}) - Runtime: {func['runtime']}")
        section.append(f"    Deprecated: {func['deprecation_date']}")
    
    if len(critical_functions) > 10:
        section.append(f"    ... and {len(critical_functions) - 10} more critical functions")
    
    section.append("")
    return section

def build_high_risk_section(high_risk_functions: List[Dict]) -> List[str]:
    """Build the high risk findings section of the SNS message."""
    if not high_risk_functions:
        return []
    
    section = ["🟠 HIGH RISK - SOON TO BE DEPRECATED:"]
    
    # Limit to first 10 for message size
    for func in high_risk_functions[:10]:
        section.append(f"  • {func['function_name']} ({func['region']}) - Runtime: {func['runtime']}")
        section.append(f"    Deprecating: {func['deprecation_date']}")
    
    if len(high_risk_functions) > 10:
        section.append(f"    ... and {len(high_risk_functions) - 10} more high-risk functions")
    
    section.append("")
    return section

def build_remediation_section() -> List[str]:
    """Build the remediation recommendations section of the SNS message."""
    return [
        "IMMEDIATE ACTIONS REQUIRED:",
        "1. Update Lambda function runtimes to supported versions",
        "2. Test functions thoroughly after runtime updates", 
        "3. Update deployment automation to use current runtimes",
        "4. Schedule regular runtime compliance audits",
        "",
        "RUNTIME UPGRADE RECOMMENDATIONS:",
        "• Python 3.6/3.7/3.8 → Python 3.12",
        "• Node.js 12.x/14.x/16.x → Node.js 20.x",
        "• Java 8 → Java 21",
        "• .NET Core 2.1/3.1 → .NET 8",
        "",
        "For detailed function analysis, run the Lambda Runtime Detector manually.",
        "",
        "This alert was generated by the AWS Lambda Deprecated Runtime Detector CLI."
    ]

def build_sns_alert_message(at_risk_functions: List[Dict], account_id: str) -> tuple[str, str]:
    """
    Build complete SNS alert message and subject.
    
    Args:
        at_risk_functions: List of functions with deprecated runtimes
        account_id: AWS account ID for context
    
    Returns:
        Tuple of (subject, message)
    """
    # Categorize findings by urgency
    critical_functions = [f for f in at_risk_functions if f['urgency'] == 'CRITICAL']
    high_risk_functions = [f for f in at_risk_functions if f['urgency'] == 'HIGH']
    medium_risk_functions = [f for f in at_risk_functions if f['urgency'] == 'MEDIUM']
    
    # Get current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Build subject
    subject = build_sns_subject(
        len(critical_functions), 
        len(high_risk_functions), 
        len(medium_risk_functions), 
        account_id
    )
    
    # Build message sections
    message_parts = []
    
    # Header section
    message_parts.extend(build_sns_message_header(
        account_id, timestamp, len(at_risk_functions),
        len(critical_functions), len(high_risk_functions), len(medium_risk_functions)
    ))
    
    # Critical findings section
    message_parts.extend(build_critical_findings_section(critical_functions))
    
    # High risk findings section
    message_parts.extend(build_high_risk_section(high_risk_functions))
    
    # Remediation section
    message_parts.extend(build_remediation_section())
    
    # Join all parts
    message = "\n".join(message_parts)
    
    return subject, message

def send_sns_alert(at_risk_functions: List[Dict], sns_topic_arn: str, account_id: str = "Unknown", session=None):
    """
    Send SNS alert for deprecated runtime findings.
    
    Args:
        at_risk_functions: List of functions with deprecated runtimes
        sns_topic_arn: ARN of SNS topic to send alert to
        account_id: AWS account ID for context
        session: AWS session to use
    """
    if not sns_topic_arn or not at_risk_functions:
        return
    
    try:
        # Create SNS client
        if session:
            sns_client = session.client('sns')
        else:
            sns_client = boto3.client('sns')
        
        # Build message and subject
        subject, message = build_sns_alert_message(at_risk_functions, account_id)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        # Get counts for logging
        critical_count = len([f for f in at_risk_functions if f['urgency'] == 'CRITICAL'])
        high_risk_count = len([f for f in at_risk_functions if f['urgency'] == 'HIGH'])
        
        message_id = response.get('MessageId', 'Unknown')
        print(f"📧 SNS alert sent successfully. MessageId: {message_id}")
        print(f"   Topic: {sns_topic_arn}")
        print(f"   Summary: {critical_count} critical, {high_risk_count} high-risk functions")
        
    except Exception as e:
        print(f"{Colors.RED}❌ Failed to send SNS alert: {str(e)}{Colors.RESET}")
        print(f"   Topic ARN: {sns_topic_arn}")
        # Don't raise exception to avoid failing the main analysis process

def print_summary(at_risk_functions: List[Dict]):
    """Print a summary of findings with color coding."""
    if not at_risk_functions:
        print(f"\n{Colors.GREEN}🎉 Excellent! No Lambda functions with deprecated or soon-to-be-deprecated runtimes found.{Colors.RESET}")
        return
    
    print(f"\n{Colors.RED}{Colors.BOLD}📊 CRITICAL ALERT: Found {len(at_risk_functions)} Lambda functions using deprecated or soon-to-be-deprecated runtimes{Colors.RESET}")
    print("=" * 100)
    
    # Group by runtime and sort by urgency
    runtime_groups = {}
    for func in at_risk_functions:
        runtime = func['runtime']
        if runtime not in runtime_groups:
            runtime_groups[runtime] = []
        runtime_groups[runtime].append(func)
    
    # Sort by urgency (CRITICAL first, then HIGH, then MEDIUM)
    urgency_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    sorted_runtimes = sorted(runtime_groups.items(), 
                           key=lambda x: urgency_order.get(x[1][0]['urgency'], 3))
    
    for runtime, functions in sorted_runtimes:
        runtime_name = functions[0]['runtime_name']
        deprecation_date = functions[0]['deprecation_date']
        status = functions[0]['status']
        urgency = functions[0]['urgency']
        
        # Color coding based on urgency
        if urgency == 'CRITICAL':
            color = Colors.RED
            emoji = "🚨"
        elif urgency == 'HIGH':
            color = Colors.YELLOW
            emoji = "⚠️"
        else:
            color = Colors.MAGENTA
            emoji = "📅"
        
        print(f"\n{color}{emoji} Runtime: {runtime_name} ({runtime}) - Deprecated: {deprecation_date}{Colors.RESET}")
        print(f"{color}   Status: {status.replace('_', ' ')}{Colors.RESET}")
        print(f"{color}   Functions affected: {len(functions)}{Colors.RESET}")
        
        for func in functions:
            print(f"{color}   • {func['function_name']} in {func['region']}{Colors.RESET}")
            print(f"     ARN: {func['function_arn']}")
            print(f"     Last Modified: {func['last_modified']}")

def save_to_json(at_risk_functions: List[Dict], filename: str = "deprecated_lambda_functions.json"):
    """Save results to JSON file."""
    if at_risk_functions:
        with open(filename, 'w') as f:
            json.dump(at_risk_functions, f, indent=2, default=str)
        print(f"\n💾 Results saved to {filename}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="AWS Lambda Deprecated Runtime Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic scan with interactive prompts
  ./detect_outdated_lambda_runtimes_cli.py

  # Non-interactive scan with specific parameters and parallel processing
  ./detect_outdated_lambda_runtimes_cli.py --months 12 --all-regions --save-json --max-workers 10

  # Use specific AWS profile with SNS alerting  
  ./detect_outdated_lambda_runtimes_cli.py --profile production --months 6 --sns-topic arn:aws:sns:us-east-1:123456789012:lambda-alerts

  # Quick scan of current region only (no parallel processing needed)
  ./detect_outdated_lambda_runtimes_cli.py --months 3 --no-interactive

  # Scan all regions sequentially (disable parallel processing)
  ./detect_outdated_lambda_runtimes_cli.py --all-regions --no-parallel

  # Production scan with SNS alerts and optimized performance
  ./detect_outdated_lambda_runtimes_cli.py --profile prod --all-regions --sns-topic arn:aws:sns:us-east-1:123456789012:security-alerts --max-workers 15 --save-json

ANALYSIS INCLUDES:
- Runtime deprecation status and dates
- Functions using deprecated or soon-to-be-deprecated runtimes
- Multi-region support for comprehensive scanning
- Color-coded urgency levels (Critical, High, Medium)
- JSON export for integration with other tools
"""
    )
    parser.add_argument(
        '--profile', type=str,
        help='AWS profile to use for credentials'
    )
    parser.add_argument(
        '--months', type=int, default=6,
        help='Check for runtimes deprecated or deprecating within N months (default: 6)'
    )
    parser.add_argument(
        '--all-regions', action='store_true',
        help='Scan all AWS regions (default: current region only)'
    )
    parser.add_argument(
        '--save-json', action='store_true',
        help='Automatically save results to JSON file'
    )
    parser.add_argument(
        '--no-interactive', action='store_true',
        help='Run in non-interactive mode with provided parameters'
    )
    parser.add_argument(
        '--output', type=str, default='deprecated_lambda_functions.json',
        help='Output JSON file name (default: deprecated_lambda_functions.json)'
    )
    parser.add_argument(
        '--sns-topic', type=str,
        help='SNS topic ARN for sending alerts (optional - if not provided, no SNS alerts will be sent)'
    )
    parser.add_argument(
        '--no-parallel', action='store_true',
        help='Disable parallel processing and scan regions sequentially'
    )
    parser.add_argument(
        '--max-workers', type=int, default=5,
        help='Maximum number of worker threads for parallel processing (default: 5, max: 20)'
    )
    
    args = parser.parse_args()
    
    # Validate max_workers
    if args.max_workers < 1:
        args.max_workers = 1
    elif args.max_workers > 20:
        args.max_workers = 20
    
    print(f"{Colors.CYAN}{Colors.BOLD}🚀 AWS Lambda Deprecated Runtime Detector{Colors.RESET}")
    print("=" * 60)
    
    # Create AWS session with profile if specified
    session = None
    if args.profile:
        try:
            session = boto3.Session(profile_name=args.profile)
            print(f"Using AWS profile: {args.profile}")
        except ProfileNotFound:
            print(f"{Colors.RED}❌ AWS profile '{args.profile}' not found.{Colors.RESET}")
            print("Available profiles can be listed with: aws configure list-profiles")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}❌ Error loading AWS profile '{args.profile}': {e}{Colors.RESET}")
            sys.exit(1)
    
    # Validate credentials
    if not validate_aws_credentials(session):
        sys.exit(1)
    
    # Fetch runtime information
    deprecated_runtimes, supported_runtimes = fetch_runtime_information()
    
    if not deprecated_runtimes and not supported_runtimes:
        print(f"{Colors.RED}❌ Could not fetch runtime information. Exiting.{Colors.RESET}")
        sys.exit(1)
    
    # Get time window preference
    months_ahead = args.months
    if not args.no_interactive and args.months == 6:  # Only ask if default wasn't changed
        try:
            months_input = input(f"\n❓ Check for runtimes deprecated or deprecating within how many months? (default: {months_ahead}): ").strip()
            months_ahead = int(months_input) if months_input else months_ahead
        except ValueError:
            pass
    
    # Filter for at-risk runtimes
    at_risk_runtimes = filter_at_risk_runtimes(deprecated_runtimes, supported_runtimes, months_ahead)
    
    if not at_risk_runtimes:
        print(f"\n{Colors.GREEN}✅ No runtimes are deprecated or will be deprecated within {months_ahead} months.{Colors.RESET}")
        sys.exit(0)
    
    print(f"\n📋 At-risk runtimes to check ({len(at_risk_runtimes)}): {list(at_risk_runtimes.keys())}")
    
    # Determine scanning scope
    scan_all_regions_flag = args.all_regions
    if not args.no_interactive and not args.all_regions:
        scan_all_regions_flag = input("\n❓ Scan all regions? (y/N): ").lower().strip() == 'y'
    
    # Scan for at-risk functions
    use_parallel = not args.no_parallel and scan_all_regions_flag  # Only use parallel for multi-region scans
    at_risk_functions = scan_all_regions(
        at_risk_runtimes, 
        scan_all_regions_flag, 
        session, 
        parallel=use_parallel, 
        max_workers=args.max_workers
    )
    
    # Print results
    print_summary(at_risk_functions)
    
    # Send SNS alert if topic is provided and findings exist
    if args.sns_topic and at_risk_functions:
        try:
            # Get account ID for context
            account_id = "Unknown"
            try:
                if session:
                    sts = session.client('sts')
                else:
                    sts = boto3.client('sts')
                account_id = sts.get_caller_identity().get('Account', 'Unknown')
            except Exception:
                pass  # Use "Unknown" if we can't get account ID
            
            print(f"\n📧 Sending SNS alert to: {args.sns_topic}")
            send_sns_alert(at_risk_functions, args.sns_topic, account_id, session)
            
        except Exception as e:
            print(f"{Colors.RED}❌ Failed to send SNS alert: {str(e)}{Colors.RESET}")
    elif args.sns_topic and not at_risk_functions:
        print(f"\n📧 No SNS alert sent - no deprecated runtimes found")
    
    # Save to file if results found
    if at_risk_functions:
        save_file = args.save_json
        if not args.no_interactive and not args.save_json:
            save_choice = input(f"\n❓ Save results to JSON file? (Y/n): ").lower().strip()
            save_file = save_choice != 'n'
        
        if save_file:
            save_to_json(at_risk_functions, args.output)
    
    print(f"\n{Colors.GREEN}✨ Scan complete!{Colors.RESET}")
    
    # Return appropriate exit code for automation
    if at_risk_functions:
        critical_functions = [f for f in at_risk_functions if f['urgency'] == 'CRITICAL']
        high_risk_functions = [f for f in at_risk_functions if f['urgency'] == 'HIGH']
        
        if critical_functions:
            print(f"\n{Colors.RED}🚨 CRITICAL: Found {len(critical_functions)} functions with deprecated runtimes!{Colors.RESET}")
            sys.exit(2)
        elif high_risk_functions:
            print(f"\n{Colors.YELLOW}⚠️  HIGH RISK: Found {len(high_risk_functions)} functions with soon-to-be-deprecated runtimes!{Colors.RESET}")
            sys.exit(1)
        else:
            print(f"\n{Colors.MAGENTA}📅 MEDIUM RISK: Found {len(at_risk_functions)} functions requiring attention.{Colors.RESET}")
            sys.exit(0)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
