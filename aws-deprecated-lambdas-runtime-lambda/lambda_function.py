#!/usr/bin/env python3
"""
AWS Lambda Deprecated Runtime Detector - Lambda Version
Serverless function for automated AWS Lambda runtime auditing
"""

import json
import boto3
import requests
import re
import os
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Set, Tuple, Any
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    
    logger.warning(f"Could not parse date: {date_str}")
    return datetime.max

def fetch_runtime_information() -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, str]]]:
    """
    Fetch both deprecated and supported runtime information from AWS Lambda documentation.
    Returns tuple of (deprecated_runtimes, supported_runtimes).
    """
    logger.info("Fetching latest runtime information from AWS documentation...")
    
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
                        logger.warning(f"Error parsing row: {e}")
                        continue
        
        logger.info(f"Found {len(deprecated_runtimes)} deprecated runtimes")
        logger.info(f"Found {len(supported_runtimes)} supported runtimes")
        
        return deprecated_runtimes, supported_runtimes
        
    except requests.RequestException as e:
        logger.error(f"Error fetching AWS documentation: {e}")
        return {}, {}
    except Exception as e:
        logger.error(f"Error parsing AWS documentation: {e}")
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

def get_all_regions() -> List[str]:
    """Get all AWS regions where Lambda is available."""
    return AWS_REGIONS

def scan_lambda_functions_in_region(region: str, at_risk_runtimes: Dict[str, Dict[str, str]]) -> List[Dict]:
    """
    Scan Lambda functions in a specific region for at-risk runtimes.
    """
    try:
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
            logger.warning(f"No access to Lambda in region {region}")
        else:
            logger.error(f"Error scanning region {region}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error in region {region}: {e}")
        return []

def scan_region_worker(region: str, at_risk_runtimes: Dict[str, Dict[str, str]], results_queue: Queue) -> None:
    """
    Worker function to scan a single region and put results in queue.
    """
    try:
        logger.info(f"Scanning region: {region}")
        at_risk_functions = scan_lambda_functions_in_region(region, at_risk_runtimes)
        
        if at_risk_functions:
            logger.info(f"Found {len(at_risk_functions)} functions with at-risk runtimes in {region}")
        else:
            logger.info(f"No at-risk runtimes found in {region}")
            
        results_queue.put((region, at_risk_functions))
        
    except Exception as e:
        logger.error(f"Error scanning region {region}: {e}")
        results_queue.put((region, []))

def scan_all_regions_parallel(at_risk_runtimes: Dict[str, Dict[str, str]], scan_all_regions_flag: bool = False, max_workers: int = 10) -> List[Dict]:
    """
    Scan Lambda functions across regions using parallel threading.
    """
    all_at_risk_functions = []
    
    if scan_all_regions_flag:
        logger.info("Scanning all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Scanning current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region scanning tasks
        future_to_region = {
            executor.submit(scan_lambda_functions_in_region, region, at_risk_runtimes): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                at_risk_functions = future.result()
                if at_risk_functions:
                    logger.info(f"Found {len(at_risk_functions)} functions with at-risk runtimes in {region}")
                    all_at_risk_functions.extend(at_risk_functions)
                else:
                    logger.info(f"No at-risk runtimes found in {region}")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
    
    logger.info(f"Parallel scanning complete. Total functions found: {len(all_at_risk_functions)}")
    return all_at_risk_functions

def send_security_notifications(at_risk_functions: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk Lambda runtime findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Filter for critical and high risk functions
        critical_functions = [f for f in at_risk_functions if f['urgency'] == 'CRITICAL']
        high_risk_functions = [f for f in at_risk_functions if f['urgency'] == 'HIGH']
        
        if not critical_functions and not high_risk_functions:
            logger.info("No critical or high risk Lambda runtime findings to notify")
            return
        
        # Build notification message
        subject = f"🚨 Lambda Runtime Security Alert - Account {account_id}"
        
        message_parts = [
            f"CRITICAL LAMBDA RUNTIME VULNERABILITIES DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total at-risk functions: {len(at_risk_functions)}",
            f"• Critical functions (deprecated): {len(critical_functions)}",
            f"• High risk functions (deprecating soon): {len(high_risk_functions)}",
            f""
        ]
        
        # Add critical findings details
        if critical_functions:
            message_parts.append("🔴 CRITICAL RISK FUNCTIONS (Already Deprecated Runtimes):")
            for func in critical_functions:
                message_parts.append(f"  • {func['function_name']} ({func['region']})")
                message_parts.append(f"    - Runtime: {func['runtime']} ({func['runtime_name']})")
                message_parts.append(f"    - Status: {func['status']}")
                message_parts.append(f"    - Deprecation: {func['deprecation_date']}")
                message_parts.append(f"    - Last Modified: {func['last_modified']}")
                message_parts.append(f"    - ⚠️  IMMEDIATE MIGRATION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_functions:
            message_parts.append("🟠 HIGH RISK FUNCTIONS (Deprecating Within 90 Days):")
            for func in high_risk_functions:
                message_parts.append(f"  • {func['function_name']} ({func['region']})")
                message_parts.append(f"    - Runtime: {func['runtime']} ({func['runtime_name']})")
                message_parts.append(f"    - Status: {func['status']}")
                message_parts.append(f"    - Deprecation: {func['deprecation_date']}")
                message_parts.append(f"    - Function ARN: {func['function_arn']}")
                message_parts.append(f"    - Code Size: {func['code_size']} bytes")
            message_parts.append("")
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Migrate deprecated Lambda functions to supported runtimes immediately",
            "2. Plan migration for functions deprecating within 90 days",
            "3. Update deployment pipelines to use latest runtime versions",
            "4. Test function compatibility with new runtimes",
            "5. Update Infrastructure as Code (CloudFormation/Terraform/SAM)",
            "6. Review function dependencies for runtime compatibility",
            "",
            "MIGRATION PRIORITIES:",
            "• python3.8 → python3.12 or python3.11",
            "• nodejs14.x → nodejs20.x or nodejs18.x", 
            "• java8.al2 → java21 or java17",
            "• dotnet6 → dotnet8",
            "",
            "REMEDIATION COMMANDS:",
            "# Update Lambda function runtime",
            "aws lambda update-function-configuration --function-name FUNCTION_NAME --runtime python3.12",
            "",
            "# Update SAM template",
            "# Runtime: python3.12",
            "",
            "For detailed migration guidance, see AWS Lambda Runtime Migration Guide.",
            "",
            "This alert was generated by the automated Lambda Runtime Security Audit function."
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
        logger.info(f"Notified about {len(critical_functions)} critical and {len(high_risk_functions)} high risk Lambda functions")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for deprecated runtime detection
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with execution results
    """
    try:
        logger.info("Starting AWS Lambda deprecated runtime detection")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        months_ahead = params.get('months_ahead', int(os.environ.get('MONTHS_AHEAD', '6')))
        scan_all_regions_flag = params.get('scan_all_regions', 
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        
        logger.info(f"Configuration - Months ahead: {months_ahead}, Scan all regions: {scan_all_regions_flag}, Max workers: {max_workers}")
        
        # Validate credentials and get account info
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Auditing AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Fetch runtime information
        deprecated_runtimes, supported_runtimes = fetch_runtime_information()
        
        if not deprecated_runtimes and not supported_runtimes:
            raise Exception("Could not fetch runtime information from AWS documentation")
        
        # Filter for at-risk runtimes
        at_risk_runtimes = filter_at_risk_runtimes(deprecated_runtimes, supported_runtimes, months_ahead)
        
        if not at_risk_runtimes:
            logger.info(f"No runtimes are deprecated or will be deprecated within {months_ahead} months")
            return {
                'statusCode': 200,
                'body': {
                    'message': 'Runtime analysis completed successfully',
                    'results': {
                        'at_risk_functions': [],
                        'summary': {
                            'total_functions': 0,
                            'critical_functions': 0,
                            'high_risk_functions': 0,
                            'medium_risk_functions': 0
                        },
                        'analysis_parameters': {
                            'months_ahead': months_ahead,
                            'scan_all_regions': scan_all_regions_flag,
                            'deprecated_runtimes_found': len(deprecated_runtimes),
                            'supported_runtimes_found': len(supported_runtimes)
                        }
                    },
                    'executionId': context.aws_request_id,
                    'alerts_triggered': False
                }
            }
        
        logger.info(f"At-risk runtimes to check ({len(at_risk_runtimes)}): {list(at_risk_runtimes.keys())}")
        
        # Scan for at-risk functions using parallel processing
        at_risk_functions = scan_all_regions_parallel(at_risk_runtimes, scan_all_regions_flag, max_workers)
        
        # Calculate summary statistics
        critical_functions = [f for f in at_risk_functions if f['urgency'] == 'CRITICAL']
        high_risk_functions = [f for f in at_risk_functions if f['urgency'] == 'HIGH']
        medium_risk_functions = [f for f in at_risk_functions if f['urgency'] == 'MEDIUM']
        
        # Determine response status
        status_code = 200
        alerts_triggered = False
        if critical_functions:
            status_code = 201  # Alert: Critical issues found
            alerts_triggered = True
        elif high_risk_functions:
            status_code = 201  # Alert: High risk issues found
            alerts_triggered = True
        
        # Format results
        results = {
            'message': 'Runtime analysis completed successfully',
            'results': {
                'at_risk_functions': at_risk_functions,
                'summary': {
                    'total_functions': len(at_risk_functions),
                    'critical_functions': len(critical_functions),
                    'high_risk_functions': len(high_risk_functions),
                    'medium_risk_functions': len(medium_risk_functions)
                },
                'analysis_parameters': {
                    'months_ahead': months_ahead,
                    'scan_all_regions': scan_all_regions_flag,
                    'deprecated_runtimes_found': len(deprecated_runtimes),
                    'supported_runtimes_found': len(supported_runtimes),
                    'at_risk_runtimes': list(at_risk_runtimes.keys())
                }
            },
            'executionId': context.aws_request_id,
            'alerts_triggered': alerts_triggered
        }
        
        # Log summary and send notifications if needed
        if at_risk_functions:
            if alerts_triggered:
                # Send SNS notifications for critical and high risk findings
                send_security_notifications(at_risk_functions, account_id)
            logger.warning(f"ALERT: Found {len(at_risk_functions)} Lambda functions with at-risk runtimes")
            logger.warning(f"Critical: {len(critical_functions)}, High: {len(high_risk_functions)}, Medium: {len(medium_risk_functions)}")
        else:
            logger.info("No Lambda functions with at-risk runtimes found")
        
        return {
            'statusCode': status_code,
            'body': results
        }
        
    except Exception as e:
        logger.error(f"Runtime analysis failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Runtime analysis failed',
                'executionId': context.aws_request_id
            }
        }