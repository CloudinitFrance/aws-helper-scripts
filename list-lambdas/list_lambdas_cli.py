#!/usr/bin/env python3
"""
Comprehensive AWS Lambda functions inventory across regions with detailed analysis.

This script provides a complete overview of Lambda functions including runtime analysis,
security configuration, performance metrics, and cost optimization recommendations.
"""

import boto3
import argparse
import sys
import json
import csv
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional

def validate_aws_credentials():
    """Validate AWS credentials before proceeding."""
    try:
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

def get_available_regions(lambda_client) -> List[str]:
    """Get list of available Lambda regions."""
    return AWS_REGIONS

def get_function_configuration_details(lambda_client, function_name: str) -> Dict:
    """Get detailed configuration for a Lambda function."""
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        function_config = response['Configuration']
        
        # Get additional details
        tags = {}
        try:
            tags_response = lambda_client.list_tags(Resource=function_config['FunctionArn'])
            tags = tags_response.get('Tags', {})
        except ClientError:
            pass
        
        # Get policy information
        has_resource_policy = False
        try:
            lambda_client.get_policy(FunctionName=function_name)
            has_resource_policy = True
        except ClientError:
            pass
        
        return {
            'Tags': tags,
            'HasResourcePolicy': has_resource_policy,
            'CodeSha256': function_config.get('CodeSha256', ''),
            'ReservedConcurrency': function_config.get('ReservedConcurrencyExecutions'),
            'Environment': function_config.get('Environment', {}).get('Variables', {}),
            'KMSKeyArn': function_config.get('KMSKeyArn', ''),
            'TracingMode': function_config.get('TracingConfig', {}).get('Mode', 'PassThrough'),
            'Layers': function_config.get('Layers', [])
        }
    except ClientError as e:
        print(f"Warning: Could not get details for {function_name}: {e.response['Error']['Message']}")
        return {}

def analyze_lambda_function(function: Dict, region: str, lambda_client) -> Dict:
    """Comprehensive analysis of a Lambda function."""
    function_analysis = {
        'Region': region,
        'FunctionName': function['FunctionName'],
        'Runtime': function['Runtime'],
        'MemorySize': function['MemorySize'],
        'Timeout': function['Timeout'],
        'CodeSize': function['CodeSize'],
        'LastModified': function['LastModified'],
        'FunctionArn': function['FunctionArn'],
        'Role': function['Role'],
        'Handler': function['Handler'],
        'Description': function.get('Description', ''),
        'VpcConfig': function.get('VpcConfig', {}),
        'DeadLetterConfig': function.get('DeadLetterConfig', {}),
        'State': function.get('State', 'Active'),
        'StateReason': function.get('StateReason', ''),
        'PackageType': function.get('PackageType', 'Zip'),
        'Architecture': function.get('Architectures', ['x86_64'])[0],
        'RuntimeDeprecated': False,
        'HighMemoryUsage': False,
        'LongTimeout': False,
        'SecurityIssues': [],
        'OptimizationOpportunities': [],
        'CostOptimizationLevel': 'Optimized'
    }
    
    # Get additional details
    additional_details = get_function_configuration_details(lambda_client, function['FunctionName'])
    function_analysis.update(additional_details)
    
    # Runtime deprecation analysis
    deprecated_runtimes = [
        'python2.7', 'python3.6', 'python3.7',
        'nodejs8.10', 'nodejs10.x', 'nodejs12.x',
        'ruby2.5', 'ruby2.7',
        'dotnetcore2.1', 'dotnetcore3.1',
        'go1.x'
    ]
    if function['Runtime'] in deprecated_runtimes:
        function_analysis['RuntimeDeprecated'] = True
        function_analysis['SecurityIssues'].append(f"Deprecated runtime: {function['Runtime']}")
    
    # Memory and timeout analysis
    if function['MemorySize'] >= 2048:
        function_analysis['HighMemoryUsage'] = True
        function_analysis['OptimizationOpportunities'].append("High memory allocation - consider optimization")
    
    if function['Timeout'] >= 300:  # 5 minutes
        function_analysis['LongTimeout'] = True
        function_analysis['OptimizationOpportunities'].append("Long timeout - consider optimization")
    
    # Security analysis
    if not function_analysis.get('KMSKeyArn'):
        function_analysis['SecurityIssues'].append("No customer-managed KMS key for encryption")
    
    if function_analysis.get('TracingMode') == 'PassThrough':
        function_analysis['OptimizationOpportunities'].append("X-Ray tracing not enabled")
    
    if not function_analysis.get('VpcConfig', {}).get('VpcId'):
        if 'database' in function['FunctionName'].lower() or 'rds' in function['FunctionName'].lower():
            function_analysis['SecurityIssues'].append("Database-related function not in VPC")
    
    # Environment variables check
    env_vars = function_analysis.get('Environment', {})
    sensitive_keywords = ['password', 'key', 'secret', 'token', 'credential']
    for var_name in env_vars.keys():
        if any(keyword in var_name.lower() for keyword in sensitive_keywords):
            function_analysis['SecurityIssues'].append(f"Potential secret in environment variable: {var_name}")
    
    # Cost optimization assessment
    issues_count = len(function_analysis['SecurityIssues']) + len(function_analysis['OptimizationOpportunities'])
    if issues_count >= 3:
        function_analysis['CostOptimizationLevel'] = 'Needs Review'
    elif issues_count >= 1:
        function_analysis['CostOptimizationLevel'] = 'Minor Issues'
    
    # Age analysis
    try:
        last_modified = datetime.fromisoformat(function['LastModified'].replace('Z', '+00:00'))
        days_old = (datetime.now(timezone.utc) - last_modified).days
        function_analysis['DaysOld'] = days_old
        
        if days_old > 365:
            function_analysis['OptimizationOpportunities'].append("Function not updated in over a year")
    except Exception:
        function_analysis['DaysOld'] = 0
    
    return function_analysis

def list_lambda_functions_in_region(region: str, session=None) -> List[Dict]:
    """List and analyze Lambda functions in a specific region."""
    try:
        if session:
            lambda_client = session.client('lambda', region_name=region)
        else:
            lambda_client = boto3.client('lambda', region_name=region)
        
        print(f"Scanning region: {region}")
        
        # Get all Lambda functions with pagination
        print("  Retrieving Lambda functions...")
        functions = []
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions.extend(page['Functions'])
        
        if not functions:
            print(f"  No Lambda functions found in {region}")
            return []
        
        print(f"  Found {len(functions)} Lambda functions")
        
        # Analyze each function
        analyzed_functions = []
        for i, function in enumerate(functions):
            print(f"  Analyzing {i+1}/{len(functions)}: {function['FunctionName']}")
            function_analysis = analyze_lambda_function(function, region, lambda_client)
            analyzed_functions.append(function_analysis)
        
        return analyzed_functions
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"  Access denied for region {region} - skipping")
        else:
            print(f"  Error in region {region}: {e.response['Error']['Message']}")
        return []

def export_to_csv(functions: List[Dict], filename: str):
    """Export function data to CSV."""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Region', 'FunctionName', 'Runtime', 'MemorySize', 'Timeout', 'CodeSize',
            'Architecture', 'LastModified', 'DaysOld', 'State', 'PackageType',
            'RuntimeDeprecated', 'HighMemoryUsage', 'LongTimeout', 'HasResourcePolicy',
            'KMSKeyArn', 'TracingMode', 'SecurityIssues', 'OptimizationOpportunities',
            'CostOptimizationLevel', 'Tags'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for function in functions:
            row = function.copy()
            # Convert lists to strings for CSV
            row['SecurityIssues'] = '; '.join(function.get('SecurityIssues', []))
            row['OptimizationOpportunities'] = '; '.join(function.get('OptimizationOpportunities', []))
            row['Tags'] = ', '.join([f"{k}={v}" for k, v in function.get('Tags', {}).items()])
            writer.writerow(row)

def export_to_json(functions: List[Dict], filename: str):
    """Export function data to JSON."""
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(functions, jsonfile, indent=2, default=str)

def print_summary_report(functions: List[Dict]):
    """Print comprehensive summary report."""
    total_functions = len(functions)
    
    if total_functions == 0:
        print(f"\n{'='*80}")
        print("LAMBDA FUNCTIONS SUMMARY")
        print(f"{'='*80}")
        print("No Lambda functions found in any scanned regions.")
        print(f"{'='*80}")
        return
    
    # Group by region and analyze
    by_region = {}
    deprecated_runtime = []
    security_issues = []
    optimization_needed = []
    
    # Runtime statistics
    runtime_stats = {}
    memory_stats = {}
    architecture_stats = {}
    
    for func in functions:
        region = func['Region']
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(func)
        
        # Runtime analysis
        runtime = func['Runtime']
        runtime_stats[runtime] = runtime_stats.get(runtime, 0) + 1
        
        # Memory analysis
        memory = func['MemorySize']
        memory_range = f"{memory//512*512}-{memory//512*512+511}MB"
        memory_stats[memory_range] = memory_stats.get(memory_range, 0) + 1
        
        # Architecture analysis
        arch = func.get('Architecture', 'x86_64')
        architecture_stats[arch] = architecture_stats.get(arch, 0) + 1
        
        # Issues tracking
        if func.get('RuntimeDeprecated'):
            deprecated_runtime.append(func)
        
        if func.get('SecurityIssues'):
            security_issues.append(func)
        
        if func.get('OptimizationOpportunities'):
            optimization_needed.append(func)
    
    print(f"\n{'='*80}")
    print("LAMBDA FUNCTIONS SUMMARY")
    print(f"{'='*80}")
    print(f"Total Lambda Functions: {total_functions}")
    print(f"Regions with Functions: {len(by_region)}")
    print(f"Functions with Deprecated Runtimes: {len(deprecated_runtime)}")
    print(f"Functions with Security Issues: {len(security_issues)}")
    print(f"Functions Needing Optimization: {len(optimization_needed)}")
    
    # Runtime breakdown
    print(f"\n{'='*80}")
    print("RUNTIME DISTRIBUTION")
    print(f"{'='*80}")
    for runtime, count in sorted(runtime_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_functions) * 100
        deprecated_marker = " ⚠️ DEPRECATED" if runtime in [
            'python2.7', 'python3.6', 'python3.7', 'nodejs8.10', 'nodejs10.x', 
            'nodejs12.x', 'ruby2.5', 'ruby2.7', 'dotnetcore2.1', 'dotnetcore3.1', 'go1.x'
        ] else ""
        print(f"{runtime:20} {count:6} functions ({percentage:5.1f}%){deprecated_marker}")
    
    # Architecture breakdown
    print(f"\n{'='*80}")
    print("ARCHITECTURE DISTRIBUTION")
    print(f"{'='*80}")
    for arch, count in sorted(architecture_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_functions) * 100
        print(f"{arch:15} {count:6} functions ({percentage:5.1f}%)")
    
    # Regional breakdown
    print(f"\n{'='*80}")
    print("BREAKDOWN BY REGION")
    print(f"{'='*80}")
    for region, funcs in sorted(by_region.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n{region}: {len(funcs)} functions")
        
        # Show top functions by issues
        issues_funcs = [f for f in funcs if f.get('SecurityIssues') or f.get('OptimizationOpportunities')]
        if issues_funcs:
            print(f"  Functions with issues: {len(issues_funcs)}")
            for func in issues_funcs[:3]:  # Show top 3
                issues = len(func.get('SecurityIssues', []) + func.get('OptimizationOpportunities', []))
                print(f"    {func['FunctionName']:30} ({issues} issues)")
            if len(issues_funcs) > 3:
                print(f"    ... and {len(issues_funcs) - 3} more")
    
    # Security issues details
    if security_issues:
        print(f"\n{'='*80}")
        print("SECURITY ISSUES REQUIRING ATTENTION")
        print(f"{'='*80}")
        print(f"{'Function Name':35} {'Region':12} {'Runtime':15} {'Issues'}")
        print("-" * 90)
        
        for func in security_issues[:15]:  # Show top 15
            issues_summary = ', '.join(func.get('SecurityIssues', [])[:2])
            if len(func.get('SecurityIssues', [])) > 2:
                issues_summary += '...'
            
            print(f"{func['FunctionName']:35} {func['Region']:12} {func['Runtime']:15} {issues_summary}")
        
        if len(security_issues) > 15:
            print(f"... and {len(security_issues) - 15} more functions with security issues")
    
    # Deprecated runtimes
    if deprecated_runtime:
        print(f"\n{'='*80}")
        print("DEPRECATED RUNTIMES (UPGRADE REQUIRED)")
        print(f"{'='*80}")
        print(f"{'Function Name':35} {'Region':12} {'Runtime':15} {'Days Old'}")
        print("-" * 75)
        
        for func in deprecated_runtime:
            days_old = func.get('DaysOld', 0)
            print(f"{func['FunctionName']:35} {func['Region']:12} {func['Runtime']:15} {days_old:8}")
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS:")
    print("- Upgrade deprecated runtimes to supported versions")
    print("- Review security issues and implement best practices")
    print("- Optimize memory allocation and timeout settings")
    print("- Enable X-Ray tracing for better observability")
    print("- Use customer-managed KMS keys for encryption")
    print(f"{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive Lambda functions inventory with security and optimization analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # List functions in specific region
  ./list_lambdas.py --region us-east-1
  
  # Scan all regions
  ./list_lambdas.py --all-regions
  
  # Export detailed report
  ./list_lambdas.py --all-regions --export-csv lambda_inventory.csv
  
  # Show only functions with issues
  ./list_lambdas.py --all-regions --issues-only

ANALYSIS INCLUDES:
- Runtime deprecation status
- Security configuration review
- Performance optimization opportunities
- Cost optimization recommendations
- Compliance and best practices checks
"""
    )
    parser.add_argument('--region', help='Specific AWS region to check')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Check all available regions')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--issues-only', action='store_true',
                       help='Show only functions with security or optimization issues')
    parser.add_argument('--profile', help='AWS profile to use')
    
    args = parser.parse_args()

    # Validate arguments
    if not args.region and not args.all_regions:
        print("Error: Must specify either --region or --all-regions")
        sys.exit(1)

    # Validate credentials
    if not validate_aws_credentials():
        sys.exit(1)

    try:
        # Create session
        session = None
        if args.profile:
            session = boto3.Session(profile_name=args.profile)

        # Determine regions to scan
        regions_to_scan = []
        if args.all_regions:
            # Get all available regions
            lambda_client = session.client('lambda') if session else boto3.client('lambda')
            regions_to_scan = get_available_regions(lambda_client)
            print(f"Scanning {len(regions_to_scan)} regions for Lambda functions...")
        else:
            regions_to_scan = [args.region]
            print(f"Scanning region: {args.region}")

        print("=" * 60)

        # Scan all regions
        all_functions = []
        for region in regions_to_scan:
            region_functions = list_lambda_functions_in_region(region, session)
            all_functions.extend(region_functions)

        # Filter results if requested
        display_functions = all_functions
        if args.issues_only:
            display_functions = [
                f for f in all_functions 
                if f.get('SecurityIssues') or f.get('OptimizationOpportunities') or f.get('RuntimeDeprecated')
            ]

        # Print summary report
        print_summary_report(all_functions)

        # Export to files if requested
        if args.export_csv:
            export_to_csv(all_functions, args.export_csv)
            print(f"\n📊 Detailed report exported to: {args.export_csv}")

        if args.export_json:
            export_to_json(all_functions, args.export_json)
            print(f"📊 JSON report exported to: {args.export_json}")

        # Return appropriate exit code for automation
        deprecated_functions = [f for f in all_functions if f.get('RuntimeDeprecated')]
        security_issues = [f for f in all_functions if f.get('SecurityIssues')]
        
        if deprecated_functions:
            print(f"\n⚠️  WARNING: Found {len(deprecated_functions)} functions with deprecated runtimes!")
            sys.exit(1)
        elif security_issues:
            print(f"\n🔒 SECURITY: Found {len(security_issues)} functions with security issues!")
            sys.exit(1)
        else:
            print(f"\n✅ All Lambda functions are using current runtimes and best practices!")
            sys.exit(0)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access Lambda. Required permissions:")
            print("- lambda:ListFunctions")
            print("- lambda:GetFunction")
            print("- lambda:ListTags")
            print("- lambda:GetPolicy")
            print("- ec2:DescribeRegions")
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

