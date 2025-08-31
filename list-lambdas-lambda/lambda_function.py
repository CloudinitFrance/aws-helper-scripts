#!/usr/bin/env python3
"""
List Lambda Functions Inventory - Lambda Version
Serverless function for automated Lambda function inventory and monitoring
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
    """Get all AWS regions where Lambda is available."""
    return AWS_REGIONS

def get_function_details(lambda_client, function_name: str) -> Optional[Dict]:
    """Get detailed information about a Lambda function."""
    try:
        # Get function configuration
        response = lambda_client.get_function(FunctionName=function_name)
        config = response.get('Configuration', {})
        code = response.get('Code', {})
        
        # Get function tags
        tags = {}
        try:
            tags_response = lambda_client.list_tags(Resource=config.get('FunctionArn', ''))
            tags = tags_response.get('Tags', {})
        except ClientError:
            pass
        
        # Get event source mappings
        event_sources = []
        try:
            mappings_response = lambda_client.list_event_source_mappings(FunctionName=function_name)
            for mapping in mappings_response.get('EventSourceMappings', []):
                event_sources.append({
                    'EventSourceArn': mapping.get('EventSourceArn', 'Unknown'),
                    'State': mapping.get('State', 'Unknown'),
                    'BatchSize': mapping.get('BatchSize', 'Unknown')
                })
        except ClientError:
            pass
        
        # Calculate memory cost (approximate)
        memory_mb = config.get('MemorySize', 128)
        # AWS Lambda pricing: $0.0000166667 per GB-second
        gb_memory = memory_mb / 1024
        cost_per_second = gb_memory * 0.0000166667
        
        return {
            'FunctionName': config.get('FunctionName', 'Unknown'),
            'FunctionArn': config.get('FunctionArn', 'Unknown'),
            'Runtime': config.get('Runtime', 'Unknown'),
            'Role': config.get('Role', 'Unknown'),
            'Handler': config.get('Handler', 'Unknown'),
            'CodeSize': config.get('CodeSize', 0),
            'Description': config.get('Description', ''),
            'Timeout': config.get('Timeout', 0),
            'MemorySize': config.get('MemorySize', 0),
            'LastModified': config.get('LastModified', 'Unknown'),
            'CodeSha256': config.get('CodeSha256', 'Unknown'),
            'Version': config.get('Version', 'Unknown'),
            'Environment': config.get('Environment', {}).get('Variables', {}),
            'DeadLetterConfig': config.get('DeadLetterConfig', {}),
            'KMSKeyArn': config.get('KMSKeyArn', ''),
            'TracingConfig': config.get('TracingConfig', {}),
            'MasterArn': config.get('MasterArn', ''),
            'RevisionId': config.get('RevisionId', ''),
            'PackageType': config.get('PackageType', 'Zip'),
            'Architectures': config.get('Architectures', []),
            'EphemeralStorage': config.get('EphemeralStorage', {}),
            'RepositoryType': code.get('RepositoryType', ''),
            'Tags': tags,
            'EventSources': event_sources,
            'EstimatedCostPerSecond': round(cost_per_second, 8)
        }
    
    except ClientError as e:
        logger.warning(f"Error getting details for function {function_name}: {e}")
        return None

def list_lambda_functions_in_region(region: str) -> Dict:
    """List Lambda functions in a specific region with detailed information."""
    try:
        lambda_client = boto3.client('lambda', region_name=region)
        
        logger.info(f"Listing Lambda functions in region: {region}")
        
        functions = []
        
        # Use paginator for large number of functions
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for func in page['Functions']:
                function_name = func['FunctionName']
                
                # Get detailed information
                detailed_info = get_function_details(lambda_client, function_name)
                if detailed_info:
                    functions.append(detailed_info)
                else:
                    # Fallback to basic info
                    functions.append({
                        'FunctionName': func.get('FunctionName', 'Unknown'),
                        'FunctionArn': func.get('FunctionArn', 'Unknown'),
                        'Runtime': func.get('Runtime', 'Unknown'),
                        'Role': func.get('Role', 'Unknown'),
                        'Handler': func.get('Handler', 'Unknown'),
                        'CodeSize': func.get('CodeSize', 0),
                        'Description': func.get('Description', ''),
                        'Timeout': func.get('Timeout', 0),
                        'MemorySize': func.get('MemorySize', 0),
                        'LastModified': func.get('LastModified', 'Unknown'),
                        'Version': func.get('Version', 'Unknown'),
                        'PackageType': func.get('PackageType', 'Zip'),
                        'Architectures': func.get('Architectures', []),
                        'Tags': {},
                        'EventSources': [],
                        'EstimatedCostPerSecond': 0
                    })
        
        # Calculate statistics
        total_functions = len(functions)
        total_code_size = sum(f.get('CodeSize', 0) for f in functions)
        
        # Runtime distribution
        runtimes = {}
        memory_sizes = {}
        package_types = {}
        architectures = {}
        
        for func in functions:
            runtime = func.get('Runtime', 'Unknown')
            runtimes[runtime] = runtimes.get(runtime, 0) + 1
            
            memory = func.get('MemorySize', 0)
            memory_sizes[str(memory)] = memory_sizes.get(str(memory), 0) + 1
            
            package_type = func.get('PackageType', 'Unknown')
            package_types[package_type] = package_types.get(package_type, 0) + 1
            
            arch_list = func.get('Architectures', [])
            for arch in arch_list:
                architectures[arch] = architectures.get(arch, 0) + 1
        
        # Functions with event sources
        functions_with_triggers = len([f for f in functions if f.get('EventSources')])
        
        # Functions with environment variables
        functions_with_env_vars = len([f for f in functions if f.get('Environment')])
        
        # Functions with tags
        functions_with_tags = len([f for f in functions if f.get('Tags')])
        
        region_results = {
            'region': region,
            'functions': functions[:100],  # Limit for response size
            'statistics': {
                'total_functions': total_functions,
                'total_code_size_bytes': total_code_size,
                'total_code_size_mb': round(total_code_size / (1024 * 1024), 2),
                'runtime_distribution': runtimes,
                'memory_distribution': memory_sizes,
                'package_type_distribution': package_types,
                'architecture_distribution': architectures,
                'functions_with_triggers': functions_with_triggers,
                'functions_with_env_vars': functions_with_env_vars,
                'functions_with_tags': functions_with_tags,
                'average_memory_size': round(sum(f.get('MemorySize', 0) for f in functions) / max(total_functions, 1), 0),
                'average_timeout': round(sum(f.get('Timeout', 0) for f in functions) / max(total_functions, 1), 0),
                'average_code_size_mb': round((total_code_size / (1024 * 1024)) / max(total_functions, 1), 2)
            },
            'errors': []
        }
        
        logger.info(f"Completed listing for {region}: {total_functions} Lambda functions found")
        return region_results
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'functions': [],
            'statistics': {
                'total_functions': 0,
                'total_code_size_bytes': 0,
                'total_code_size_mb': 0,
                'runtime_distribution': {},
                'memory_distribution': {},
                'package_type_distribution': {},
                'architecture_distribution': {},
                'functions_with_triggers': 0,
                'functions_with_env_vars': 0,
                'functions_with_tags': 0
            },
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def list_lambda_functions_parallel(scan_all_regions_flag: bool, max_workers: int = 10) -> List[Dict]:
    """
    List Lambda functions across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Listing Lambda functions in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Listing Lambda functions in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region listing tasks
        future_to_region = {
            executor.submit(list_lambda_functions_in_region, region): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed listing for {region}: "
                           f"{result['statistics']['total_functions']} Lambda functions")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'functions': [],
                    'statistics': {
                        'total_functions': 0,
                        'total_code_size_bytes': 0,
                        'total_code_size_mb': 0,
                        'runtime_distribution': {},
                        'memory_distribution': {},
                        'package_type_distribution': {},
                        'architecture_distribution': {},
                        'functions_with_triggers': 0,
                        'functions_with_env_vars': 0,
                        'functions_with_tags': 0
                    },
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel Lambda functions listing complete")
    return all_results

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the inventory."""
    # Aggregate all runtime distributions
    global_runtime_distribution = {}
    global_memory_distribution = {}
    global_package_type_distribution = {}
    global_architecture_distribution = {}
    
    for result in results:
        stats = result['statistics']
        
        # Aggregate runtime distribution
        for runtime, count in stats.get('runtime_distribution', {}).items():
            global_runtime_distribution[runtime] = global_runtime_distribution.get(runtime, 0) + count
        
        # Aggregate memory distribution
        for memory, count in stats.get('memory_distribution', {}).items():
            global_memory_distribution[memory] = global_memory_distribution.get(memory, 0) + count
        
        # Aggregate package type distribution
        for package_type, count in stats.get('package_type_distribution', {}).items():
            global_package_type_distribution[package_type] = global_package_type_distribution.get(package_type, 0) + count
        
        # Aggregate architecture distribution
        for arch, count in stats.get('architecture_distribution', {}).items():
            global_architecture_distribution[arch] = global_architecture_distribution.get(arch, 0) + count
    
    total_functions = sum(r['statistics']['total_functions'] for r in results)
    total_code_size_bytes = sum(r['statistics']['total_code_size_bytes'] for r in results)
    
    return {
        'total_regions_processed': len(results),
        'total_lambda_functions': total_functions,
        'total_code_size_bytes': total_code_size_bytes,
        'total_code_size_mb': round(total_code_size_bytes / (1024 * 1024), 2),
        'total_code_size_gb': round(total_code_size_bytes / (1024 * 1024 * 1024), 2),
        'global_runtime_distribution': global_runtime_distribution,
        'global_memory_distribution': global_memory_distribution,
        'global_package_type_distribution': global_package_type_distribution,
        'global_architecture_distribution': global_architecture_distribution,
        'total_functions_with_triggers': sum(r['statistics']['functions_with_triggers'] for r in results),
        'total_functions_with_env_vars': sum(r['statistics']['functions_with_env_vars'] for r in results),
        'total_functions_with_tags': sum(r['statistics']['functions_with_tags'] for r in results),
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results),
        'average_functions_per_region': round(total_functions / max(len(results), 1), 1)
    }

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for Lambda functions inventory
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with inventory results
    """
    try:
        logger.info("Starting Lambda functions inventory")
        
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
            logger.info(f"Inventorying Lambda functions in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform inventory using parallel processing
        results = list_lambda_functions_parallel(scan_all_regions_flag, max_workers)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = summary_stats['total_errors'] > 0
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Inventory completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Lambda functions found: {summary_stats['total_lambda_functions']}, "
                   f"Total code size: {summary_stats['total_code_size_mb']} MB")
        
        if summary_stats['total_lambda_functions'] == 0:
            logger.info("No Lambda functions found in scanned regions")
        
        return {
            'statusCode': status_code,
            'body': {
                'message': f'Lambda functions inventory completed successfully',
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
        logger.error(f"Lambda functions inventory failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Lambda functions inventory failed',
                'executionId': context.aws_request_id
            }
        }