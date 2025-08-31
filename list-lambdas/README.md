# Lambda Functions Inventory Tool

A comprehensive AWS Lambda inventory and monitoring tool that lists all Lambda functions in a region with their configuration details including runtime, memory size, and timeout settings.

## Description

This script provides detailed inventory of your Lambda functions by:

- **Complete Function Listing**: Shows all Lambda functions in the specified region
- **Configuration Details**: Displays runtime, memory allocation, and timeout settings
- **Resource Monitoring**: Helps track Lambda resource usage and configurations
- **Infrastructure Documentation**: Generates reports for compliance and planning
- **Capacity Planning**: Assists in understanding current Lambda deployments

## Prerequisites

### Required Python Packages
```bash
pip install boto3
```

### AWS Credentials
Configure AWS credentials using one of these methods:
- AWS CLI: `aws configure`
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- IAM roles (for EC2 instances)
- AWS credentials file

### Required AWS Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
python3 list_lambdas_cli.py --region us-east-1
```

### Required Parameters
- `--region`: AWS region to scan (required)

### Examples
```bash
# List Lambda functions in US East 1
python3 list_lambdas_cli.py --region us-east-1

# List Lambda functions in EU West 1
python3 list_lambdas_cli.py --region eu-west-1

# List Lambda functions in Asia Pacific Tokyo
python3 list_lambdas_cli.py --region ap-northeast-1
```

## Example Output

### Active Lambda Environment
```
Function Name                            Runtime    Memory(MB) Timeout(s)
---------------------------------------------------------------------------
user-authentication-service             python3.9  256        30
data-processing-pipeline                 python3.11 1024       300
image-thumbnail-generator                python3.9  512        60
notification-dispatcher                  python3.10 128        15
database-backup-automation               python3.11 2048       900
api-gateway-authorizer                   python3.9  128        10
file-upload-processor                    python3.10 1024       120
scheduled-report-generator               python3.11 512        180
webhook-handler                          python3.9  256        30
log-analytics-processor                  python3.10 1536       600
```

### Mixed Runtime Environment
```
Function Name                            Runtime    Memory(MB) Timeout(s)
---------------------------------------------------------------------------
legacy-data-processor                    python3.6  128        30
modern-api-service                       python3.11 512        60
nodejs-microservice                      nodejs18.x 256        30
java-batch-processor                     java11     1024       900
dotnet-api-handler                       dotnet6    512        30
custom-runtime-function                  provided.al2 256      60
```

### No Lambda Functions
```
Function Name                            Runtime    Memory(MB) Timeout(s)
---------------------------------------------------------------------------
```

## Understanding the Output

### Column Descriptions
- **Function Name**: Unique identifier for the Lambda function
- **Runtime**: Programming language and version (e.g., python3.9, nodejs18.x)
- **Memory(MB)**: Allocated memory in megabytes (128 MB to 10,008 MB)
- **Timeout(s)**: Maximum execution time in seconds (1 to 900 seconds)

### Common Runtimes
- **Python**: python3.8, python3.9, python3.10, python3.11
- **Node.js**: nodejs14.x, nodejs16.x, nodejs18.x, nodejs20.x
- **Java**: java8, java11, java17, java21
- **.NET**: dotnet6, dotnet8
- **Go**: provided.al2 (custom runtime)
- **Ruby**: ruby2.7, ruby3.2
- **Custom**: provided, provided.al2

## Use Cases

### Infrastructure Management
- **Resource Planning**: Understand memory and runtime distribution
- **Cost Optimization**: Identify over-provisioned functions
- **Migration Planning**: Inventory functions for runtime upgrades
- **Compliance Auditing**: Document function configurations

### Operational Tasks
- **Performance Monitoring**: Track function configurations
- **Security Reviews**: Identify functions using deprecated runtimes
- **Capacity Planning**: Understand current deployment patterns
- **Change Management**: Document baseline configurations

## Configuration Analysis

### Memory Allocation Patterns
```bash
# Analyze memory usage distribution
python3 list_lambdas_cli.py --region us-east-1 | grep -o '[0-9]*' | sort -n | uniq -c
```

### Runtime Distribution
```bash
# Count functions by runtime
python3 list_lambdas_cli.py --region us-east-1 | awk '{print $2}' | tail -n +3 | sort | uniq -c
```

### Timeout Analysis
```bash
# Find functions with long timeouts
python3 list_lambdas_cli.py --region us-east-1 | awk '$4 > 300 {print $1, $4}'
```

## Extended Features

### Adding Function Details
```python
def get_detailed_function_info(lambda_client, function_name):
    """Get detailed information about a Lambda function"""
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        config = response['Configuration']
        
        return {
            'last_modified': config['LastModified'],
            'code_size': config['CodeSize'],
            'environment_vars': len(config.get('Environment', {}).get('Variables', {})),
            'layers': len(config.get('Layers', [])),
            'vpc_config': bool(config.get('VpcConfig', {}).get('VpcId')),
            'dead_letter_queue': bool(config.get('DeadLetterConfig')),
            'reserved_concurrency': config.get('ReservedConcurrencyExecutions')
        }
    except Exception as e:
        return None

# Usage in main function
details = get_detailed_function_info(client, fn['FunctionName'])
if details:
    print(f"  Code Size: {details['code_size']} bytes")
    print(f"  Last Modified: {details['last_modified']}")
    print(f"  Environment Variables: {details['environment_vars']}")
```

### Cost Analysis Integration
```python
def estimate_monthly_cost(memory_mb, avg_duration_ms, monthly_invocations):
    """Estimate monthly cost for a Lambda function"""
    
    # AWS Lambda pricing (approximate, varies by region)
    price_per_gb_second = 0.0000166667
    price_per_request = 0.0000002
    
    # Convert memory to GB
    memory_gb = memory_mb / 1024
    
    # Calculate GB-seconds per month
    duration_seconds = avg_duration_ms / 1000
    gb_seconds_per_month = memory_gb * duration_seconds * monthly_invocations
    
    # Calculate costs
    compute_cost = gb_seconds_per_month * price_per_gb_second
    request_cost = monthly_invocations * price_per_request
    
    return {
        'compute_cost': compute_cost,
        'request_cost': request_cost,
        'total_cost': compute_cost + request_cost
    }
```

### Output Formatting Options

#### JSON Export
```python
import json

def export_to_json(functions_list):
    """Export Lambda inventory to JSON format"""
    output = {
        'timestamp': datetime.now().isoformat(),
        'region': 'us-east-1',  # Make this dynamic
        'functions': []
    }
    
    for func in functions_list:
        output['functions'].append({
            'name': func['FunctionName'],
            'runtime': func['Runtime'],
            'memory_size': func['MemorySize'],
            'timeout': func['Timeout'],
            'last_modified': func['LastModified']
        })
    
    return json.dumps(output, indent=2, default=str)
```

#### CSV Export
```python
import csv

def export_to_csv(functions_list, filename='lambda_inventory.csv'):
    """Export Lambda inventory to CSV format"""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['FunctionName', 'Runtime', 'MemorySize', 'Timeout', 'CodeSize', 'LastModified'])
        
        for func in functions_list:
            writer.writerow([
                func['FunctionName'],
                func['Runtime'],
                func['MemorySize'],
                func['Timeout'],
                func['CodeSize'],
                func['LastModified']
            ])
```

#### HTML Report
```python
def generate_html_report(functions_list):
    """Generate HTML report for Lambda inventory"""
    html = """
    <html>
    <head>
        <title>Lambda Functions Inventory</title>
        <style>
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Lambda Functions Inventory</h1>
        <table>
            <tr>
                <th>Function Name</th>
                <th>Runtime</th>
                <th>Memory (MB)</th>
                <th>Timeout (s)</th>
            </tr>
    """
    
    for func in functions_list:
        html += f"""
            <tr>
                <td>{func['FunctionName']}</td>
                <td>{func['Runtime']}</td>
                <td>{func['MemorySize']}</td>
                <td>{func['Timeout']}</td>
            </tr>
        """
    
    html += """
        </table>
    </body>
    </html>
    """
    
    return html
```

## Advanced Usage

### Multi-Region Inventory
```bash
#!/bin/bash
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
echo "Lambda Functions Global Inventory - $(date)" > lambda_global_inventory.txt
echo "================================================" >> lambda_global_inventory.txt

for region in "${regions[@]}"; do
    echo "" >> lambda_global_inventory.txt
    echo "Region: $region" >> lambda_global_inventory.txt
    echo "----------------------------" >> lambda_global_inventory.txt
    python3 list_lambdas_cli.py --region "$region" >> lambda_global_inventory.txt
done
```

### Performance Analysis
```python
def analyze_function_performance(functions):
    """Analyze Lambda function configurations for performance insights"""
    analysis = {
        'total_functions': len(functions),
        'runtime_distribution': {},
        'memory_distribution': {},
        'timeout_distribution': {},
        'potential_optimizations': []
    }
    
    for func in functions:
        runtime = func['Runtime']
        memory = func['MemorySize']
        timeout = func['Timeout']
        
        # Count distributions
        analysis['runtime_distribution'][runtime] = analysis['runtime_distribution'].get(runtime, 0) + 1
        analysis['memory_distribution'][memory] = analysis['memory_distribution'].get(memory, 0) + 1
        analysis['timeout_distribution'][timeout] = analysis['timeout_distribution'].get(timeout, 0) + 1
        
        # Identify potential optimizations
        if memory == 128 and timeout > 30:
            analysis['potential_optimizations'].append(
                f"{func['FunctionName']}: Low memory with high timeout - consider memory increase"
            )
        
        if memory > 1024 and timeout < 30:
            analysis['potential_optimizations'].append(
                f"{func['FunctionName']}: High memory with low timeout - consider memory reduction"
            )
    
    return analysis
```

### Integration with Monitoring
```python
def get_function_metrics(cloudwatch, function_name, region):
    """Get CloudWatch metrics for Lambda function"""
    from datetime import datetime, timedelta
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    try:
        # Get invocation count
        invocations = cloudwatch.get_metric_statistics(
            Namespace='AWS/Lambda',
            MetricName='Invocations',
            Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Sum']
        )
        
        # Get duration metrics
        duration = cloudwatch.get_metric_statistics(
            Namespace='AWS/Lambda',
            MetricName='Duration',
            Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Average']
        )
        
        return {
            'total_invocations': sum(point['Sum'] for point in invocations['Datapoints']),
            'avg_duration': sum(point['Average'] for point in duration['Datapoints']) / len(duration['Datapoints']) if duration['Datapoints'] else 0
        }
    except Exception as e:
        return {'error': str(e)}
```

## Troubleshooting

### Common Issues

1. **No Functions Found**
   ```
   (Empty table output)
   ```
   **Solution**: Verify you're scanning the correct region and have Lambda functions deployed.

2. **Permission Denied**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Ensure your AWS credentials have Lambda:ListFunctions permission.

3. **Region Not Specified**
   ```
   error: the following arguments are required: --region
   ```
   **Solution**: Always specify the region parameter.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Integration

### Scheduled Inventory Updates
```bash
# Daily Lambda inventory update
0 8 * * * /usr/bin/python3 /path/to/list_lambdas.py --region us-east-1 > /var/inventory/lambda_inventory_$(date +\%Y\%m\%d).txt
```

### Integration with CMDB
```python
def sync_with_cmdb(functions_data):
    """Sync Lambda inventory with Configuration Management Database"""
    import requests
    
    for func in functions_data:
        cmdb_record = {
            'name': func['FunctionName'],
            'type': 'AWS Lambda Function',
            'runtime': func['Runtime'],
            'memory': func['MemorySize'],
            'timeout': func['Timeout'],
            'status': 'Active'
        }
        
        response = requests.post(
            'https://cmdb.company.com/api/resources',
            json=cmdb_record,
            headers={'Authorization': 'Bearer TOKEN'}
        )
```

### Change Detection
```bash
#!/bin/bash
# Detect changes in Lambda inventory
current_inventory=$(python3 list_lambdas_cli.py --region us-east-1)
if [ -f /tmp/previous_lambda_inventory.txt ]; then
    if ! diff -q <(echo "$current_inventory") /tmp/previous_lambda_inventory.txt > /dev/null; then
        echo "Lambda configuration changed!"
        echo "$current_inventory" | mail -s "Lambda Inventory Change" ops@company.com
    fi
fi
echo "$current_inventory" > /tmp/previous_lambda_inventory.txt
```

### CloudWatch Metrics Integration
```python
def send_inventory_metrics(function_count, region):
    """Send Lambda inventory metrics to CloudWatch"""
    import boto3
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    cloudwatch.put_metric_data(
        Namespace='Infrastructure/Inventory',
        MetricData=[{
            'MetricName': 'LambdaFunctionCount',
            'Value': function_count,
            'Unit': 'Count',
            'Dimensions': [{'Name': 'Region', 'Value': region}]
        }]
    )
```

## Best Practices

### Inventory Management
1. **Regular Updates**: Run inventory reports weekly or monthly
2. **Version Control**: Store inventory reports in version control
3. **Change Tracking**: Monitor function configuration changes
4. **Documentation**: Maintain function purpose and ownership information
5. **Cleanup**: Regular review for unused or outdated functions

### Operational Guidelines
1. **Standardized Naming**: Use consistent naming conventions
2. **Tagging Strategy**: Tag functions with environment, purpose, and owner
3. **Resource Optimization**: Regular review of memory and timeout settings
4. **Security Monitoring**: Track runtime versions for security updates
5. **Cost Management**: Monitor function costs and optimization opportunities

## Related AWS Services

- **AWS Lambda**: Serverless compute service
- **AWS CloudWatch**: Monitoring and observability
- **AWS X-Ray**: Application tracing and debugging
- **AWS SAM**: Serverless Application Model for deployment
- **AWS Step Functions**: Workflow orchestration
- **AWS API Gateway**: API management for Lambda functions

## Security Considerations

- This tool only reads Lambda metadata and configuration
- Results may contain sensitive function names and configurations
- Consider access controls for inventory reports
- Regular inventory helps identify unauthorized or misconfigured functions
- Monitor for functions using deprecated runtimes or insecure configurations