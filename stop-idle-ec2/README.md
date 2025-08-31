# Idle EC2 Instance Stopper

A cost optimization tool that identifies and stops EC2 instances with low CPU utilization over a specified time period. This helps reduce AWS costs by automatically stopping underutilized instances.

## Description

This script helps you optimize AWS costs by:

- **CPU Utilization Monitoring**: Analyzes CloudWatch metrics for CPU usage patterns
- **Configurable Thresholds**: Customizable CPU threshold and time period settings
- **Safe Operation**: Dry-run mode to preview actions before execution
- **Cost Optimization**: Reduces EC2 costs by stopping idle instances
- **Automated Monitoring**: Can be scheduled to run automatically

## Prerequisites

### Required Python Packages
```bash
pip install boto3
```

### AWS Credentials
Configure AWS credentials using one of these methods:
- AWS CLI: `aws configure`
- Multiple profiles: `aws configure --profile production`
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
                "ec2:DescribeInstances",
                "ec2:StopInstances",
                "cloudwatch:GetMetricStatistics"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Dry run - see what would be stopped (recommended first step)
python3 stop_idle_ec2_cli.py --region us-east-1 --dry-run

# Use specific AWS profile
python3 stop_idle_ec2_cli.py --profile production --region us-east-1 --dry-run

# Scan all regions with dry-run
python3 stop_idle_ec2_cli.py --all-regions --dry-run

# Scan all regions with specific profile
python3 stop_idle_ec2_cli.py --profile production --all-regions --dry-run

# Actually stop idle instances
python3 stop_idle_ec2_cli.py --region us-east-1
```

### Command Line Options
- `--region`: AWS region to scan (overridden by --all-regions)
- `--all-regions`: Scan all AWS regions
- `--profile`: AWS profile to use for credentials (optional)
- `--threshold`: CPU utilization threshold percentage (default: 5.0)
- `--hours`: Lookback period in hours (default: 3)
- `--dry-run`: Preview mode - show what would be stopped without actually stopping

### Examples
```bash
# Check for instances idle for 6 hours with less than 2% CPU (default profile)
python3 stop_idle_ec2_cli.py --region us-east-1 --threshold 2.0 --hours 6 --dry-run

# Check for instances using production profile
python3 stop_idle_ec2_cli.py --profile production --region us-east-1 --threshold 2.0 --hours 6 --dry-run

# Stop instances idle for 24 hours with less than 10% CPU (staging environment)
python3 stop_idle_ec2_cli.py --profile staging --region us-east-1 --threshold 10.0 --hours 24

# Very conservative - stop only instances with less than 1% CPU for 12 hours (development)
python3 stop_idle_ec2_cli.py --profile development --region us-east-1 --threshold 1.0 --hours 12 --dry-run

# Multi-region cost optimization examples
python3 stop_idle_ec2_cli.py --all-regions --dry-run
python3 stop_idle_ec2_cli.py --profile development --all-regions --threshold 10.0 --hours 6 --dry-run
python3 stop_idle_ec2_cli.py --profile staging --all-regions --threshold 8.0 --hours 8 --dry-run
python3 stop_idle_ec2_cli.py --profile production --all-regions --threshold 2.0 --hours 24 --dry-run

# Multi-environment testing (single region)
python3 stop_idle_ec2_cli.py --profile development --region us-west-2 --dry-run
python3 stop_idle_ec2_cli.py --profile staging --region us-west-2 --dry-run
python3 stop_idle_ec2_cli.py --profile production --region us-west-2 --dry-run

# Specific region examples for different environments
python3 stop_idle_ec2_cli.py --profile development --region us-east-1 --threshold 15.0 --hours 4 --dry-run
python3 stop_idle_ec2_cli.py --profile staging --region eu-west-1 --threshold 8.0 --hours 8 --dry-run
python3 stop_idle_ec2_cli.py --profile production --region ap-southeast-1 --threshold 2.0 --hours 24 --dry-run
```

## Example Output

### Instances Found and Analyzed
```
Checking i-0a1b2c3d4e5f6g7h8...
  Avg CPU: 2.34%
Checking i-0b2c3d4e5f6g7h8i9...
  Avg CPU: 45.67%
Checking i-0c3d4e5f6g7h8i9j0...
  Avg CPU: 1.23%
Checking i-0d4e5f6g7h8i9j0k1...
  Avg CPU: 0.89%

Stopping 3 idle instances: ['i-0a1b2c3d4e5f6g7h8', 'i-0c3d4e5f6g7h8i9j0', 'i-0d4e5f6g7h8i9j0k1']
Stop command sent.
```

### Dry Run Mode
```
Checking i-0a1b2c3d4e5f6g7h8...
  Avg CPU: 2.34%
Checking i-0b2c3d4e5f6g7h8i9...
  Avg CPU: 45.67%
Checking i-0c3d4e5f6g7h8i9j0...
  Avg CPU: 1.23%

Stopping 2 idle instances: ['i-0a1b2c3d4e5f6g7h8', 'i-0c3d4e5f6g7h8i9j0']
Dry run: not stopping instances.
```

### No Idle Instances Found
```
Checking i-0a1b2c3d4e5f6g7h8...
  Avg CPU: 25.34%
Checking i-0b2c3d4e5f6g7h8i9...
  Avg CPU: 45.67%

No idle instances found.
```

## Understanding the Analysis

### CPU Threshold Guidelines
- **1-2%**: Very conservative, catches truly idle instances
- **5%**: Default setting, good balance of safety and cost savings
- **10%**: More aggressive, may catch lightly used development instances
- **15%+**: Aggressive settings, use with caution

### Time Period Considerations
- **1-3 hours**: Short-term idle detection
- **6-12 hours**: Good for development/testing environments
- **24+ hours**: Very conservative, for production environments

### Instance States Considered
- **Only Running Instances**: The script only analyzes instances in "running" state
- **CloudWatch Availability**: Requires CloudWatch metrics to be available
- **Metric History**: Instances without sufficient metric history are skipped

## Safety Considerations

### Pre-Execution Checklist
1. **Always Use Dry-Run First**: Preview actions before execution
2. **Understand Your Workloads**: Know which instances should remain running
3. **Consider Time Zones**: Factor in business hours and peak usage times
4. **Review Instance Types**: Be cautious with production and database instances
5. **Check Dependencies**: Ensure stopped instances won't break applications

### Instance Protection Strategies
```python
def is_instance_protected(instance):
    """Check if instance should be protected from automatic stopping"""
    
    # Check tags for protection
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    
    if tags.get('AutoStop', '').lower() == 'false':
        return True
    
    if tags.get('Environment', '').lower() == 'production':
        return True
    
    if tags.get('Role', '').lower() in ['database', 'critical']:
        return True
    
    # Check instance type (protect expensive instances by default)
    instance_type = instance['InstanceType']
    if any(size in instance_type for size in ['xlarge', '2xlarge', '4xlarge']):
        return True
    
    return False
```

## Configuration Options

### Extending the Script

#### Add Instance Protection
```python
def get_protected_instances(ec2):
    """Get list of instances that should not be stopped"""
    protected = []
    reservations = ec2.describe_instances(Filters=[
        {'Name': 'instance-state-name', 'Values': ['running']},
        {'Name': 'tag:AutoStop', 'Values': ['false', 'no', 'never']}
    ])['Reservations']
    
    for res in reservations:
        for inst in res['Instances']:
            protected.append(inst['InstanceId'])
    
    return protected
```

#### Add Cost Impact Analysis
```python
def calculate_cost_savings(instance_ids, region):
    """Calculate estimated cost savings from stopping instances"""
    ec2 = boto3.client('ec2', region_name=region)
    
    # Get instance details
    reservations = ec2.describe_instances(InstanceIds=instance_ids)['Reservations']
    
    total_hourly_cost = 0
    for res in reservations:
        for inst in res['Instances']:
            instance_type = inst['InstanceType']
            # Rough cost estimation (varies by region and instance type)
            hourly_cost = get_instance_hourly_cost(instance_type, region)
            total_hourly_cost += hourly_cost
    
    daily_savings = total_hourly_cost * 24
    monthly_savings = daily_savings * 30
    
    return {
        'hourly_savings': total_hourly_cost,
        'daily_savings': daily_savings,
        'monthly_savings': monthly_savings,
        'instances_count': len(instance_ids)
    }

def get_instance_hourly_cost(instance_type, region):
    """Get approximate hourly cost for instance type"""
    # Simplified cost mapping (actual costs vary)
    base_costs = {
        't3.micro': 0.0104,
        't3.small': 0.0208,
        't3.medium': 0.0416,
        't3.large': 0.0832,
        'm5.large': 0.096,
        'm5.xlarge': 0.192,
        'c5.large': 0.085,
        'r5.large': 0.126
    }
    
    return base_costs.get(instance_type, 0.10)  # Default estimate
```

#### Add Notification Integration
```python
def send_notification(stopped_instances, dry_run=False):
    """Send notification about stopped instances"""
    import boto3
    
    sns = boto3.client('sns')
    
    if dry_run:
        subject = "EC2 Idle Instance Report (Dry Run)"
        message = f"Would stop {len(stopped_instances)} idle instances:\n"
    else:
        subject = "EC2 Instances Stopped - Cost Optimization"
        message = f"Stopped {len(stopped_instances)} idle instances:\n"
    
    for instance_id in stopped_instances:
        message += f"- {instance_id}\n"
    
    try:
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:ec2-cost-optimization',
            Subject=subject,
            Message=message
        )
    except Exception as e:
        print(f"Failed to send notification: {e}")
```

#### Add CloudWatch Metrics
```python
def send_cost_metrics(stopped_count, estimated_savings, region, profile=None):
    """Send cost optimization metrics to CloudWatch"""
    import boto3
    
    if profile:
        session = boto3.Session(profile_name=profile)
        cloudwatch = session.client('cloudwatch', region_name=region)
    else:
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    try:
        cloudwatch.put_metric_data(
            Namespace='CostOptimization/EC2',
            MetricData=[
                {
                    'MetricName': 'InstancesStopped',
                    'Value': stopped_count,
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Region', 'Value': region}]
                },
                {
                    'MetricName': 'EstimatedMonthlySavings',
                    'Value': estimated_savings,
                    'Unit': 'None',
                    'Dimensions': [{'Name': 'Region', 'Value': region}]
                }
            ]
        )
    except Exception as e:
        print(f"Failed to send metrics: {e}")
```

### Advanced Filtering

#### Time-Based Filtering
```python
def is_business_hours():
    """Check if current time is during business hours"""
    from datetime import datetime
    import pytz
    
    # Configure for your timezone
    tz = pytz.timezone('US/Eastern')
    now = datetime.now(tz)
    
    # Business hours: 8 AM to 6 PM, Monday to Friday
    if now.weekday() >= 5:  # Weekend
        return False
    
    if now.hour < 8 or now.hour >= 18:  # Outside business hours
        return False
    
    return True

def should_stop_instance(instance, cpu_avg):
    """Enhanced logic for determining if instance should be stopped"""
    
    # Don't stop during business hours if it's a development instance
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    env = tags.get('Environment', '').lower()
    
    if env in ['dev', 'development', 'test'] and is_business_hours():
        return False
    
    # Apply different thresholds based on environment
    if env == 'production':
        threshold = 1.0  # Very conservative for production
    elif env in ['staging', 'test']:
        threshold = 5.0  # Standard threshold
    else:
        threshold = 10.0  # More aggressive for dev
    
    return cpu_avg < threshold
```

#### Multi-Metric Analysis
```python
def analyze_instance_utilization(cloudwatch, instance_id, hours):
    """Analyze multiple metrics for better decision making"""
    from datetime import datetime, timedelta
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    metrics = {}
    
    # CPU Utilization
    try:
        cpu_response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum']
        )
        
        if cpu_response['Datapoints']:
            metrics['cpu_avg'] = sum(dp['Average'] for dp in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
            metrics['cpu_max'] = max(dp['Maximum'] for dp in cpu_response['Datapoints'])
        else:
            return None
    except Exception:
        return None
    
    # Network In/Out
    for metric_name in ['NetworkIn', 'NetworkOut']:
        try:
            network_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName=metric_name,
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            if network_response['Datapoints']:
                total_bytes = sum(dp['Sum'] for dp in network_response['Datapoints'])
                metrics[f'{metric_name.lower()}_total'] = total_bytes
        except Exception:
            metrics[f'{metric_name.lower()}_total'] = 0
    
    return metrics

def is_instance_truly_idle(metrics, cpu_threshold=5.0):
    """Determine if instance is truly idle based on multiple metrics"""
    
    if not metrics:
        return False
    
    # CPU check
    if metrics['cpu_avg'] >= cpu_threshold:
        return False
    
    # Network activity check (very low network activity might indicate idle)
    network_threshold = 1_000_000  # 1 MB total over the period
    if (metrics.get('networkin_total', 0) + metrics.get('networkout_total', 0)) > network_threshold:
        return False
    
    # High maximum CPU might indicate burst activity
    if metrics.get('cpu_max', 0) > cpu_threshold * 3:
        return False
    
    return True
```

## Automation and Scheduling

### Cron Job Setup
```bash
# Daily cost optimization check at 2 AM (default profile)
0 2 * * * /usr/bin/python3 /path/to/stop_idle_ec2_cli.py --region us-east-1 --threshold 5.0 --hours 12 >> /var/log/ec2-optimization.log 2>&1

# Daily checks for different environments
0 2 * * * /usr/bin/python3 /path/to/stop_idle_ec2_cli.py --profile development --region us-east-1 --threshold 10.0 --hours 6 >> /var/log/ec2-optimization-dev.log 2>&1
0 3 * * * /usr/bin/python3 /path/to/stop_idle_ec2_cli.py --profile staging --region us-east-1 --threshold 8.0 --hours 8 >> /var/log/ec2-optimization-staging.log 2>&1
0 4 * * * /usr/bin/python3 /path/to/stop_idle_ec2_cli.py --profile production --region us-east-1 --threshold 2.0 --hours 24 >> /var/log/ec2-optimization-prod.log 2>&1

# Weekly more aggressive check on weekends (development only)
0 6 * * 6 /usr/bin/python3 /path/to/stop_idle_ec2_cli.py --profile development --region us-east-1 --threshold 15.0 --hours 24 >> /var/log/ec2-optimization-weekend.log 2>&1
```

### AWS Lambda Integration
```python
import json
import boto3

def lambda_handler(event, context):
    """AWS Lambda function for automated EC2 cost optimization"""
    
    regions = event.get('regions', ['us-east-1'])
    threshold = event.get('threshold', 5.0)
    hours = event.get('hours', 6)
    dry_run = event.get('dry_run', True)
    
    results = {}
    
    for region in regions:
        try:
            # Import and run the idle instance detection logic
            idle_instances = get_idle_instances(region, threshold, hours)
            
            if idle_instances and not dry_run:
                ec2 = boto3.client('ec2', region_name=region)
                ec2.stop_instances(InstanceIds=idle_instances)
            
            results[region] = {
                'idle_instances_count': len(idle_instances),
                'instances': idle_instances,
                'action_taken': 'stopped' if not dry_run else 'dry_run'
            }
            
        except Exception as e:
            results[region] = {'error': str(e)}
    
    return {
        'statusCode': 200,
        'body': json.dumps(results)
    }
```

### Integration with AWS Systems Manager
```bash
#!/bin/bash
# Systems Manager document for EC2 cost optimization

# Create SSM document
aws ssm create-document \
    --name "EC2-CostOptimization-StopIdle" \
    --document-type "Command" \
    --content '{
        "schemaVersion": "2.2",
        "description": "Stop idle EC2 instances for cost optimization",
        "parameters": {
            "region": {
                "type": "String",
                "default": "us-east-1"
            },
            "threshold": {
                "type": "String",
                "default": "5.0"
            }
        },
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "stopIdleInstances",
                "inputs": {
                    "runCommand": [
                        "python3 /opt/scripts/stop_idle_ec2_cli.py --region {{region}} --threshold {{threshold}}"
                    ]
                }
            }
        ]
    }'
```

## Troubleshooting

### Common Issues

1. **No CloudWatch Metrics Available**
   ```
   No datapoints found for instance
   ```
   **Solution**: Instances need to run for some time before metrics are available. New instances may not have sufficient data.

2. **Permission Denied**
   ```
   UnauthorizedOperation: You are not authorized to perform this operation
   ```
   **Solution**: Ensure your IAM user/role has the required EC2 and CloudWatch permissions.

3. **Instance Already Stopping**
   ```
   IncorrectInstanceState: The instance 'i-xxx' is not in a state from which it can be stopped
   ```
   **Solution**: This is normal - the instance may already be stopping or stopped.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Best Practices

### Safety Guidelines
1. **Start Conservative**: Begin with low thresholds and longer time periods
2. **Use Dry-Run**: Always test with dry-run first
3. **Tag Protection**: Use tags to protect critical instances
4. **Business Hours**: Consider business hours in your automation
5. **Gradual Implementation**: Start with development environments

### Operational Guidelines
1. **Regular Monitoring**: Monitor the effectiveness of cost optimization
2. **Instance Tagging**: Use consistent tagging for better automation
3. **Cost Tracking**: Track actual cost savings achieved
4. **Team Communication**: Notify teams about automated stopping policies
5. **Exception Handling**: Have procedures for false positives

## Related AWS Services

- **AWS Auto Scaling**: Automatic scaling based on demand
- **AWS Lambda**: Serverless automation for cost optimization
- **AWS CloudWatch**: Monitoring and metrics collection
- **AWS Cost Explorer**: Cost analysis and optimization insights
- **AWS Trusted Advisor**: Cost optimization recommendations

## Security Considerations

- This tool can stop running instances - use with appropriate safeguards
- Consider the impact on running applications and services
- Implement proper access controls for cost optimization tools
- Monitor and audit all automated stopping activities
- Have procedures for quickly restarting accidentally stopped instances