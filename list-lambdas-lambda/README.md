# List Lambda Functions Inventory - Lambda Version

AWS Lambda function for automated Lambda function inventory and monitoring with parallel region processing.

## Overview

This serverless version of the list-lambdas tool provides:

- **🕐 Scheduled Execution**: Automated inventory on CloudWatch Events schedules
- **⚡ Parallel Processing**: Multi-region scanning with configurable concurrency (85-90% faster)
- **📊 Comprehensive Analysis**: Runtime distribution, memory usage, code size statistics
- **🏷️ Metadata Collection**: Tags, environment variables, event sources
- **💰 Cost Insights**: Memory cost calculations and optimization recommendations
- **📋 Infrastructure Documentation**: Detailed reports for compliance and planning

## Architecture

- **Runtime**: Python 3.11
- **Memory**: 1024 MB (configurable)
- **Timeout**: 15 minutes
- **Trigger**: CloudWatch Events (scheduled)
- **Concurrency**: Up to 20 parallel workers for region scanning

## Deployment

### Prerequisites

1. **AWS SAM CLI**: Install the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
2. **AWS Credentials**: Configure AWS credentials with appropriate permissions
3. **Docker**: Required for SAM build process

### Required AWS Permissions

The Lambda function requires these IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions",
                "lambda:GetFunction",
                "lambda:ListTags",
                "lambda:GetPolicy",
                "lambda:ListEventSourceMappings",
                "ec2:DescribeRegions",
                "sts:GetCallerIdentity",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

### Quick Deployment
```bash
# Clone and navigate
git clone <repository-url>
cd helper-scripts/list-lambdas-lambda/

# Deploy with guided setup (first time - REQUIRED)
./deploy.sh dev --guided

# Deploy to production (after guided setup)
./deploy.sh prod

# Deploy and test
./deploy.sh dev --test
```

### Advanced Deployment
```bash
# Validate template
sam validate

# Build application
sam build

# Deploy with specific parameters
sam deploy \
    --stack-name list-lambdas-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        ScanAllRegions=true \
        MaxWorkers=15
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `dev` | Environment name (dev/staging/prod) |
| `SCAN_ALL_REGIONS` | `false` | Scan all AWS regions vs current region |
| `MAX_WORKERS` | `10` | Parallel workers for region scanning (1-20) |

### Schedule Configuration

Default schedule: `cron(0 7 1 * ? *)` (Monthly on 1st at 7 AM UTC)

Common schedule patterns:
```yaml
# Weekly on Monday at 7 AM UTC  
Schedule: "cron(0 7 ? * MON *)"

# Monthly on 1st at 7 AM UTC
Schedule: "cron(0 7 1 * ? *)"

# Quarterly (every 3 months on 1st)
Schedule: "cron(0 7 1 */3 ? *)"

# On-demand only (disable scheduled execution)
Schedule: "rate(365 days)"
```

### Deployment Parameters

Configure in `samconfig.toml` or override during deployment:

```bash
sam deploy --parameter-overrides \
    Environment=prod \
    ScanAllRegions=true \
    MaxWorkers=15
```

## Usage

### Manual Invocation

```bash
# Inventory current region
aws lambda invoke \
    --function-name list-lambdas-function \
    --payload '{"params": {"scan_all_regions": false}}' \
    response.json

# Inventory all regions
aws lambda invoke \
    --function-name list-lambdas-function \
    --payload '{
        "params": {
            "scan_all_regions": true,
            "max_workers": 15
        }
    }' \
    response.json
```

### Event Payload Structure

```json
{
    "params": {
        "scan_all_regions": false,
        "max_workers": 10
    }
}
```

### Response Structure

```json
{
    "statusCode": 200,
    "body": {
        "message": "Lambda functions inventory completed successfully",
        "results": {
            "region_results": [
                {
                    "region": "us-east-1",
                    "functions": [
                        {
                            "FunctionName": "api-handler",
                            "Runtime": "python3.11",
                            "MemorySize": 512,
                            "Timeout": 30,
                            "CodeSize": 15728640,
                            "PackageType": "Zip",
                            "Architectures": ["x86_64"],
                            "EventSources": [
                                {
                                    "EventSourceArn": "arn:aws:dynamodb:...",
                                    "State": "Enabled",
                                    "BatchSize": 10
                                }
                            ],
                            "EstimatedCostPerSecond": 0.00000833
                        }
                    ],
                    "statistics": {
                        "total_functions": 25,
                        "total_code_size_mb": 450.5,
                        "runtime_distribution": {
                            "python3.11": 15,
                            "nodejs18.x": 8,
                            "java11": 2
                        },
                        "memory_distribution": {
                            "128": 10,
                            "256": 8,
                            "512": 5,
                            "1024": 2
                        },
                        "functions_with_triggers": 18,
                        "functions_with_env_vars": 20,
                        "functions_with_tags": 22,
                        "average_memory_size": 256,
                        "average_timeout": 45
                    },
                    "errors": []
                }
            ],
            "summary": {
                "total_regions_processed": 1,
                "total_lambda_functions": 25,
                "total_code_size_mb": 450.5,
                "total_code_size_gb": 0.44,
                "global_runtime_distribution": {
                    "python3.11": 15,
                    "nodejs18.x": 8,
                    "java11": 2
                },
                "global_memory_distribution": {
                    "128": 10,
                    "256": 8,
                    "512": 5,
                    "1024": 2
                },
                "total_functions_with_triggers": 18,
                "total_functions_with_env_vars": 20,
                "total_functions_with_tags": 22,
                "regions_with_errors": 0,
                "total_errors": 0,
                "average_functions_per_region": 25.0
            },
            "inventory_parameters": {
                "scan_all_regions": false,
                "max_workers": 10,
                "account_id": "123456789012",
                "caller_arn": "arn:aws:sts::123456789012:assumed-role/..."
            }
        },
        "executionId": "uuid-here",
        "alerts_triggered": false
    }
}
```

## Inventory Features

### Function Data Collection

1. **Basic Configuration**
   - Function name, ARN, runtime
   - Memory size, timeout settings
   - Handler and package type
   - Architecture (x86_64, arm64)

2. **Code Information**
   - Code size and SHA256
   - Last modified timestamp
   - Version information
   - Repository type

3. **Advanced Configuration**
   - Environment variables
   - Dead letter queues
   - KMS encryption keys
   - Tracing configuration
   - Ephemeral storage

4. **Integration Details**
   - Event source mappings
   - Function tags
   - IAM roles
   - VPC configuration

### Statistical Analysis

- **Runtime Distribution**: Count by runtime version
- **Memory Usage Patterns**: Memory allocation analysis
- **Code Size Analysis**: Storage usage statistics
- **Architecture Distribution**: x86_64 vs ARM64 usage
- **Configuration Patterns**: Environment variables, tags, triggers

## Performance Features

### Parallel Region Processing

- **ThreadPoolExecutor**: Thread-safe parallel execution
- **Configurable Concurrency**: 1-20 workers (default: 10)
- **Performance Gain**: 85-90% faster execution vs sequential
- **Example**: 35 regions scanned in 10-20 seconds vs 70-140 seconds

### Execution Time Estimates

| Regions | Workers | Functions/Region | Estimated Time |
|---------|---------|------------------|----------------|
| 1 | 1 | 50 | 5-10 seconds |
| 10 | 10 | 50 | 10-15 seconds |
| 35 | 15 | 50 | 15-25 seconds |
| 35 | 5 | 50 | 30-50 seconds |

## Cost Analysis

### Lambda Cost Calculation

The function calculates estimated cost per second for each Lambda:
- **Formula**: (Memory in GB) × $0.0000166667 per GB-second
- **Example**: 512 MB function = 0.5 GB × $0.0000166667 = $0.00000833/second

### Optimization Insights

Use inventory data to identify:
1. **Over-provisioned Memory**: Functions with high memory, low usage
2. **Runtime Standardization**: Consolidate to fewer runtime versions
3. **Code Size Optimization**: Large functions that could be optimized
4. **Architecture Migration**: Potential ARM64 candidates for cost savings

## Monitoring

### CloudWatch Metrics

Monitor Lambda execution through CloudWatch:
- Duration
- Memory utilization  
- Error rate
- Invocation count

### CloudWatch Logs

Structured logging includes:
- Region processing progress
- Function discovery counts
- Runtime distribution summaries
- Error details

### Custom Metrics

The function logs key statistics:
```
INFO Inventory completed. Regions processed: 3, Lambda functions found: 125, Total code size: 2.5 GB
INFO Completed listing for us-east-1: 45 Lambda functions
```

## Integration

### Cost Management Integration

Export data for cost analysis:
```python
def analyze_lambda_costs(inventory_data):
    # Calculate potential savings from right-sizing
    pass
```

### Compliance Reporting

Generate compliance reports:
```python
def generate_compliance_report(inventory_data):
    # Check runtime versions, security configurations
    pass
```

### Asset Management Integration

Update CMDB with Lambda inventory:
```python
def update_cmdb(inventory_data):
    # Sync with asset management systems
    pass
```

## Use Cases

### Infrastructure Management

1. **Runtime Lifecycle**: Track and plan runtime upgrades
2. **Resource Optimization**: Identify over/under-provisioned functions
3. **Security Compliance**: Monitor runtime versions and configurations
4. **Cost Optimization**: Analyze memory and architecture usage

### Operational Insights

1. **Change Tracking**: Monitor function modifications
2. **Capacity Planning**: Understand Lambda usage patterns
3. **Architecture Evolution**: Track technology adoption
4. **Performance Optimization**: Identify optimization opportunities

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase timeout in template.yaml
   - Reduce max_workers for better resource management
   - Enable scan_all_regions=false for faster execution

2. **Memory Limit Exceeded**
   - Increase MemorySize in template.yaml
   - Process fewer regions concurrently

3. **Permission Errors**
   - Verify IAM role has required Lambda permissions
   - Check for cross-account access requirements

### Debug Mode

Enable detailed logging:
```json
{
    "params": {
        "scan_all_regions": false,
        "max_workers": 1
    }
}
```

Check CloudWatch logs for detailed execution traces.

### Manual Testing

```bash
# Test single region inventory
aws lambda invoke \
    --function-name list-lambdas-function \
    --payload '{
        "params": {
            "scan_all_regions": false,
            "max_workers": 1
        }
    }' \
    test-response.json

# View response
cat test-response.json | python -m json.tool
```

## Best Practices

### Deployment Strategy

1. **Regular Inventory**: Schedule monthly or quarterly inventory
2. **Environment Separation**: Separate functions for dev/staging/prod
3. **Data Retention**: Store historical inventory for trend analysis
4. **Alert Configuration**: Monitor for inventory failures

### Operational Guidelines

1. **Review Schedule**: Align with infrastructure review cycles
2. **Trend Analysis**: Compare inventory over time
3. **Cost Review**: Use data for cost optimization initiatives
4. **Security Monitoring**: Track runtime versions and updates

## Related Resources

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Lambda Pricing](https://aws.amazon.com/lambda/pricing/)
- [AWS Well-Architected Serverless Lens](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/)

## Support

For issues, questions, or contributions:
1. Check CloudWatch logs for detailed error information
2. Review IAM permissions for Lambda access
3. Verify network connectivity to target regions
4. Test with scan_all_regions=false first