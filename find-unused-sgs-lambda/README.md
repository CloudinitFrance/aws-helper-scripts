# Find Unused Security Groups - Lambda Version

AWS Lambda function for automated security group cleanup analysis with parallel region processing.

## Overview

This serverless version of the find-unused-sgs tool provides:

- **🕐 Scheduled Execution**: Automated analysis on CloudWatch Events schedules
- **⚡ Parallel Processing**: Multi-region scanning with configurable concurrency (85-90% faster)
- **🔍 Comprehensive Analysis**: ENI usage, launch templates, security group references
- **📊 Cost Optimization**: Identifies management overhead reduction opportunities
- **🚨 Alert Integration**: Triggers alerts when many unused security groups detected
- **📋 Detailed Reporting**: Statistics and actionable cleanup recommendations

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
4. **The SNS topic 'SecurityFindings' must be created in the deployment region before deploying this Lambda**

### Required AWS Permissions

The Lambda function requires these IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeVpcs",
                "ec2:DescribeInstances",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeLaunchTemplateVersions",
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
cd helper-scripts/find-unused-sgs-lambda/

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
    --stack-name find-unused-sgs-stack \
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

Default schedule: `cron(0 8 1 * ? *)` (Monthly on 1st at 8 AM UTC)

Common schedule patterns:
```yaml
# Weekly on Monday at 8 AM UTC  
Schedule: "cron(0 8 ? * MON *)"

# Monthly on 1st at 8 AM UTC
Schedule: "cron(0 8 1 * ? *)"

# Quarterly (every 3 months on 1st)
Schedule: "cron(0 8 1 */3 ? *)"

# Bi-annual (twice a year)
Schedule: "cron(0 8 1 */6 ? *)"
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
# Analyze current region
aws lambda invoke \
    --function-name find-unused-sgs-function \
    --payload '{"params": {"scan_all_regions": false}}' \
    response.json

# Analyze all regions
aws lambda invoke \
    --function-name find-unused-sgs-function \
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
        "message": "Unused security groups analysis completed successfully",
        "results": {
            "region_results": [
                {
                    "region": "us-east-1",
                    "unused_security_groups": [
                        {
                            "GroupId": "sg-0a1b2c3d4e5f6g7h8",
                            "GroupName": "old-web-servers",
                            "VpcId": "vpc-12345678",
                            "Description": "Legacy web servers",
                            "RulesCount": 3,
                            "Tags": []
                        }
                    ],
                    "statistics": {
                        "total_security_groups": 45,
                        "used_security_groups": 38,
                        "unused_security_groups": 7,
                        "default_security_groups": 3,
                        "unused_with_rules": 2,
                        "unused_with_tags": 1
                    },
                    "errors": []
                }
            ],
            "summary": {
                "total_regions_processed": 1,
                "total_security_groups": 45,
                "total_used_security_groups": 38,
                "total_unused_security_groups": 7,
                "total_default_security_groups": 3,
                "total_unused_with_rules": 2,
                "total_unused_with_tags": 1,
                "regions_with_errors": 0,
                "total_errors": 0,
                "estimated_annual_savings": 35.0,
                "management_hours_saved": 0.7
            },
            "analysis_parameters": {
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

## Analysis Features

### Usage Detection Methods

1. **Network Interface Analysis**
   - EC2 instances
   - Load balancers (ELB/ALB/NLB)
   - RDS instances
   - Lambda functions (ENI-based)
   - ECS tasks
   - Other AWS services using ENIs

2. **Launch Template Detection**
   - EC2 launch templates
   - Auto Scaling launch configurations
   - All versions of launch templates

3. **Security Group References**
   - Ingress rule references
   - Egress rule references
   - Cross-security group dependencies

4. **Default Security Group Protection**
   - Automatically excludes default security groups
   - Preserves AWS-managed security groups

### Alert Triggers

Alerts are triggered when:
- More than 50 unused security groups detected
- Processing errors occur across regions

## Performance Features

### Parallel Region Processing

- **ThreadPoolExecutor**: Thread-safe parallel execution
- **Configurable Concurrency**: 1-20 workers (default: 10)
- **Performance Gain**: 85-90% faster execution vs sequential
- **Example**: 35 regions scanned in 15-25 seconds vs 105-140 seconds

### Execution Time Estimates

| Regions | Workers | Security Groups/Region | Estimated Time |
|---------|---------|------------------------|----------------|
| 1 | 1 | 50 | 3-8 seconds |
| 10 | 10 | 50 | 8-15 seconds |
| 35 | 15 | 50 | 15-25 seconds |
| 35 | 5 | 50 | 35-50 seconds |

## Cost Optimization

### Management Overhead Savings

The function automatically calculates potential savings:
- **Assumption**: 6 minutes per security group per year for management
- **DevOps Rate**: $50/hour (configurable)
- **Formula**: unused_count × 0.1 hours × $50 = annual savings

### Example Cost Analysis

```
Unused Security Groups: 25
Management Hours Saved: 2.5 hours/year
Estimated Annual Savings: $125
Lambda Execution Cost: <$1/year
Net Savings: $124/year
```

### Lambda Execution Costs

Typical execution costs:
- **Memory**: 1024 MB
- **Duration**: 15-25 seconds (with parallelization)
- **Cost per execution**: $0.0003 - $0.0005
- **Monthly cost** (monthly execution): ~$0.0005

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
- Security group analysis statistics
- Unused security group details
- Error information

### Custom Metrics

The function logs key statistics:
```
INFO Analysis completed. Regions processed: 3, Total security groups: 150, Unused security groups: 12
WARNING CLEANUP ALERT: 55 unused security groups detected!
```

## Integration

### SNS Notifications

Add SNS integration for cleanup alerts:
```yaml
# In template.yaml
CleanupAlertTopic:
  Type: AWS::SNS::Topic
  Properties:
    Subscription:
      - Endpoint: devops@company.com
        Protocol: email
```

### CloudWatch Alarms

Create alarms for cleanup thresholds:
```yaml
UnusedSGAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    MetricName: UnusedSecurityGroups
    Namespace: Security/ResourceCleanup
    Threshold: 20
    ComparisonOperator: GreaterThanThreshold
```

### Security Hub Integration

Send findings to AWS Security Hub:
```python
def send_to_security_hub(unused_sgs):
    security_hub = boto3.client('securityhub')
    # Format and send findings
```

## Cleanup Workflow

### Automated Cleanup Pipeline

1. **Analysis Phase** (Lambda function)
   - Identify unused security groups
   - Generate cleanup report
   - Trigger alerts if thresholds exceeded

2. **Review Phase** (Manual/Automated)
   - Review findings for accuracy
   - Verify no hidden dependencies
   - Approve cleanup actions

3. **Cleanup Phase** (Separate automation)
   - Delete approved unused security groups
   - Log cleanup actions
   - Update inventory systems

### Manual Cleanup Process

Based on Lambda findings:

```bash
# Export unused security groups from Lambda response
cat response.json | jq -r '.body.results.region_results[].unused_security_groups[].GroupId'

# Verify findings
for sg in $(cat unused_sgs.txt); do
    aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$sg"
done

# Delete unused security groups
for sg in $(cat verified_unused_sgs.txt); do
    aws ec2 delete-security-group --group-id $sg
    echo "Deleted $sg"
done
```

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase timeout in template.yaml
   - Reduce max_workers to decrease processing time
   - Enable scan_all_regions=false for faster execution

2. **Memory Limit Exceeded**
   - Increase MemorySize in template.yaml
   - Process fewer regions concurrently

3. **Permission Errors**
   - Verify IAM role has required EC2 permissions
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
# Test single region analysis
aws lambda invoke \
    --function-name find-unused-sgs-function \
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

1. **Regular Analysis**: Schedule monthly or quarterly analysis
2. **Gradual Cleanup**: Start with obviously unused security groups
3. **Environment Separation**: Separate functions for dev/staging/prod
4. **Alert Tuning**: Adjust thresholds based on environment size

### Security Group Management

1. **Tagging Strategy**: Tag security groups with purpose and lifecycle
2. **Naming Conventions**: Use descriptive names for easy identification
3. **Documentation**: Maintain inventory of security group purposes
4. **Change Management**: Review before bulk cleanup operations

### Operational Guidelines

1. **Verify Findings**: Always verify before deletion
2. **Backup Strategy**: Export security group rules before deletion
3. **Team Coordination**: Notify teams before cleanup
4. **Audit Trail**: Maintain logs of all cleanup activities

## Related Resources

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [EC2 Security Groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)
- [AWS Resource Groups](https://aws.amazon.com/resource-groups/)

## Support

For issues, questions, or contributions:
1. Check CloudWatch logs for detailed error information
2. Review IAM permissions for EC2 access
3. Verify network connectivity to target regions
4. Test with scan_all_regions=false first