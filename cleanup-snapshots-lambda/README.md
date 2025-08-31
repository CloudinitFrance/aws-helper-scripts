# Cleanup EBS Snapshots - Lambda Version

AWS Lambda function for automated EBS snapshot cleanup with comprehensive safety checks and parallel region processing.

## Overview

This serverless version of the cleanup-snapshots tool provides:

- **🕐 Scheduled Execution**: Automated cleanup on CloudWatch Events schedules
- **⚡ Parallel Processing**: Multi-region scanning with configurable concurrency (85-90% faster)
- **🔒 Comprehensive Safety**: AMI usage, launch template checks, protection tags, backup detection
- **💰 Cost Optimization**: Automated storage cost reduction
- **📊 Detailed Reporting**: Structured output with cost savings estimates
- **🚨 Error Handling**: Graceful failure handling with detailed error reporting

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
                "ec2:DescribeSnapshots",
                "ec2:DescribeImages",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeLaunchTemplateVersions",
                "ec2:DeleteSnapshot",
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
cd helper-scripts/cleanup-snapshots-lambda/

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
    --stack-name cleanup-snapshots-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        DaysOld=30 \
        ScanAllRegions=true \
        DryRun=false \
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
| `DAYS_OLD` | `30` | Delete snapshots older than N days |
| `SCAN_ALL_REGIONS` | `false` | Scan all AWS regions vs current region |
| `DRY_RUN` | `true` | Dry run mode - don't actually delete |
| `REQUIRE_UNTAGGED` | `false` | Only delete completely untagged snapshots |
| `MAX_WORKERS` | `10` | Parallel workers for region scanning (1-20) |

### Schedule Configuration

Default schedule: `cron(0 3 * * SUN *)` (Weekly on Sunday at 3 AM UTC)

Common schedule patterns:
```yaml
# Daily at 2 AM UTC
Schedule: "cron(0 2 * * ? *)"

# Weekly on Sunday at 3 AM UTC  
Schedule: "cron(0 3 ? * SUN *)"

# Monthly on 1st at 1 AM UTC
Schedule: "cron(0 1 1 * ? *)"

# Quarterly (every 3 months on 1st)
Schedule: "cron(0 1 1 */3 ? *)"
```

### Deployment Parameters

Configure in `samconfig.toml` or override during deployment:

```bash
sam deploy --parameter-overrides \
    Environment=prod \
    DaysOld=60 \
    ScanAllRegions=true \
    DryRun=false \
    MaxWorkers=15
```

## Usage

### Manual Invocation

```bash
# Test with dry run
aws lambda invoke \
    --function-name cleanup-snapshots-function \
    --payload '{"params": {"dry_run": true, "days_old": 30}}' \
    response.json

# Production cleanup (all regions)
aws lambda invoke \
    --function-name cleanup-snapshots-function \
    --payload '{
        "params": {
            "dry_run": false,
            "days_old": 60,
            "scan_all_regions": true,
            "require_untagged": true,
            "max_workers": 15
        }
    }' \
    response.json
```

### Event Payload Structure

```json
{
    "params": {
        "days_old": 30,
        "scan_all_regions": false,
        "dry_run": true,
        "require_untagged": false,
        "max_workers": 10
    }
}
```

### Response Structure

```json
{
    "statusCode": 200,
    "body": {
        "message": "EBS snapshot cleanup completed successfully (DRY RUN)",
        "results": {
            "region_results": [
                {
                    "region": "us-east-1",
                    "snapshots_analyzed": 150,
                    "snapshots_deleted": 25,
                    "snapshots_protected": 125,
                    "total_size_deleted_gb": 500,
                    "estimated_savings": 25.0,
                    "errors": []
                }
            ],
            "summary": {
                "total_regions_processed": 1,
                "total_snapshots_analyzed": 150,
                "total_snapshots_deleted": 25,
                "total_snapshots_protected": 125,
                "total_size_deleted_gb": 500,
                "total_estimated_savings": 25.0,
                "regions_with_errors": 0,
                "total_errors": 0
            },
            "cleanup_parameters": {
                "days_old": 30,
                "scan_all_regions": false,
                "dry_run": true,
                "require_untagged": false,
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

## Safety Features

### Comprehensive Protection Checks

1. **AMI Usage Detection**: Prevents deletion of snapshots used by AMIs
2. **Launch Template Protection**: Checks for launch template references
3. **Protection Tags**: Respects various protection tag patterns:
   - `DoNotDelete`, `do-not-delete`, `DONOTDELETE`
   - `Production`, `PRODUCTION`, `Prod`, `PROD`
   - `Critical`, `CRITICAL`, `Important`, `IMPORTANT`
   - `Keep`, `KEEP`, `Preserve`, `PRESERVE`
   - `Backup`, `BACKUP`, `Protected`, `PROTECTED`
4. **Recent Backup Detection**: Identifies recent backups by description keywords
5. **Environment Tags**: Protects production/staging environments

### Error Handling

- Graceful failure handling per region
- Continues processing if individual regions fail
- Detailed error reporting in response
- CloudWatch logs for debugging
- Access denied handling for restricted regions

## Performance Features

### Parallel Region Processing

- **ThreadPoolExecutor**: Thread-safe parallel execution
- **Configurable Concurrency**: 1-20 workers (default: 10)
- **Performance Gain**: 85-90% faster execution vs sequential
- **Example**: 35 regions scanned in 10-25 seconds vs 70-175 seconds

### Execution Time Estimates

| Regions | Workers | Snapshots/Region | Estimated Time |
|---------|---------|------------------|----------------|
| 1 | 1 | 100 | 5-10 seconds |
| 10 | 10 | 100 | 8-15 seconds |
| 35 | 15 | 100 | 15-25 seconds |
| 35 | 5 | 100 | 30-45 seconds |

## Monitoring

### CloudWatch Metrics

Monitor Lambda execution through CloudWatch:
- Duration
- Memory utilization  
- Error rate
- Invocation count

### CloudWatch Logs

Structured logging includes:
- Execution parameters
- Region processing progress
- Safety check results
- Deletion summaries
- Error details

### Custom Metrics

The function logs detailed statistics:
```
INFO Cleanup completed (DRY RUN). Regions processed: 3, Snapshots deleted: 45, Estimated savings: $67.50/month
```

## Cost Optimization

### Storage Cost Savings

Automatic calculation of monthly savings:
- AWS EBS snapshot pricing: ~$0.05 per GB-month
- Real-time cost impact reporting
- Cumulative savings tracking

### Lambda Execution Costs

Typical execution costs:
- **Memory**: 1024 MB
- **Duration**: 10-30 seconds (with parallelization)
- **Cost per execution**: $0.0001 - $0.0005
- **Monthly cost** (weekly execution): ~$0.002

### ROI Example

```
Snapshots cleaned: 100 snapshots × 20 GB = 2,000 GB
Monthly savings: 2,000 GB × $0.05 = $100/month
Annual savings: $1,200
Lambda costs: $0.024/year
ROI: 49,900%
```

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase timeout in template.yaml
   - Reduce max_workers to decrease memory usage
   - Enable scan_all_regions=false for faster execution

2. **Memory Limit Exceeded**
   - Increase MemorySize in template.yaml
   - Reduce max_workers for lower concurrency

3. **Permission Errors**
   - Verify IAM role has required permissions
   - Check for service-linked role requirements

### Debug Mode

Enable detailed logging:
```json
{
    "params": {
        "days_old": 30,
        "dry_run": true
    }
}
```

Check CloudWatch logs for detailed execution traces.

### Manual Testing

```bash
# Test specific regions
aws lambda invoke \
    --function-name cleanup-snapshots-function \
    --payload '{
        "params": {
            "scan_all_regions": false,
            "dry_run": true,
            "days_old": 90
        }
    }' \
    test-response.json

# View response
cat test-response.json | python -m json.tool
```

## Best Practices

### Deployment Strategy

1. **Start Conservative**: Begin with dry_run=true and high days_old values
2. **Test Thoroughly**: Use dev/staging environments first
3. **Monitor Execution**: Watch CloudWatch logs and metrics
4. **Gradual Rollout**: Reduce days_old gradually over time

### Operational Guidelines

1. **Schedule Appropriately**: Weekly or monthly execution
2. **Monitor Costs**: Track storage cost reductions
3. **Review Logs**: Regular log analysis for optimization
4. **Update Regularly**: Keep function updated with latest safety features

### Security Considerations

1. **Least Privilege**: IAM role with minimal required permissions
2. **Environment Separation**: Separate functions for dev/staging/prod
3. **Audit Trail**: CloudTrail logging for all snapshot deletions
4. **Compliance**: Ensure alignment with data retention policies

## Related Resources

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [EBS Snapshot Pricing](https://aws.amazon.com/ebs/pricing/)
- [AWS Data Lifecycle Manager](https://docs.aws.amazon.com/dlm/)

## Support

For issues, questions, or contributions:
1. Check CloudWatch logs for detailed error information
2. Review this documentation for configuration options
3. Test with dry_run=true before production deployment
4. Ensure IAM permissions are correctly configured