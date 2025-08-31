# AWS Lambda Deprecated Runtime Detector - Lambda Version

Serverless AWS Lambda function for automated detection and monitoring of deprecated Lambda runtimes across your AWS infrastructure.

## 🎯 Overview

This Lambda function provides automated AWS Lambda runtime auditing with scheduled execution and intelligent alerting. It's the serverless version of the [AWS Lambda Deprecated Runtime Detector CLI tool](../aws-deprecated-lambdas-runtime/).

## ✨ Features

- 🔍 **Automated Runtime Detection**: Scheduled scanning for deprecated Lambda runtimes
- 🌐 **Multi-Region Support**: Parallel scanning across all AWS regions with configurable concurrency
- 📊 **Dynamic Runtime Data**: Fetches latest deprecation information from AWS documentation
- 🚨 **Risk Assessment**: Categorizes findings by urgency (CRITICAL, HIGH, MEDIUM)
- ⚡ **High Performance**: Parallel region scanning reduces execution time by 85-90%
- 📋 **Comprehensive Reporting**: Detailed function metadata and deprecation timelines
- 🔒 **Secure**: IAM roles with least privilege permissions
- 📈 **Structured Output**: JSON response format for integration with other systems

## 🏗️ Architecture

```
CloudWatch Events (Schedule) → Lambda Function → AWS Lambda API (All Regions)
                                     ↓
                              AWS Documentation (Runtime Info)
                                     ↓
                              CloudWatch Logs + Structured Response
```

## 📋 Prerequisites

- AWS CLI configured with appropriate permissions
- AWS SAM CLI installed
- Python 3.11+ runtime support
- **The SNS topic 'SecurityFindings' must be created in the deployment region before deploying this Lambda**

### Required AWS Permissions

The Lambda function requires these permissions (automatically configured in template):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunction",
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

## 🚀 Quick Start

### Quick Deployment
```bash
# Clone and navigate
git clone <repository-url>
cd helper-scripts/aws-deprecated-lambdas-runtime-lambda/

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
    --stack-name aws-deprecated-lambdas-runtime-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        MonthsAhead=12 \
        ScanAllRegions=true \
        MaxWorkers=15
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup

### 2. Configure Parameters

The function supports these environment variables and event parameters:

- `MONTHS_AHEAD`: Check for runtimes deprecated within N months (default: 6)
- `SCAN_ALL_REGIONS`: Scan all regions vs current region only (default: false)
- `MAX_WORKERS`: Maximum parallel workers for region scanning (default: 10)
- `ENVIRONMENT`: Environment name (dev/staging/prod)

## 📊 Usage Examples

### Scheduled Execution (Default)

The function runs automatically based on the CloudWatch Events schedule:

```yaml
# Default: Weekly on Monday at 9 AM UTC
Schedule: "cron(0 9 * * MON *)"
```

### Manual Invocation

```bash
# Test with default parameters (6 months, current region)
aws lambda invoke \
  --function-name aws-deprecated-lambdas-runtime-function \
  --payload '{"params": {}}' \
  response.json

# Check all regions with custom timeframe
aws lambda invoke \
  --function-name aws-deprecated-lambdas-runtime-function \
  --payload '{
    "params": {
      "months_ahead": 12,
      "scan_all_regions": true,
      "max_workers": 15
    }
  }' \
  response.json

# Quick scan of current region only
aws lambda invoke \
  --function-name aws-deprecated-lambdas-runtime-function \
  --payload '{
    "params": {
      "months_ahead": 3,
      "scan_all_regions": false
    }
  }' \
  response.json
```

### Event Payload Structure

```json
{
  "params": {
    "months_ahead": 6,
    "scan_all_regions": true,
    "max_workers": 10
  }
}
```

## 📈 Response Format

### Successful Execution (No Issues)

```json
{
  "statusCode": 200,
  "body": {
    "message": "Runtime analysis completed successfully",
    "results": {
      "at_risk_functions": [],
      "summary": {
        "total_functions": 0,
        "critical_functions": 0,
        "high_risk_functions": 0,
        "medium_risk_functions": 0
      },
      "analysis_parameters": {
        "months_ahead": 6,
        "scan_all_regions": true,
        "deprecated_runtimes_found": 15,
        "supported_runtimes_found": 25,
        "at_risk_runtimes": []
      }
    },
    "executionId": "abc123-def456-ghi789",
    "alerts_triggered": false
  }
}
```

### With Critical Alerts (HTTP 201)

```json
{
  "statusCode": 201,
  "body": {
    "message": "Runtime analysis completed successfully",
    "results": {
      "at_risk_functions": [
        {
          "region": "us-east-1",
          "function_name": "legacy-api-handler",
          "function_arn": "arn:aws:lambda:us-east-1:123456789012:function:legacy-api-handler",
          "runtime": "python3.6",
          "runtime_name": "Python 3.6",
          "deprecation_date": "Jul 18, 2022",
          "status": "DEPRECATED",
          "urgency": "CRITICAL",
          "last_modified": "2022-01-15T10:30:00.000+0000",
          "code_size": 1024576,
          "memory_size": 128,
          "timeout": 30
        }
      ],
      "summary": {
        "total_functions": 1,
        "critical_functions": 1,
        "high_risk_functions": 0,
        "medium_risk_functions": 0
      }
    },
    "alerts_triggered": true
  }
}
```

## ⚙️ Configuration

### Environment Variables

Set via SAM template parameters:

```bash
# Deploy with custom configuration
sam deploy \
  --parameter-overrides \
    Environment=prod \
    MonthsAhead=12 \
    ScanAllRegions=true \
    MaxWorkers=15
```

### Scheduled Execution

Modify the schedule in `template.yaml`:

```yaml
Parameters:
  Schedule:
    Type: String
    Default: "cron(0 9 * * MON *)"  # Weekly on Monday at 9 AM UTC
    # Examples:
    # "cron(0 9 * * ? *)"           # Daily at 9 AM UTC
    # "cron(0 */6 * * ? *)"         # Every 6 hours
    # "rate(1 day)"                 # Once per day
```

### Performance Tuning

The function uses parallel processing for optimal performance:

```yaml
Parameters:
  MaxWorkers:
    Type: Number
    Default: 10
    MinValue: 1
    MaxValue: 20
    Description: "Parallel workers for region scanning"
```

**Performance Impact:**
- **Sequential**: ~35 regions × 2-3 seconds = 70-105 seconds
- **Parallel (10 workers)**: ~10-15 seconds total execution time

## 📊 Monitoring & Observability

### CloudWatch Metrics

Monitor your function performance:

```bash
# View function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=aws-deprecated-lambdas-runtime-function \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### CloudWatch Logs

```bash
# View recent logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/aws-deprecated-lambdas-runtime

# Stream logs in real-time
aws logs tail /aws/lambda/aws-deprecated-lambdas-runtime-function --follow
```

### Structured Logging

The function logs comprehensive information:

- Execution configuration and parameters
- Runtime information fetching results
- Region scanning progress and results
- Performance metrics and timing
- Alert triggers and risk assessments

## 🔧 Development

### Local Testing

```bash
# Build function locally
sam build

# Test with sample event
sam local invoke AwsDeprecatedLambdasRuntimeFunction -e events/event.json

# Start local API for testing
sam local start-api
```

### Sample Events

Create test events in `events/` folder:

```json
// events/default-scan.json
{
  "params": {
    "months_ahead": 6,
    "scan_all_regions": false
  }
}

// events/full-scan.json
{
  "params": {
    "months_ahead": 12,
    "scan_all_regions": true,
    "max_workers": 15
  }
}

// events/quick-scan.json
{
  "params": {
    "months_ahead": 3,
    "scan_all_regions": false,
    "max_workers": 5
  }
}
```

## 🛠️ Customization

### Adding SNS Notifications

1. Add SNS topic to template.yaml:

```yaml
Resources:
  RuntimeAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: deprecated-runtime-alerts
```

2. Update Lambda permissions and environment variables
3. Modify lambda_function.py to publish alerts for critical findings

### Custom Risk Assessment

Modify the urgency categorization logic:

```python
# In filter_at_risk_runtimes function
if deprecation_date <= current_date:
    info['urgency'] = 'CRITICAL'
elif days_until <= 30:  # Custom: 30 days instead of 90
    info['urgency'] = 'HIGH'
else:
    info['urgency'] = 'MEDIUM'
```

### Integration with Security Tools

The structured JSON response format makes it easy to integrate with:

- **AWS Security Hub**: Convert findings to Security Hub format
- **Slack/Teams**: Parse results and send notifications
- **JIRA**: Create tickets for critical runtime issues
- **Monitoring Systems**: Alert on specific urgency levels

## 🚨 Troubleshooting

### Common Issues

1. **Function Timeout**: Increase timeout or reduce max_workers for large AWS accounts
2. **Memory Issues**: Increase memory allocation if processing many functions
3. **Rate Limiting**: AWS Lambda API has rate limits; the function includes retry logic
4. **Network Issues**: Function needs internet access to fetch AWS documentation

### Debug Mode

Enable detailed logging by modifying the function:

```python
import logging
logger.setLevel(logging.DEBUG)
```

### Performance Optimization

For very large AWS accounts (1000+ Lambda functions):

```yaml
# Increase function resources
Globals:
  Function:
    Timeout: 900          # 15 minutes
    MemorySize: 1024      # 1GB memory
    
# Reduce parallel workers to avoid rate limits
Parameters:
  MaxWorkers:
    Default: 8            # Reduced from 10
```

## 💰 Cost Considerations

- **Execution Cost**: ~$0.50/month for weekly execution
- **CloudWatch Logs**: ~$1.00/month for log storage
- **Lambda API Calls**: No additional charges for basic operations
- **Internet Access**: Data transfer costs for AWS documentation fetch (~$0.01/month)

## 🔗 Related Resources

- [AWS Lambda Runtime Deprecation Policy](https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html)
- [AWS Lambda Runtimes Documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [CloudWatch Events Scheduling](https://docs.aws.amazon.com/eventbridge/latest/userguide/scheduled-events.html)
- [CLI Version Documentation](../aws-deprecated-lambdas-runtime/README.md)

## 📝 License

Same as parent project - see main repository for license details.