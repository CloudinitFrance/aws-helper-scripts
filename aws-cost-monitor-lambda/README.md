# AWS Cost Monitor - Lambda Version

Serverless AWS Lambda function for automated cost monitoring and alerting.

## 🎯 Overview

This Lambda function provides automated AWS cost monitoring with scheduled execution and threshold-based alerting. It's the serverless version of the [AWS Cost Monitor CLI tool](../aws-cost-monitor/).

## ✨ Features

- 💰 **Automated Cost Monitoring**: Scheduled daily/monthly cost tracking
- 📊 **Service-Level Breakdown**: Detailed cost analysis by AWS service
- 🚨 **Threshold Alerts**: Configurable spending alerts with SNS integration
- 📧 **FinOps SNS Notifications**: Automated cost alerts to dedicated FinOps topic
- 📈 **Cost Trend Analysis**: Historical cost tracking and analysis
- 💡 **Cost Optimization Guidance**: Built-in recommendations and action items
- ⏰ **Scheduled Execution**: CloudWatch Events trigger for automation
- 📋 **Structured Logging**: Comprehensive CloudWatch logs
- 🔒 **Secure**: IAM roles with least privilege permissions

## 🏗️ Architecture

```
CloudWatch Events (Schedule) → Lambda Function → Cost Explorer API
                                     ↓              ↓
                              CloudWatch Logs + FinOps SNS Alerts
                                     ↓
                              Cost Analysis & Optimization Recommendations
```

## 📋 Prerequisites

- AWS CLI configured with appropriate permissions
- AWS SAM CLI installed
- Python 3.11+ runtime support
- **The SNS topic 'FinOps' must be created in the deployment region before deploying this Lambda**

### Required AWS Permissions

The Lambda function requires these permissions (automatically configured in template):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "ce:GetUsageReport",
        "ce:GetDimensionValues",
        "ce:GetMetricStat",
        "budgets:ViewBudget",
        "budgets:DescribeBudgets",
        "sns:Publish",
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
cd helper-scripts/aws-cost-monitor-lambda/

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
    --stack-name aws-cost-monitor-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        DailyThreshold=200 \
        MonthlyThreshold=5000
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup
- **FinOps Team Setup**: After deployment, the FinOps team must subscribe to the "FinOps" SNS topic for cost threshold alerts

### FinOps SNS Notifications Setup

**IMPORTANT**: The FinOps team must subscribe to the "FinOps" SNS topic to receive automated cost threshold alerts.

1. **Find the SNS Topic ARN** (after deployment):
   ```bash
   aws cloudformation describe-stacks \
     --stack-name aws-cost-monitor-stack \
     --query 'Stacks[0].Outputs[?OutputKey==`FinOpsTopic`].OutputValue' \
     --output text
   ```

2. **Subscribe FinOps Team to SNS Topic**:
   ```bash
   # Email subscription (recommended)
   aws sns subscribe \
     --topic-arn arn:aws:sns:eu-west-1:ACCOUNT:FinOps \
     --protocol email \
     --notification-endpoint finops-team@company.com

   # SMS subscription (for critical alerts)
   aws sns subscribe \
     --topic-arn arn:aws:sns:eu-west-1:ACCOUNT:FinOps \
     --protocol sms \
     --notification-endpoint +1234567890

   # Slack webhook (via HTTPS endpoint)
   aws sns subscribe \
     --topic-arn arn:aws:sns:eu-west-1:ACCOUNT:FinOps \
     --protocol https \
     --notification-endpoint https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
   ```

3. **Confirm Subscriptions**: Check email/SMS and confirm the subscription.

### Alert Triggers

FinOps SNS notifications are sent when:
- **CRITICAL**: Monthly spending threshold exceeded
- **HIGH**: Daily spending threshold exceeded  
- The alert includes:
  - Account ID and timestamp
  - Total cost and spending breakdown by service
  - Cost trend analysis and optimization recommendations
  - Detailed investigation checklist and remediation actions

### 2. Configure Parameters

The function supports these environment variables and event parameters:

- `DAILY_THRESHOLD`: Daily spending alert threshold (USD)
- `MONTHLY_THRESHOLD`: Monthly spending alert threshold (USD)
- `ENVIRONMENT`: Environment name (dev/staging/prod)
- `FINOPS_TOPIC_ARN`: FinOps SNS topic ARN (automatically configured)

## 📊 Usage Examples

### Scheduled Execution (Default)

The function runs automatically based on the CloudWatch Events schedule:

```yaml
# Default: Daily at 9 AM UTC
Schedule: "cron(0 9 * * ? *)"
```

### Manual Invocation

```bash
# Test with default parameters (7 days)
aws lambda invoke \
  --function-name aws-cost-monitor-function \
  --payload '{"params": {"days": 7}}' \
  response.json

# Check current month with thresholds
aws lambda invoke \
  --function-name aws-cost-monitor-function \
  --payload '{
    "params": {
      "current_month": true,
      "daily_threshold": 100,
      "monthly_threshold": 3000
    }
  }' \
  response.json

# Custom date range
aws lambda invoke \
  --function-name aws-cost-monitor-function \
  --payload '{"params": {"days": 30}}' \
  response.json
```

### Event Payload Structure

```json
{
  "params": {
    "days": 7,
    "daily_threshold": 100.0,
    "monthly_threshold": 3000.0,
    "current_month": false
  }
}
```

## 📈 Response Format

### Successful Execution

```json
{
  "statusCode": 200,
  "body": {
    "message": "Cost monitoring completed successfully",
    "results": {
      "report": "=== AWS COST REPORT ===\n...",
      "alerts": [],
      "period": {
        "start_date": "2024-01-01",
        "end_date": "2024-01-08",
        "days": 7,
        "current_month": false
      },
      "thresholds": {
        "daily": 100.0,
        "monthly": 3000.0
      },
      "service_costs": {
        "top_services": [
          {"service": "Amazon EC2-Instance", "amount": 423.45, "percentage": 34.0},
          {"service": "Amazon RDS Service", "amount": 267.89, "percentage": 21.5},
          {"service": "Amazon S3", "amount": 156.23, "percentage": 12.5}
        ],
        "total_cost": 1247.83,
        "service_count": 15
      },
      "alert_count": 0
    },
    "executionId": "abc123-def456-ghi789",
    "alerts_triggered": false
  }
}
```

### With Alerts (HTTP 201)

```json
{
  "statusCode": 201,
  "body": {
    "message": "Cost monitoring completed successfully",
    "results": {
      "alerts": [
        "ALERT: Daily cost on 2024-01-07 ($125.50) exceeds threshold ($100.00)"
      ],
      "alert_count": 1
    },
    "alerts_triggered": true
  }
}
```

## 📧 FinOps SNS Notification Format

When cost thresholds are exceeded, the function sends comprehensive FinOps alerts via SNS:

### Sample FinOps Alert

```
AWS COST THRESHOLD ALERT
Severity: CRITICAL
Account: 123456789012
Timestamp: 2024-01-07 15:30:25 UTC

COST SUMMARY:
• Period: 2024-01-01 to 2024-01-07
• Total cost: $1,247.83
• Alert count: 2

CONFIGURED THRESHOLDS:
• Daily threshold: $100.00
• Monthly threshold: $3000.00

🔴 THRESHOLD BREACHES:
  • ALERT: Daily cost on 2024-01-07 ($125.50) exceeds threshold ($100.00)
  • ALERT: Monthly cost ($1,247.83) exceeds threshold ($1,000.00)

💰 TOP COST DRIVERS:
  • Amazon EC2-Instance: $423.45 (34.0%)
  • Amazon RDS Service: $267.89 (21.5%)
  • Amazon S3: $156.23 (12.5%)
  • Amazon CloudWatch: $89.67 (7.2%)
  • Amazon Lambda: $45.33 (3.6%)

📊 DAILY COST TREND:
  • 2024-01-01: $87.34
  • 2024-01-02: $92.45
  • 2024-01-03: $95.67
  • 2024-01-04: $102.34 ⚠️ OVER THRESHOLD
  • 2024-01-05: $109.45 ⚠️ OVER THRESHOLD
  • 2024-01-06: $115.67 ⚠️ OVER THRESHOLD
  • 2024-01-07: $125.50 ⚠️ OVER THRESHOLD

💡 IMMEDIATE ACTIONS RECOMMENDED:
1. Review top cost-driving services for optimization opportunities
2. Analyze usage patterns for unexpected spikes
3. Check for untagged or orphaned resources
4. Review Reserved Instance and Savings Plan coverage
5. Implement cost allocation tags for better visibility
6. Set up AWS Budgets for proactive monitoring

🔧 COST OPTIMIZATION TOOLS:
• AWS Cost Explorer: Detailed cost analysis and recommendations
• AWS Trusted Advisor: Cost optimization recommendations
• AWS Compute Optimizer: Right-sizing recommendations
• AWS Cost Anomaly Detection: Automated anomaly alerts

📋 INVESTIGATION CHECKLIST:
□ Check for new service deployments or scaling events
□ Review data transfer costs (especially cross-region)
□ Analyze storage costs and lifecycle policies
□ Verify auto-scaling group configurations
□ Check for development/test resources left running

📈 COST TREND ANALYSIS:
• Recent 3-day average: $116.87
• Period average: $103.21
• Trend: increasing

For detailed cost analysis, access AWS Cost Explorer or Cost Management dashboard.

This alert was generated by the automated AWS Cost Monitoring function.
```

### FinOps Alert Features

- **Severity Classification**: CRITICAL (monthly), HIGH (daily), MEDIUM (other thresholds)
- **Cost Breakdown**: Top 5 services with percentages
- **Trend Analysis**: Recent vs. overall averages
- **Daily Cost History**: Last 7 days with threshold indicators
- **Actionable Recommendations**: Immediate optimization steps
- **Investigation Tools**: Checklist for cost spike analysis
- **Cost Control Best Practices**: Long-term cost management guidance

## ⚙️ Configuration

### Environment Variables

Set via SAM template parameters:

```bash
# Deploy with custom thresholds
sam deploy \
  --parameter-overrides \
    Environment=prod \
    DailyThreshold=200 \
    MonthlyThreshold=5000
```

### Scheduled Execution

Modify the schedule in `template.yaml`:

```yaml
Parameters:
  Schedule:
    Type: String
    Default: "cron(0 9 * * ? *)"  # Daily at 9 AM UTC
    # Examples:
    # "cron(0 */6 * * ? *)"      # Every 6 hours
    # "cron(0 9 * * MON *)"      # Weekly on Monday
    # "rate(1 day)"              # Once per day
```

## 📊 Monitoring & Observability

### CloudWatch Metrics

Monitor your function performance:

```bash
# View function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=aws-cost-monitor-function \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### CloudWatch Logs

```bash
# View recent logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/aws-cost-monitor

# Stream logs in real-time
aws logs tail /aws/lambda/aws-cost-monitor-function --follow
```

### Custom Metrics

The function logs structured information for easy monitoring:

- Execution duration
- Cost analysis results
- Alert triggers
- API call statistics

## 🔧 Development

### Local Testing

```bash
# Build function locally
sam build

# Test with sample event
sam local invoke AwsCostMonitorFunction -e events/event.json

# Start local API for testing
sam local start-api
```

### Sample Events

Create test events in `events/` folder:

```json
// events/daily-check.json
{
  "params": {
    "days": 1,
    "daily_threshold": 50
  }
}

// events/monthly-check.json
{
  "params": {
    "current_month": true,
    "monthly_threshold": 2000
  }
}
```

## 🛠️ Customization

### Adding SNS Notifications

1. Add SNS topic to template.yaml:

```yaml
Resources:
  CostAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: cost-monitor-alerts
```

2. Update Lambda permissions and environment variables
3. Modify lambda_function.py to publish alerts

### Cost Allocation Tags

Modify the Cost Explorer query to group by tags:

```python
GroupBy=[
    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
    {'Type': 'TAG', 'Key': 'Environment'}
]
```

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure Cost Explorer permissions are granted
2. **No Data**: Cost Explorer data has 24-48 hour delay
3. **Timeout**: Increase function timeout for large accounts
4. **Memory Issues**: Increase memory allocation for complex reports

### Debug Mode

Enable detailed logging:

```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

## 💰 Cost Considerations

- **Execution Cost**: ~$0.20/month for daily execution
- **CloudWatch Logs**: ~$0.50/month for log storage
- **Cost Explorer API**: No additional charges for basic metrics

## 🔗 Related Resources

- [AWS Cost Explorer API Documentation](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html)
- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [CloudWatch Events Scheduling](https://docs.aws.amazon.com/eventbridge/latest/userguide/scheduled-events.html)
- [CLI Version Documentation](../aws-cost-monitor/README.md)

## 📝 License

Same as parent project - see main repository for license details.