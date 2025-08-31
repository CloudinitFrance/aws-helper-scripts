# AWS Cost Monitor

A Python script to monitor AWS costs, track spending trends, and alert on budget thresholds.

## Features

- 💰 Daily and monthly cost tracking
- 📊 Service-level cost breakdown
- 🚨 Configurable spending alerts
- 📈 Advanced cost trend analysis with 3-day averages
- 📧 **FinOps SNS notifications** for threshold breaches
- 📄 Export reports in text format
- 🔍 Support for cost anomaly detection
- 🎯 **Environment variable support** for automated deployments
- 📊 **Comprehensive cost insights** with remediation recommendations

## Prerequisites

```bash
# Install required Python library
pip install boto3

# Configure AWS credentials
aws configure

# Or configure multiple profiles for different environments
aws configure --profile production
aws configure --profile staging
```

## Usage

```bash
# Basic usage - last 7 days
python3 aws_cost_monitor_cli.py

# Use specific AWS profile
python3 aws_cost_monitor_cli.py --profile production

# Check current month costs
python3 aws_cost_monitor_cli.py --current-month

# Set alert thresholds with specific profile
python3 aws_cost_monitor_cli.py --daily-threshold 100 --monthly-threshold 3000 --profile production

# Custom date range
python3 aws_cost_monitor_cli.py --days 30

# Save report to file
python3 aws_cost_monitor_cli.py --output my_cost_report.txt --profile staging
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--days` | Number of days to analyze | 7 |
| `--daily-threshold` | Daily cost alert threshold (USD) | None |
| `--monthly-threshold` | Monthly cost alert threshold (USD) | None |
| `--output` | Output file for report | aws_cost_report.txt |
| `--current-month` | Analyze current month instead of last N days | False |
| `--profile` | AWS profile to use for credentials | None (uses default) |
| `--finops-alert` | Send comprehensive FinOps notifications via SNS | False |
| `--sns-topic` | SNS topic ARN for FinOps notifications | None |
| `--show-trends` | Include detailed cost trend analysis in output | False |

## Examples

### Monitor Weekly Costs
```bash
python3 aws_cost_monitor_cli.py --days 7 --profile production
```

### Set Up Cost Alerts
```bash
# Alert if daily costs exceed $150 or monthly exceed $4000
python3 aws_cost_monitor_cli.py \
  --daily-threshold 150 \
  --monthly-threshold 4000 \
  --current-month \
  --profile production
```

### Generate Monthly Report with Trends
```bash
# Generate report for the current month with trend analysis
python3 aws_cost_monitor_cli.py \
  --current-month \
  --profile production \
  --show-trends \
  --output monthly_report_$(date +%Y-%m).txt
```

### FinOps Alerts with SNS Notifications
```bash
# Send comprehensive FinOps alerts when thresholds are exceeded
python3 aws_cost_monitor_cli.py \
  --daily-threshold 100 \
  --finops-alert \
  --sns-topic arn:aws:sns:us-east-1:123456789012:cost-alerts \
  --profile production
```

### Environment Variable Configuration
```bash
# Set thresholds via environment variables
export DAILY_THRESHOLD=150
export MONTHLY_THRESHOLD=4000
python3 aws_cost_monitor_cli.py --profile production
```

### Multi-Environment Monitoring
```bash
# Monitor production environment
python3 aws_cost_monitor_cli.py --profile production --daily-threshold 200

# Monitor staging environment with lower threshold
python3 aws_cost_monitor_cli.py --profile staging --daily-threshold 50
```

## Output Format

The script generates a detailed cost report showing:

```
============================================================
AWS COST REPORT
============================================================

Date: 2024-01-15
----------------------------------------
  EC2                           $   45.32
  RDS                           $   23.15
  S3                            $   12.89
  Lambda                        $    3.45
----------------------------------------
  DAILY TOTAL                   $   84.81

============================================================
  PERIOD TOTAL                  $  593.67
============================================================
```

## Alerts

When thresholds are exceeded, you'll see alerts like:

```
⚠️  ALERTS ⚠️
  ALERT: Daily cost on 2024-01-15 ($125.43) exceeds threshold ($100.00)
  ALERT: Monthly cost ($3,245.67) exceeds threshold ($3,000.00)
```

## AWS Permissions Required

The IAM user/role needs the following permissions:

### Basic Cost Monitoring
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ce:GetCostAndUsage"
            ],
            "Resource": "*"
        }
    ]
}
```

### FinOps SNS Notifications (Additional)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ce:GetCostAndUsage",
                "sns:Publish",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### SNS Topic Setup
```bash
# Create SNS topic for cost alerts
aws sns create-topic --name cost-alerts --profile production

# Subscribe email to topic
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:cost-alerts \
  --protocol email \
  --notification-endpoint finops-team@company.com \
  --profile production
```

## Scheduling

To run automatically, add to crontab:

```bash
# Daily cost check at 9 AM for production environment with FinOps alerts
0 9 * * * /usr/bin/python3 /path/to/aws_cost_monitor_cli.py --daily-threshold 100 --finops-alert --sns-topic arn:aws:sns:us-east-1:123456789012:cost-alerts --profile production

# Weekly report on Mondays for production
0 8 * * 1 /usr/bin/python3 /path/to/aws_cost_monitor_cli.py --days 7 --profile production --output /path/to/weekly_report_prod.txt

# Daily staging environment check at 10 AM with lower threshold
0 10 * * * /usr/bin/python3 /path/to/aws_cost_monitor_cli.py --daily-threshold 25 --profile staging --output /path/to/staging_costs.txt

# Monthly cost summary on the 1st of each month
0 9 1 * * /usr/bin/python3 /path/to/aws_cost_monitor_cli.py --current-month --profile production --monthly-threshold 5000
```

## Tips

1. **Cost Allocation Tags**: Enable cost allocation tags in AWS for more detailed tracking
2. **Multiple Accounts**: Use AWS Organizations for consolidated billing views
3. **Budget Actions**: Combine with AWS Budgets for automated responses
4. **Historical Data**: AWS provides up to 12 months of historical cost data
5. **Profile Management**: Use different AWS profiles for production, staging, and development environments
6. **Environment Isolation**: Set different cost thresholds per environment using profiles
7. **FinOps Integration**: Use SNS notifications to integrate with your FinOps workflow
8. **Automated Monitoring**: Combine with Lambda for serverless cost monitoring
9. **Trend Detection**: Enable `--show-trends` for advanced cost pattern analysis
10. **Environment Variables**: Use `DAILY_THRESHOLD` and `MONTHLY_THRESHOLD` for CI/CD integration

## FinOps Notification Features

The `--finops-alert` flag enables comprehensive cost management notifications that include:

- **Threshold Breach Alerts**: Detailed breakdown of costs exceeding limits
- **Cost Trend Analysis**: 3-day rolling averages with trend detection (increasing/stable/decreasing)
- **Top Cost Drivers**: Identification of services contributing most to costs
- **Immediate Action Items**: Specific recommendations for cost optimization
- **Investigation Checklist**: Structured approach to cost anomaly investigation
- **Remediation Commands**: Ready-to-use AWS CLI commands for cost reduction

### Sample FinOps Notification
```
AWS COST THRESHOLD ALERT
Risk Level: HIGH
Account: 123456789012
Timestamp: 2024-01-15 09:30:00 UTC

SUMMARY:
• Total cost analyzed: $2,847.63
• Daily threshold: $150.00
• Monthly threshold: $3,000.00

🔴 THRESHOLD BREACHES:
• 2024-01-15: $287.45 ⚠️ OVER THRESHOLD (Daily: $150.00)
• Monthly total: $2,847.63 (approaching limit: $3,000.00)

📈 COST TRENDS (3-day average):
• Trend: INCREASING (+15.3%)
• Recent average: $264.32/day
• Previous average: $229.18/day

💰 TOP COST DRIVERS:
• EC2-Instance: $145.23 (50.7%) ⚠️ OVER THRESHOLD
• RDS: $89.45 (31.1%)
• S3: $52.77 (18.4%)

IMMEDiate Actions Required:
1. Review EC2 instance usage and rightsizing opportunities
2. Analyze RDS performance and utilization metrics
3. Check for unused or oversized resources
4. Consider Reserved Instance purchases for steady workloads
5. Review S3 storage classes and lifecycle policies
```

## Troubleshooting

### SNS Notification Issues
**"Failed to send SNS notification"**
- Verify SNS topic ARN is correct
- Check IAM permissions include `sns:Publish`
- Ensure SNS topic exists in the same region
- Confirm topic policy allows your IAM role to publish

**"No FinOps notifications sent"**
- Verify `--finops-alert` flag is used
- Check if thresholds are actually exceeded
- Ensure `--sns-topic` parameter is provided
- Review CloudWatch logs for detailed error messages

**"No cost data available"**
- Ensure AWS credentials are configured correctly
- Check if the account has Cost Explorer API enabled
- Verify IAM permissions
- Confirm the correct AWS profile is being used: `aws sts get-caller-identity --profile your-profile`

**"Access Denied"**
- Add the required Cost Explorer permissions to your IAM user/role
- Verify the AWS profile has the necessary permissions

**"AWS profile 'profile-name' not found"**
- List available profiles: `aws configure list-profiles`
- Configure the missing profile: `aws configure --profile profile-name`

**Incomplete data**
- Cost data may have up to 24-hour delay
- Some services report costs with delays
- Ensure you're checking the correct AWS account using the right profile
