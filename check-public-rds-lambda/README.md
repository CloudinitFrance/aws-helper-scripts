# Check Public RDS Instances - Lambda Version

Serverless AWS Lambda function for automated RDS security auditing and public exposure detection.

## 🎯 Overview

This Lambda function provides automated RDS security auditing with scheduled execution and intelligent alerting. It's the serverless version of the [Check Public RDS Instances CLI tool](../check-public-rds/).

## ✨ Features

- 🔍 **Automated RDS Security Auditing**: Scheduled scanning for publicly accessible RDS instances
- 🌐 **Multi-Region Support**: Parallel scanning across all AWS regions with configurable concurrency
- 🚨 **Risk Assessment**: Categorizes findings by risk level (CRITICAL, HIGH, MEDIUM, LOW)
- 📧 **SNS Security Alerts**: Automated notifications for CRITICAL and HIGH risk findings
- 🛡️ **Security Group Analysis**: Identifies open security group rules and misconfigurations
- 📊 **Comprehensive Analysis**: Storage encryption, backup settings, and VPC configuration
- ⚡ **High Performance**: Parallel region scanning reduces execution time by 85-90%
- 📋 **Detailed Reporting**: Structured JSON response with comprehensive instance metadata
- 🔒 **Secure**: IAM roles with least privilege permissions
- 📈 **Integration Ready**: JSON response format for SIEM and monitoring systems

## 🏗️ Architecture

```
CloudWatch Events (Schedule) → Lambda Function → RDS/EC2 APIs (All Regions)
                                     ↓              ↓
                              CloudWatch Logs + SNS Alerts (Critical/High Risk)
                                     ↓
                              Structured Response
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
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBSubnetGroups",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "sns:Publish",
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
cd helper-scripts/check-public-rds-lambda/

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
    --stack-name check-public-rds-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        ScanAllRegions=true \
        PublicOnly=true \
        MaxWorkers=15
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup
- **Security Team Setup**: After deployment, the security team must subscribe to the "SecurityFindings" SNS topic for critical security alerts

### SNS Security Alerts Setup

**CRITICAL**: The security team must subscribe to the "SecurityFindings" SNS topic to receive alerts for CRITICAL and HIGH risk RDS findings.

1. **Find the SNS Topic ARN** (after deployment):
   ```bash
   aws cloudformation describe-stacks \
     --stack-name check-public-rds-stack \
     --query 'Stacks[0].Outputs[?OutputKey==`SecurityFindingsTopic`].OutputValue' \
     --output text
   ```

2. **Subscribe Security Team to SNS Topic**:
   ```bash
   # Email subscription (recommended)
   aws sns subscribe \
     --topic-arn arn:aws:sns:eu-west-1:ACCOUNT:SecurityFindings \
     --protocol email \
     --notification-endpoint security-team@company.com

   # SMS subscription (for critical alerts)
   aws sns subscribe \
     --topic-arn arn:aws:sns:eu-west-1:ACCOUNT:SecurityFindings \
     --protocol sms \
     --notification-endpoint +1234567890

   # Slack webhook (via HTTPS endpoint)
   aws sns subscribe \
     --topic-arn arn:aws:sns:eu-west-1:ACCOUNT:SecurityFindings \
     --protocol https \
     --notification-endpoint https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
   ```

3. **Confirm Subscriptions**: Check email/SMS and confirm the subscription.

### Alert Triggers

SNS notifications are sent when:
- **CRITICAL Risk**: Public RDS instances with overly permissive security groups (0.0.0.0/0 access)
- **HIGH Risk**: Any publicly accessible RDS instance
- The alert includes:
  - Account ID and timestamp
  - Database identifiers, engine types, and encryption status
  - Security group configurations and endpoint details
  - Immediate remediation recommendations

### 2. Configure Parameters

The function supports these environment variables and event parameters:

- `SCAN_ALL_REGIONS`: Scan all regions vs current region only (default: false)
- `PUBLIC_ONLY`: Only report publicly accessible instances (default: true)
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
# Scan current region for public RDS instances
aws lambda invoke \
  --function-name check-public-rds-function \
  --payload '{"params": {"scan_all_regions": false, "public_only": true}}' \
  response.json

# Full security audit across all regions
aws lambda invoke \
  --function-name check-public-rds-function \
  --payload '{
    "params": {
      "scan_all_regions": true,
      "public_only": false,
      "max_workers": 15
    }
  }' \
  response.json

# High-performance scan of all regions (public only)
aws lambda invoke \
  --function-name check-public-rds-function \
  --payload '{
    "params": {
      "scan_all_regions": true,
      "public_only": true,
      "max_workers": 20
    }
  }' \
  response.json
```

### Event Payload Structure

```json
{
  "params": {
    "scan_all_regions": true,
    "public_only": true,
    "max_workers": 10
  }
}
```

## 📈 Response Format

### Successful Execution (No Security Issues)

```json
{
  "statusCode": 200,
  "body": {
    "message": "RDS security audit completed successfully",
    "results": {
      "instances": [],
      "summary": {
        "total_instances": 5,
        "public_instances": 0,
        "encrypted_instances": 5,
        "critical_risk": 0,
        "high_risk": 0,
        "medium_risk": 0,
        "low_risk": 5,
        "unencrypted_instances": 0
      },
      "audit_parameters": {
        "scan_all_regions": true,
        "public_only": true,
        "max_workers": 10,
        "account_id": "123456789012",
        "caller_arn": "arn:aws:sts::123456789012:assumed-role/SecurityAuditor/user"
      }
    },
    "executionId": "abc123-def456-ghi789",
    "alerts_triggered": false
  }
}
```

### With Security Violations (HTTP 201)

```json
{
  "statusCode": 201,
  "body": {
    "message": "RDS security audit completed successfully",
    "results": {
      "instances": [
        {
          "Region": "us-east-1",
          "DBInstanceIdentifier": "production-db",
          "Engine": "mysql",
          "EngineVersion": "8.0.35",
          "DBInstanceClass": "db.t3.medium",
          "PubliclyAccessible": true,
          "Endpoint": "production-db.cluster-xxx.us-east-1.rds.amazonaws.com",
          "Port": 3306,
          "StorageEncrypted": false,
          "MultiAZ": true,
          "BackupRetentionPeriod": 7,
          "VpcId": "vpc-12345678",
          "SubnetGroup": "default",
          "SecurityGroups": [
            {
              "GroupId": "sg-12345678",
              "Status": "active"
            }
          ],
          "SecurityIssues": [
            {
              "SecurityGroupId": "sg-12345678",
              "Issue": "Port 3306 open to 0.0.0.0/0",
              "Risk": "Critical",
              "Protocol": "tcp"
            }
          ],
          "RiskLevel": "Critical"
        }
      ],
      "summary": {
        "total_instances": 6,
        "public_instances": 1,
        "encrypted_instances": 5,
        "critical_risk": 1,
        "high_risk": 0,
        "medium_risk": 1,
        "low_risk": 4,
        "unencrypted_instances": 1
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
    ScanAllRegions=true \
    PublicOnly=false \
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
    # "cron(0 8 * * MON-FRI *)"     # Weekdays at 8 AM UTC
    # "rate(1 day)"                 # Once per day
```

### Risk Level Categorization

The function categorizes instances into risk levels:

- **CRITICAL**: Public instances with security group issues (0.0.0.0/0 access)
- **HIGH**: Public instances with less severe security group issues
- **MEDIUM**: Public instances with secure security groups OR private unencrypted instances
- **LOW**: Private instances with encryption enabled

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
- **Sequential**: ~35 regions × 3-4 seconds = 105-140 seconds
- **Parallel (10 workers)**: ~15-20 seconds total execution time

## 📊 Monitoring & Observability

### CloudWatch Metrics

Monitor your function performance:

```bash
# View function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=check-public-rds-function \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### CloudWatch Logs

```bash
# View recent logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/check-public-rds

# Stream logs in real-time
aws logs tail /aws/lambda/check-public-rds-function --follow
```

### Security Alerts

The function automatically triggers alerts when:
- Publicly accessible RDS instances are detected (SNS + CloudWatch)
- Critical security group misconfigurations are found (SNS + CloudWatch)
- Unencrypted public databases are discovered (SNS + CloudWatch)

**SNS Alert Format**: Detailed notifications include database details, security analysis, and remediation steps.

## 🔧 Development

### Local Testing

```bash
# Build function locally
sam build

# Test with sample event
sam local invoke CheckPublicRdsFunction -e events/event.json

# Start local API for testing
sam local start-api
```

### Sample Events

Create test events in `events/` folder:

```json
// events/current-region.json
{
  "params": {
    "scan_all_regions": false,
    "public_only": true,
    "max_workers": 5
  }
}

// events/all-regions-public.json
{
  "params": {
    "scan_all_regions": true,
    "public_only": true,
    "max_workers": 15
  }
}

// events/full-audit.json
{
  "params": {
    "scan_all_regions": true,
    "public_only": false,
    "max_workers": 10
  }
}
```

## 🛠️ Customization

### SNS Notifications (Built-in)

The function includes automatic SNS notifications for security findings:

- **Topic Name**: `SecurityFindings`
- **Triggers**: CRITICAL and HIGH risk RDS instances
- **Content**: Detailed security analysis with remediation steps
- **Format**: Structured alerts with account info, timestamps, and database details

Subscribe your security team using the commands in the deployment section above.

### Custom Risk Assessment

Modify the risk level logic in `analyze_rds_security`:

```python
# Custom risk assessment for specific engines
if instance_info['Engine'] in ['postgres', 'mysql']:
    if instance_info['PubliclyAccessible'] and not instance_info['StorageEncrypted']:
        instance_info['RiskLevel'] = 'Critical'
```

### Integration with Security Tools

The structured JSON response integrates with:

- **AWS Security Hub**: Convert findings to ASFF format
- **Splunk/ELK**: Parse logs for security monitoring
- **PagerDuty**: Alert on critical database exposures
- **Slack/Teams**: Send security compliance reports
- **AWS Config**: Create compliance rules based on findings

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure Lambda execution role has required RDS and EC2 permissions
2. **Timeout**: Increase function timeout for accounts with many RDS instances
3. **Rate Limiting**: RDS API has rate limits; function includes retry logic
4. **Memory Issues**: Increase memory allocation for large-scale audits

### Debug Mode

Enable detailed logging:

```python
import logging
logger.setLevel(logging.DEBUG)
```

### Performance Optimization

For very large AWS accounts (100+ RDS instances):

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

## 🔐 Security Best Practices

### Compliance Integration

Use this function for:
- **PCI DSS Compliance**: Database security requirements
- **SOC 2**: Infrastructure security monitoring
- **GDPR**: Data protection and privacy audits
- **HIPAA**: Healthcare data security compliance

### Automated Remediation

Integrate with AWS Systems Manager for automated remediation:

```python
# Example: Disable public access for critical risk instances
def remediate_public_access(instance_id, region):
    rds_client = boto3.client('rds', region_name=region)
    rds_client.modify_db_instance(
        DBInstanceIdentifier=instance_id,
        PubliclyAccessible=False
    )
```

## 💰 Cost Considerations

- **Execution Cost**: ~$0.80/month for weekly execution across all regions
- **CloudWatch Logs**: ~$1.00/month for log storage
- **RDS API Calls**: No additional charges for DescribeDBInstances calls

## 🔗 Related Resources

- [AWS RDS Security Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html)
- [RDS Security Groups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
- [RDS Encryption](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html)
- [CLI Version Documentation](../check-public-rds/README.md)

## 📝 License

Same as parent project - see main repository for license details.