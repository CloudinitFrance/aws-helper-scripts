# Check Public S3 Buckets - Lambda Version

Serverless AWS Lambda function for automated S3 security auditing and public exposure detection.

## 🎯 Overview

This Lambda function provides automated S3 security auditing with scheduled execution and intelligent alerting. It's the serverless version of the [Check Public S3 Buckets CLI tool](../check-public-s3/).

## ✨ Features

- 🔍 **Automated S3 Security Auditing**: Scheduled scanning for publicly accessible S3 buckets
- 🌐 **Global Bucket Analysis**: S3 is a global service - scans all buckets regardless of region
- 🚨 **Risk Assessment**: Categorizes findings by risk level (CRITICAL, HIGH, MEDIUM, LOW)
- 📧 **SNS Security Alerts**: Automated notifications for CRITICAL and HIGH risk findings
- 🛡️ **Comprehensive Security Checks**: ACL, bucket policies, public access blocks, encryption
- 📊 **Policy Analysis**: Intelligent parsing of bucket policies for public access patterns
- 📋 **Detailed Configuration Review**: Versioning, logging, website hosting, encryption
- 🔒 **Secure**: IAM roles with least privilege permissions
- 📈 **Integration Ready**: JSON response format for SIEM and monitoring systems

## 🏗️ Architecture

```
CloudWatch Events (Schedule) → Lambda Function → S3 API (Global)
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
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
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
cd helper-scripts/check-public-s3-lambda/

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
    --stack-name check-public-s3-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        PublicOnly=true
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup
- **Security Team Setup**: After deployment, the security team must subscribe to the "SecurityFindings" SNS topic for critical security alerts

### SNS Security Alerts Setup

**CRITICAL**: The security team must subscribe to the "SecurityFindings" SNS topic to receive alerts for CRITICAL and HIGH risk findings.

1. **Find the SNS Topic ARN** (after deployment):
   ```bash
   aws cloudformation describe-stacks \
     --stack-name check-public-s3-stack \
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
- **CRITICAL Risk**: S3 buckets with public write access are detected
- **HIGH Risk**: S3 buckets with public read access are found
- The alert includes:
  - Account ID and timestamp
  - Detailed bucket names and security issues
  - Risk summary and statistics
  - Immediate remediation recommendations

### 2. Configure Parameters

The function supports these environment variables and event parameters:

- `PUBLIC_ONLY`: Only report publicly accessible buckets (default: true)
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
# Scan for public S3 buckets only
aws lambda invoke \
  --function-name check-public-s3-function \
  --payload '{"params": {"public_only": true}}' \
  response.json

# Full security audit of all buckets
aws lambda invoke \
  --function-name check-public-s3-function \
  --payload '{"params": {"public_only": false}}' \
  response.json

# Quick public bucket check
aws lambda invoke \
  --function-name check-public-s3-function \
  --payload '{}' \
  response.json
```

### Event Payload Structure

```json
{
  "params": {
    "public_only": true
  }
}
```

## 📈 Response Format

### Successful Execution (No Security Issues)

```json
{
  "statusCode": 200,
  "body": {
    "message": "S3 security audit completed successfully",
    "results": {
      "buckets": [],
      "summary": {
        "total_buckets": 10,
        "public_buckets": 0,
        "encrypted_buckets": 8,
        "versioned_buckets": 6,
        "critical_risk": 0,
        "high_risk": 0,
        "medium_risk": 2,
        "low_risk": 8,
        "unencrypted_buckets": 2
      },
      "audit_parameters": {
        "public_only": true,
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
    "message": "S3 security audit completed successfully",
    "results": {
      "buckets": [
        {
          "BucketName": "public-website-bucket",
          "Region": "us-east-1",
          "IsPublic": true,
          "RiskLevel": "High",
          "SecurityIssues": [
            "Bucket is public via bucket policy",
            "Bucket is public and configured for website hosting"
          ],
          "PublicAccessBlock": {
            "HasPublicAccessBlock": false,
            "BlockPublicAcls": false,
            "IgnorePublicAcls": false,
            "BlockPublicPolicy": false,
            "RestrictPublicBuckets": false,
            "IsFullyBlocked": false
          },
          "BucketPolicy": {
            "HasBucketPolicy": true,
            "IsPublicPolicy": true,
            "PolicyDocument": "..."
          },
          "BucketACL": {
            "PublicRead": false,
            "PublicWrite": false,
            "AuthenticatedRead": false,
            "IsPublicACL": false
          },
          "WebsiteHosting": {
            "HasWebsiteHosting": true,
            "IndexDocument": "index.html",
            "ErrorDocument": "error.html"
          },
          "Encryption": {
            "HasEncryption": true,
            "EncryptionType": "AES256"
          },
          "Versioning": {
            "VersioningEnabled": false,
            "VersioningStatus": "Disabled",
            "MfaDeleteEnabled": false
          },
          "Logging": {
            "AccessLoggingEnabled": false
          }
        }
      ],
      "summary": {
        "total_buckets": 11,
        "public_buckets": 1,
        "encrypted_buckets": 9,
        "versioned_buckets": 6,
        "critical_risk": 0,
        "high_risk": 1,
        "medium_risk": 2,
        "low_risk": 8,
        "unencrypted_buckets": 2
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
    PublicOnly=false
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

The function categorizes buckets into risk levels:

- **CRITICAL**: Buckets with public write access
- **HIGH**: Public buckets via ACL or policy
- **MEDIUM**: Private buckets without encryption
- **LOW**: Private buckets with proper security configurations

## 📊 Security Checks Performed

### Public Access Analysis

1. **Public Access Block Settings**: Checks all four public access block configurations
2. **Bucket ACL Analysis**: Identifies public read/write permissions and authenticated user access
3. **Bucket Policy Parsing**: Analyzes JSON policies for wildcard principals and public access patterns
4. **Website Hosting Detection**: Identifies buckets configured for static website hosting

### Security Configuration Review

1. **Encryption Status**: Server-side encryption configuration (AES256, KMS)
2. **Versioning Configuration**: Object versioning and MFA delete settings
3. **Access Logging**: Bucket access logging configuration
4. **Region Detection**: Identifies the region where each bucket resides

## 📊 Monitoring & Observability

### CloudWatch Metrics

Monitor your function performance:

```bash
# View function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=check-public-s3-function \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### CloudWatch Logs

```bash
# View recent logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/check-public-s3

# Stream logs in real-time
aws logs tail /aws/lambda/check-public-s3-function --follow
```

### Security Alerts

The function automatically triggers alerts when:
- Publicly accessible S3 buckets are detected (SNS + CloudWatch)
- Critical bucket misconfigurations are found (SNS + CloudWatch)
- Buckets with public write access are discovered (SNS + CloudWatch)

**SNS Alert Format**: Detailed notifications include bucket names, security issues, risk levels, and remediation steps.

## 🔧 Development

### Local Testing

```bash
# Build function locally
sam build

# Test with sample event
sam local invoke CheckPublicS3Function -e events/event.json

# Start local API for testing
sam local start-api
```

### Sample Events

Create test events in `events/` folder:

```json
// events/public-only.json
{
  "params": {
    "public_only": true
  }
}

// events/full-audit.json
{
  "params": {
    "public_only": false
  }
}

// events/default.json
{
  "params": {}
}
```

## 🛠️ Customization

### SNS Notifications (Built-in)

The function includes automatic SNS notifications for security findings:

- **Topic Name**: `SecurityFindings`
- **Triggers**: CRITICAL and HIGH risk S3 buckets
- **Content**: Detailed security analysis with remediation steps
- **Format**: Structured alerts with account info, timestamps, and bucket details

Subscribe your security team using the commands in the deployment section above.

### Custom Risk Assessment

Modify the risk level logic in `analyze_bucket_security`:

```python
# Custom risk assessment for specific bucket patterns
if bucket_name.startswith('public-'):
    if bucket_info['IsPublic']:
        bucket_info['RiskLevel'] = 'Expected'  # Custom category
    else:
        security_issues.append("Public bucket name but not actually public")
```

### Integration with Security Tools

The structured JSON response integrates with:

- **AWS Security Hub**: Convert findings to ASFF format
- **AWS Config**: Create custom Config rules based on findings
- **Splunk/ELK**: Parse logs for security monitoring
- **PagerDuty**: Alert on critical bucket exposures
- **Slack/Teams**: Send security compliance reports

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure Lambda execution role has required S3 permissions
2. **Bucket Access Errors**: Some buckets may have restrictive policies
3. **Timeout**: Increase function timeout for accounts with many buckets
4. **Cross-Region Issues**: Buckets are global but regions affect access patterns

### Debug Mode

Enable detailed logging:

```python
import logging
logger.setLevel(logging.DEBUG)
```

### Performance Optimization

For very large AWS accounts (1000+ S3 buckets):

```yaml
# Increase function resources
Globals:
  Function:
    Timeout: 600          # 10 minutes
    MemorySize: 1024      # 1GB memory
```

## 🔐 Security Best Practices

### Compliance Integration

Use this function for:
- **PCI DSS Compliance**: Data storage security requirements
- **SOC 2**: Infrastructure security monitoring
- **GDPR**: Data protection and privacy audits
- **HIPAA**: Healthcare data security compliance

### Automated Remediation

Integrate with AWS Systems Manager for automated remediation:

```python
# Example: Enable public access block for risky buckets
def remediate_public_bucket(bucket_name):
    s3_client = boto3.client('s3')
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
```

## 💰 Cost Considerations

- **Execution Cost**: ~$0.40/month for weekly execution
- **CloudWatch Logs**: ~$0.75/month for log storage
- **S3 API Calls**: No additional charges for basic bucket operations
- **Data Transfer**: Minimal costs for metadata retrieval

## 🔗 Related Resources

- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [S3 Public Access Block](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 Bucket Policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [S3 Access Control Lists](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acls.html)
- [CLI Version Documentation](../check-public-s3/README.md)

## 📝 License

Same as parent project - see main repository for license details.