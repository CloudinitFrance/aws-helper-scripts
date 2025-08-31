# IAM Users MFA Compliance Checker - Lambda Version

Serverless AWS Lambda function for automated IAM security auditing and MFA compliance monitoring.

## 🎯 Overview

This Lambda function provides automated IAM security auditing with scheduled execution and intelligent alerting. It's the serverless version of the [IAM Users MFA Compliance Checker CLI tool](../check-iam-users-no-mfa/).

## ✨ Features

- 🔐 **Automated MFA Compliance Auditing**: Scheduled scanning for IAM users without MFA
- 🚨 **Security Risk Assessment**: Categorizes findings by risk level (HIGH, MEDIUM, LOW)
- 📧 **SNS Security Alerts**: Automated notifications for CRITICAL and HIGH risk findings
- 👥 **Comprehensive User Analysis**: Console access detection and MFA device verification
- 📊 **Activity Tracking**: Last activity monitoring for user security assessment
- 📋 **Detailed Reporting**: Structured JSON response with comprehensive user metadata
- ⚡ **High Performance**: Efficient pagination and batch processing
- 🔒 **Secure**: IAM roles with least privilege permissions
- 📈 **Integration Ready**: JSON response format for SIEM and monitoring systems

## 🏗️ Architecture

```
CloudWatch Events (Schedule) → Lambda Function → IAM API
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
        "iam:ListUsers",
        "iam:GetUser",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
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
cd helper-scripts/check-iam-users-no-mfa-lambda/

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
    --stack-name check-iam-users-no-mfa-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        IncludeInactive=false \
        ViolationsOnly=true
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup
- **Security Team Setup**: After deployment, the security team must subscribe to the "SecurityFindings" SNS topic for critical security alerts

### SNS Security Alerts Setup

**CRITICAL**: The security team must subscribe to the "SecurityFindings" SNS topic to receive alerts for CRITICAL and HIGH risk IAM findings.

1. **Find the SNS Topic ARN** (after deployment):
   ```bash
   aws cloudformation describe-stacks \
     --stack-name check-iam-users-no-mfa-stack \
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
- **CRITICAL Risk**: Users with console access + no MFA + recent activity (last 30 days)
- **HIGH Risk**: Users with console access but no MFA (inactive users)
- The alert includes:
  - Account ID and timestamp
  - Detailed user names and activity status
  - Risk summary and statistics
  - Immediate remediation recommendations

### 2. Configure Parameters

The function supports these environment variables and event parameters:

- `INCLUDE_INACTIVE`: Include users with no recent activity (default: true)
- `VIOLATIONS_ONLY`: Only report users with MFA violations (default: false)
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
# Full audit with all users
aws lambda invoke \
  --function-name check-iam-users-no-mfa-function \
  --payload '{"params": {"include_inactive": true, "violations_only": false}}' \
  response.json

# Security violations only
aws lambda invoke \
  --function-name check-iam-users-no-mfa-function \
  --payload '{"params": {"violations_only": true}}' \
  response.json

# Active users only (exclude inactive)
aws lambda invoke \
  --function-name check-iam-users-no-mfa-function \
  --payload '{"params": {"include_inactive": false}}' \
  response.json
```

### Event Payload Structure

```json
{
  "params": {
    "include_inactive": true,
    "violations_only": false
  }
}
```

## 📈 Response Format

### Successful Execution (No Security Issues)

```json
{
  "statusCode": 200,
  "body": {
    "message": "IAM MFA compliance audit completed successfully",
    "results": {
      "users": [],
      "summary": {
        "total_users": 5,
        "users_with_console_access": 3,
        "users_with_mfa": 3,
        "users_without_mfa": 0,
        "high_risk_users": 0,
        "medium_risk_users": 2,
        "low_risk_users": 3,
        "users_with_recent_activity": 4
      },
      "audit_parameters": {
        "include_inactive": true,
        "violations_only": false,
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
    "message": "IAM MFA compliance audit completed successfully",
    "results": {
      "users": [
        {
          "UserName": "console-user-no-mfa",
          "CreateDate": "2023-01-15T10:30:00.000Z",
          "HasConsoleAccess": true,
          "HasMFA": false,
          "MFADevices": [],
          "LastActivity": "2024-01-10T14:22:00.000Z",
          "RiskLevel": "High",
          "Groups": [],
          "AttachedPolicies": []
        }
      ],
      "summary": {
        "total_users": 6,
        "users_with_console_access": 4,
        "users_with_mfa": 3,
        "users_without_mfa": 1,
        "high_risk_users": 1,
        "medium_risk_users": 2,
        "low_risk_users": 3,
        "users_with_recent_activity": 5
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
    IncludeInactive=false \
    ViolationsOnly=true
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

The function categorizes users into risk levels:

- **HIGH**: Users with console access but no MFA (security violation)
- **MEDIUM**: Users without console access (API access only)
- **LOW**: Users with console access and MFA enabled

## 📊 Monitoring & Observability

### CloudWatch Metrics

Monitor your function performance:

```bash
# View function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=check-iam-users-no-mfa-function \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### CloudWatch Logs

```bash
# View recent logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/check-iam-users-no-mfa

# Stream logs in real-time
aws logs tail /aws/lambda/check-iam-users-no-mfa-function --follow
```

### Security Alerts

The function automatically triggers alerts when:
- Users with console access have no MFA devices (SNS + CloudWatch)
- High-risk security violations are detected (SNS + CloudWatch)
- Compliance policies are violated (SNS + CloudWatch)

**SNS Alert Format**: Detailed notifications include user names, activity status, risk levels, and remediation steps.

## 🔧 Development

### Local Testing

```bash
# Build function locally
sam build

# Test with sample event
sam local invoke CheckIamUsersNoMfaFunction -e events/event.json

# Start local API for testing
sam local start-api
```

### Sample Events

Create test events in `events/` folder:

```json
// events/full-audit.json
{
  "params": {
    "include_inactive": true,
    "violations_only": false
  }
}

// events/violations-only.json
{
  "params": {
    "violations_only": true
  }
}

// events/active-users.json
{
  "params": {
    "include_inactive": false,
    "violations_only": false
  }
}
```

## 🛠️ Customization

### SNS Notifications (Built-in)

The function includes automatic SNS notifications for security findings:

- **Topic Name**: `SecurityFindings`
- **Triggers**: CRITICAL and HIGH risk IAM users without MFA
- **Content**: Detailed security analysis with remediation steps
- **Format**: Structured alerts with account info, timestamps, and user details

Subscribe your security team using the commands in the deployment section above.

### Custom Risk Assessment

Modify the risk level logic in `check_user_mfa_status`:

```python
# Custom risk assessment
if user_info['HasConsoleAccess'] and not user_info['HasMFA']:
    # Check for admin privileges
    if is_admin_user(username):
        user_info['RiskLevel'] = 'Critical'
    else:
        user_info['RiskLevel'] = 'High'
```

### Integration with Security Tools

The structured JSON response integrates with:

- **AWS Security Hub**: Convert findings to ASFF format
- **Splunk/ELK**: Parse logs for security monitoring
- **PagerDuty**: Alert on critical security violations
- **Slack/Teams**: Send compliance reports
- **JIRA**: Create security remediation tickets

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure Lambda execution role has required IAM permissions
2. **No Users Found**: Check if IAM users exist in the account
3. **Timeout**: Increase function timeout for accounts with many users
4. **Rate Limiting**: IAM API has rate limits; function includes error handling

### Debug Mode

Enable detailed logging:

```python
import logging
logger.setLevel(logging.DEBUG)
```

### Performance Optimization

For large AWS accounts (100+ IAM users):

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
- **SOC 2 Compliance**: Regular MFA compliance auditing
- **PCI DSS**: Multi-factor authentication requirements
- **NIST Framework**: Identity verification and access management
- **CIS Controls**: Secure configuration auditing

### Automated Remediation

Integrate with AWS Systems Manager for automated remediation:

```python
# Example: Disable console access for non-MFA users
def disable_console_access(username):
    iam_client.delete_login_profile(UserName=username)
```

## 💰 Cost Considerations

- **Execution Cost**: ~$0.30/month for weekly execution
- **CloudWatch Logs**: ~$0.50/month for log storage
- **IAM API Calls**: No additional charges for standard operations

## 🔗 Related Resources

- [AWS IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/)
- [AWS MFA Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html)
- [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [CLI Version Documentation](../check-iam-users-no-mfa/README.md)

## 📝 License

Same as parent project - see main repository for license details.