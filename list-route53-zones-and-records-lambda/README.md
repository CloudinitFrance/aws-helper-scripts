# List Route53 Zones and Records - Lambda Version

AWS Lambda function that provides comprehensive Route53 DNS infrastructure inventory, security analysis, and configuration auditing for automated DNS management.

## 🎯 Overview

This serverless function performs complete DNS infrastructure auditing by:
- **Comprehensive Zone Inventory**: Lists all hosted zones (public and private)
- **DNS Records Analysis**: Detailed analysis of all record types and configurations
- **Security Assessment**: SPF, DMARC, and DNS security best practices validation
- **SNS Security Alerts**: Automated notifications for CRITICAL and HIGH risk DNS findings
- **Configuration Review**: TTL analysis, routing policies, and health check usage
- **Compliance Monitoring**: DNS configuration standards and optimization opportunities
- **Automated Scheduling**: CloudWatch Events integration for regular DNS audits

## 🏗️ Architecture

```
CloudWatch Events ─► Lambda Function ─► Route53 API (Global Service)
                                    │
                                    ├─► Hosted Zones Discovery
                                    ├─► DNS Records Analysis
                                    ├─► Security Assessment
                                    └─► Configuration Review
```

## 🚀 Features

### Core Functionality
- **Global DNS Inventory**: Route53 is a global service (no region-specific processing needed)
- **Zone Discovery**: Complete hosted zones inventory with metadata
- **Record Analysis**: Detailed examination of A, AAAA, CNAME, MX, TXT, and other records
- **Security Scoring**: Risk assessment based on DNS security best practices
- **Performance Analysis**: TTL optimization and routing policy recommendations

### Lambda-Specific Benefits
- **Scheduled Execution**: Run automatically on monthly/weekly schedules
- **Cost Effective**: Pay only for execution time (typically $0.10-1.00/month)
- **Scalable**: Handles accounts with hundreds of hosted zones
- **Alert Integration**: Built-in CloudWatch alerts for DNS security issues
- **Global Coverage**: Single execution covers all DNS infrastructure

## 📋 Prerequisites

- **The SNS topic 'SecurityFindings' must be created in the deployment region before deploying this Lambda**

### AWS Permissions
The Lambda function requires these IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "route53:GetHostedZone",
                "route53:ListTagsForResource",
                "route53:GetHealthCheck",
                "route53:ListHealthChecks",
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

### Required Tools
- AWS CLI v2.x configured
- AWS SAM CLI (for deployment)
- Python 3.11+ (for local testing)

## ⚙️ Configuration

### Environment Variables
```bash
ENVIRONMENT=prod               # Environment tag (dev/staging/prod)
```

### Parameters
The function accepts minimal parameters since Route53 is global:
```json
{
    "params": {
        // No region-specific parameters needed
    }
}
```

## 🚀 Deployment

### Quick Deployment
```bash
# Clone and navigate
git clone <repository-url>
cd helper-scripts/list-route53-zones-and-records-lambda/

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
    --stack-name list-route53-zones-and-records-stack \
    --region eu-west-1 \
    --parameter-overrides \
        Environment=prod \
        Schedule="cron(0 6 1 * ? *)"
```

### Important Notes
- **First Deployment**: Always use `--guided` for the first deployment to configure S3 bucket and region settings
- **Region Configuration**: The default region is set to `eu-west-1` but can be changed in `samconfig.toml`
- **S3 Bucket**: SAM will create and manage the deployment bucket automatically during guided setup
- **Security Team Setup**: After deployment, the security team must subscribe to the "SecurityFindings" SNS topic for critical DNS security alerts

### SNS Security Alerts Setup

**CRITICAL**: The security team must subscribe to the "SecurityFindings" SNS topic to receive alerts for CRITICAL and HIGH risk DNS security findings.

1. **Find the SNS Topic ARN** (after deployment):
   ```bash
   aws cloudformation describe-stacks \
     --stack-name list-route53-zones-and-records-stack \
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
- **CRITICAL Risk**: DNS zones with critical security misconfigurations
- **HIGH Risk**: Zones with missing SPF records for mail-enabled domains
- The alert includes:
  - Account ID and timestamp
  - Zone names, types, and DNS record analysis
  - Email security assessment and missing protection details
  - Immediate remediation recommendations for SPF, DMARC, and DKIM setup

## 📊 Usage Examples

### Manual Invocation
```bash
# Standard execution
aws lambda invoke \
    --function-name list-route53-zones-and-records-function \
    --payload '{}' \
    response.json

# View results
cat response.json | python -m json.tool
```

### Scheduled Execution
The function automatically runs on the configured CloudWatch Events schedule:
- **Default**: Monthly on 1st at 6 AM UTC (`cron(0 6 1 * ? *)`)
- **Weekly**: Every Monday at 8 AM UTC (`cron(0 8 ? * MON *)`)
- **Quarterly**: Every 1st of quarter at 7 AM UTC (`cron(0 7 1 1,4,7,10 ? *)`)

## 📈 Sample Output

### Execution Summary
```json
{
    "statusCode": 200,
    "body": {
        "message": "Route53 inventory completed successfully",
        "results": {
            "inventory_data": {
                "statistics": {
                    "total_zones": 12,
                    "private_zones": 3,
                    "public_zones": 9,
                    "total_records": 247,
                    "zones_with_security_issues": 2,
                    "zones_with_config_issues": 5,
                    "average_records_per_zone": 20.6
                }
            }
        },
        "alerts_triggered": true
    }
}
```

### Hosted Zone Analysis (Sample)
```json
{
    "Id": "Z123456789ABCDEF",
    "Name": "example.com.",
    "ResourceRecordSetCount": 15,
    "Statistics": {
        "total_records": 15,
        "record_types": {
            "A": 5,
            "AAAA": 2,
            "CNAME": 3,
            "MX": 2,
            "TXT": 3
        },
        "alias_records": 2,
        "health_checked_records": 1,
        "security_issues": 1
    },
    "SecurityIssues": [
        "Zone has MX records but no SPF record"
    ],
    "RiskLevel": "High"
}
```

### DNS Record Analysis (Sample)
```json
{
    "Name": "mail.example.com.",
    "Type": "A",
    "TTL": 300,
    "ResourceRecords": [
        {"Value": "203.0.113.10"}
    ],
    "IsAlias": false,
    "SecurityIssues": [],
    "ConfigurationIssues": [],
    "OptimizationOpportunities": [
        "Consider adding health check for critical records"
    ],
    "RiskLevel": "Low"
}
```

## ⚡ Performance Metrics

### Execution Time
| Scenario | Typical Duration | Max Duration |
|----------|-----------------|--------------|
| Small Account (< 10 zones) | ~5 seconds | ~10 seconds |
| Medium Account (10-50 zones) | ~15 seconds | ~30 seconds |
| Large Account (50+ zones) | ~45 seconds | ~90 seconds |

### Cost Analysis
- **Execution Cost**: ~$0.0001 per invocation
- **Monthly Cost** (weekly runs): ~$0.20/month
- **Storage Cost**: Minimal (logs only)
- **Total Monthly Cost**: < $1.00 for most use cases

## 🛡️ Security Features

### Security Assessment
The function performs comprehensive DNS security analysis:
- **SPF Records**: Validates SPF policies and identifies permissive configurations
- **DMARC Records**: Checks for DMARC implementation and policy enforcement
- **DNS Security**: Identifies private IP exposure and configuration issues
- **Zone Security**: Validates overall zone security posture

### Alert Conditions
Alerts are triggered when:
- Zones with high-risk security issues found
- Missing SPF/DMARC records for mail-enabled domains
- Permissive SPF policies detected
- Configuration issues identified

### Sample Security Report
```json
{
    "security_assessment": {
        "zones_with_security_issues": 2,
        "high_risk_zones": 1,
        "critical_issues": [
            "example.com: Zone has MX records but no SPF record",
            "test.org: Permissive SPF policy (+all)"
        ],
        "risk_distribution": {
            "Low": 8,
            "Medium": 3,
            "High": 1,
            "Critical": 0
        }
    }
}
```

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```
   botocore.exceptions.ClientError: AccessDenied
   ```
   **Solution**: Ensure Lambda execution role has required Route53 permissions

2. **Large Zone Timeout**
   ```
   Task timed out after 900.00 seconds
   ```
   **Solution**: Increase Lambda timeout or optimize record processing

3. **Memory Issues**
   ```
   Runtime exited with error: signal: killed
   ```
   **Solution**: Increase Lambda memory allocation for large accounts

### Debug Mode
Enable detailed logging by setting environment variable:
```bash
LOG_LEVEL=DEBUG
```

### Performance Optimization
- **Memory Setting**: 512MB sufficient for most accounts
- **Timeout**: 900 seconds for comprehensive analysis
- **Record Limit**: Function limits to first 100 records per zone for performance

## 📊 Monitoring

### CloudWatch Metrics
The function automatically creates custom metrics:
- `Route53/InventoryDuration`: Execution time in seconds
- `Route53/ZoneCount`: Total zones discovered
- `Route53/RecordCount`: Total DNS records analyzed
- `Route53/SecurityIssues`: Number of security issues found

### CloudWatch Alarms
Recommended alarms:
```bash
# Security issues alert
aws cloudwatch put-metric-alarm \
    --alarm-name "Route53-Security-Issues" \
    --alarm-description "Route53 security issues detected" \
    --metric-name SecurityIssues \
    --namespace Route53 \
    --statistic Average \
    --period 300 \
    --threshold 0 \
    --comparison-operator GreaterThanThreshold

# Zone count monitoring
aws cloudwatch put-metric-alarm \
    --alarm-name "Route53-Unexpected-Zone-Count" \
    --alarm-description "Unexpected change in zone count" \
    --metric-name ZoneCount \
    --namespace Route53 \
    --statistic Average \
    --period 300 \
    --threshold 50 \
    --comparison-operator GreaterThanThreshold
```

## 🔄 Integration Examples

### SNS Notifications
Add SNS topic for DNS alerts:
```yaml
# In template.yaml
DNSAlertTopic:
  Type: AWS::SNS::Topic
  Properties:
    DisplayName: "DNS Security Alerts"
```

### S3 Export Integration
Store DNS inventory reports in S3:
```python
# Add to Lambda function
import boto3
s3 = boto3.client('s3')
s3.put_object(
    Bucket='dns-inventory-reports',
    Key=f'dns-inventory-{datetime.now().strftime("%Y-%m-%d")}.json',
    Body=json.dumps(results)
)
```

### Security Information Integration
Send security findings to SIEM:
```python
# Add security event logging
def send_security_events(security_issues):
    for issue in security_issues:
        # Send to security monitoring system
        pass
```

## 🆚 CLI vs Lambda Comparison

| Feature | CLI Version | Lambda Version |
|---------|-------------|----------------|
| **Execution** | Manual/Cron | Automated/Scheduled |
| **Performance** | On-demand | Consistent scheduled execution |
| **Cost** | EC2/Local compute | $1/month serverless |
| **Scaling** | Manual setup | Auto-scaling |
| **Monitoring** | Manual | CloudWatch integration |
| **Alerts** | Manual setup | Built-in alerting |

## 🚀 Advanced Features

### Custom DNS Security Rules
Extend security analysis for specific requirements:
```python
def custom_dns_security_checks(zone_analysis):
    # Add organization-specific DNS policies
    # Custom SPF/DMARC validation rules
    # Industry compliance requirements
    pass
```

### DNS Performance Analysis
Add performance monitoring:
```python
def analyze_dns_performance(records):
    # TTL optimization recommendations
    # Routing policy analysis
    # Health check coverage assessment
    pass
```

### Multi-Account DNS Inventory
Extend for cross-account DNS management:
```python
def cross_account_dns_inventory(account_list):
    # Assume roles across accounts
    # Centralized DNS inventory
    # Organization-wide DNS compliance
    pass
```

## 🌐 DNS Best Practices

### Security Configuration
1. **SPF Records**: Implement for all mail-enabled domains
2. **DMARC Policy**: Use p=quarantine or p=reject for production domains
3. **DNSSEC**: Consider enabling for critical domains
4. **Private Zones**: Use for internal resources

### Performance Optimization
1. **TTL Settings**: Balance between performance and agility
2. **Health Checks**: Implement for critical services
3. **Routing Policies**: Use weighted/latency routing for global services
4. **Alias Records**: Prefer over CNAME for AWS resources

### Operational Guidelines
1. **Zone Organization**: Logical separation of environments
2. **Record Documentation**: Use descriptive names and tags
3. **Change Management**: Track DNS changes systematically
4. **Monitoring**: Regular audits and alerting

## 🔗 Related Resources

- [AWS Route53 Documentation](https://docs.aws.amazon.com/route53/)
- [DNS Security Best Practices](https://docs.aws.amazon.com/route53/latest/developerguide/best-practices-dns.html)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [CLI Version](../list-route53-zones-and-records/) - For manual execution

## 🆘 Support

- 🐛 **Issues**: Report via GitHub Issues
- 💬 **Questions**: Use GitHub Discussions
- 📧 **DNS Security**: Contact security@yourorg.com

---

**⚡ Powered by AWS Lambda | 🌐 Secure DNS Management**