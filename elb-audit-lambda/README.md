# ELB/ALB Security Auditor - Lambda Version

AWS Lambda function for automated load balancer security auditing with parallel region processing.

## Overview

This serverless version of the elb-audit tool provides:

- **🕐 Scheduled Execution**: Automated security audits on CloudWatch Events schedules
- **⚡ Parallel Processing**: Multi-region scanning with configurable concurrency (85-90% faster)
- **🔒 Security Detection**: Identifies public exposure, insecure protocols, unhealthy targets
- **📧 SNS Security Alerts**: Automated notifications for CRITICAL and HIGH risk findings
- **📊 Comprehensive Analysis**: Audits Classic ELBs, ALBs, and NLBs
- **🚨 Alert Integration**: Triggers alerts on critical security findings
- **🎯 Target Health**: Monitors target group health status

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
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeRules",
                "ec2:DescribeRegions",
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

### Quick Deployment
```bash
# Clone and navigate
git clone <repository-url>
cd helper-scripts/elb-audit-lambda/

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
    --stack-name elb-audit-stack \
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
- **Security Team Setup**: After deployment, the security team must subscribe to the "SecurityFindings" SNS topic for critical security alerts

### SNS Security Alerts Setup

**CRITICAL**: The security team must subscribe to the "SecurityFindings" SNS topic to receive alerts for CRITICAL and HIGH risk load balancer findings.

1. **Find the SNS Topic ARN** (after deployment):
   ```bash
   aws cloudformation describe-stacks \
     --stack-name elb-audit-stack \
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
- **CRITICAL Risk**: Internet-facing load balancers with multiple security issues
- **HIGH Risk**: Public load balancers with insecure protocols (HTTP listeners)
- The alert includes:
  - Account ID and timestamp
  - Load balancer names, types, and DNS configurations
  - Security analysis and listener details
  - Immediate remediation recommendations

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `dev` | Environment name (dev/staging/prod) |
| `SCAN_ALL_REGIONS` | `false` | Scan all AWS regions vs current region |
| `MAX_WORKERS` | `10` | Parallel workers for region scanning (1-20) |

### Schedule Configuration

Default schedule: `cron(0 9 * * ? *)` (Daily at 9 AM UTC)

Common schedule patterns:
```yaml
# Every 12 hours
Schedule: "cron(0 */12 * * ? *)"

# Weekly on Monday at 9 AM UTC  
Schedule: "cron(0 9 ? * MON *)"

# Monthly on 1st at 9 AM UTC
Schedule: "cron(0 9 1 * ? *)"

# Business hours only (Mon-Fri, 9 AM)
Schedule: "cron(0 9 ? * MON-FRI *)"
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
# Test current region
aws lambda invoke \
    --function-name elb-audit-function \
    --payload '{"params": {"scan_all_regions": false}}' \
    response.json

# Audit all regions
aws lambda invoke \
    --function-name elb-audit-function \
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
        "message": "ELB/ALB security audit completed successfully",
        "results": {
            "region_results": [
                {
                    "region": "us-east-1",
                    "classic_elbs": [
                        {
                            "name": "web-elb",
                            "type": "classic",
                            "scheme": "internet-facing",
                            "dns_name": "web-elb-123456.us-east-1.elb.amazonaws.com",
                            "listeners": [...],
                            "security_analysis": {
                                "severity": "warning",
                                "findings": ["Publicly accessible ELB detected"],
                                "is_public": true,
                                "insecure_listeners": 1
                            }
                        }
                    ],
                    "alb_nlbs": [
                        {
                            "name": "api-alb",
                            "type": "application",
                            "scheme": "internal",
                            "state": "active",
                            "listeners": 2,
                            "security_analysis": {
                                "severity": "info",
                                "findings": [],
                                "is_public": false,
                                "target_groups_health": [...]
                            }
                        }
                    ],
                    "total_load_balancers": 2,
                    "public_load_balancers": 1,
                    "insecure_listeners": 1,
                    "critical_findings": 0,
                    "warnings": 1,
                    "errors": []
                }
            ],
            "summary": {
                "total_regions_processed": 1,
                "total_load_balancers": 2,
                "total_classic_elbs": 1,
                "total_alb_nlbs": 1,
                "total_public_load_balancers": 1,
                "total_insecure_listeners": 1,
                "total_critical_findings": 0,
                "total_warnings": 1,
                "regions_with_errors": 0,
                "total_errors": 0
            },
            "audit_parameters": {
                "scan_all_regions": false,
                "max_workers": 10,
                "account_id": "123456789012",
                "caller_arn": "arn:aws:sts::123456789012:assumed-role/..."
            }
        },
        "executionId": "uuid-here",
        "alerts_triggered": true
    }
}
```

## Security Findings

### Detection Capabilities

1. **Public Exposure**
   - Internet-facing load balancers
   - External accessibility risks

2. **Insecure Protocols**
   - HTTP listeners (unencrypted)
   - Common insecure ports (80, 8080, 8000, 3000)

3. **Target Health Issues**
   - Unhealthy targets in target groups
   - Service availability problems

4. **Configuration Analysis**
   - Listener security settings
   - Load balancer scheme validation

### Alert Triggers

Alerts are triggered when:
- Critical security findings detected (SNS + CloudWatch)
- Public load balancers found (SNS + CloudWatch)
- Processing errors occur (CloudWatch only)

**SNS Alert Format**: Detailed notifications include load balancer details, security analysis, and remediation steps.

## Performance Features

### Parallel Region Processing

- **ThreadPoolExecutor**: Thread-safe parallel execution
- **Configurable Concurrency**: 1-20 workers (default: 10)
- **Performance Gain**: 85-90% faster execution vs sequential
- **Example**: 35 regions scanned in 10-15 seconds vs 70-105 seconds

### Execution Time Estimates

| Regions | Workers | Load Balancers/Region | Estimated Time |
|---------|---------|----------------------|----------------|
| 1 | 1 | 10 | 2-5 seconds |
| 10 | 10 | 10 | 5-10 seconds |
| 35 | 15 | 10 | 10-15 seconds |
| 35 | 5 | 10 | 20-30 seconds |

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
- Security findings per load balancer
- Summary statistics
- Error details

### Custom Metrics

The function logs key statistics:
```
INFO Audit completed. Regions processed: 3, Load balancers found: 25, Public load balancers: 5, Warnings: 8
WARNING SECURITY ALERT: 2 critical findings, 5 public load balancers detected!
```

## Integration

### SNS Notifications (Built-in)

The function includes automatic SNS notifications for security findings:

- **Topic Name**: `SecurityFindings`
- **Triggers**: CRITICAL and HIGH risk load balancers
- **Content**: Detailed security analysis with remediation steps
- **Format**: Structured alerts with account info, timestamps, and load balancer details

Subscribe your security team using the commands in the deployment section above.

### Security Hub Integration

Send findings to AWS Security Hub:
```python
def send_to_security_hub(findings):
    security_hub = boto3.client('securityhub')
    # Format and send findings
```

### CloudWatch Alarms

Create alarms for critical findings:
```yaml
PublicLoadBalancerAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    MetricName: PublicLoadBalancers
    Namespace: Security/LoadBalancers
    Threshold: 0
    ComparisonOperator: GreaterThanThreshold
```

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase timeout in template.yaml
   - Reduce max_workers to decrease processing time
   - Enable scan_all_regions=false for faster execution

2. **Memory Limit Exceeded**
   - Increase MemorySize in template.yaml
   - Process fewer regions at once

3. **Permission Errors**
   - Verify IAM role has required ELB permissions
   - Check for cross-account access requirements

### Debug Mode

Enable detailed logging:
```json
{
    "params": {
        "scan_all_regions": false
    }
}
```

Check CloudWatch logs for detailed execution traces.

### Manual Testing

```bash
# Test specific functionality
aws lambda invoke \
    --function-name elb-audit-function \
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

1. **Regular Auditing**: Schedule daily or weekly audits
2. **Alert Thresholds**: Set appropriate thresholds for your environment
3. **Region Selection**: Start with critical regions, expand gradually
4. **Performance Tuning**: Adjust max_workers based on Lambda limits

### Security Configuration

1. **Zero Trust**: Treat all public load balancers as risks
2. **HTTPS Only**: Flag all HTTP listeners as security issues
3. **Target Health**: Monitor for service degradation
4. **Change Detection**: Compare audit results over time

### Operational Guidelines

1. **Review Schedule**: Align with change windows
2. **Alert Fatigue**: Tune alerts to reduce noise
3. **Documentation**: Maintain runbooks for remediation
4. **Compliance**: Map findings to compliance requirements

## Cost Optimization

### Lambda Execution Costs

Typical execution costs:
- **Memory**: 1024 MB
- **Duration**: 5-15 seconds (with parallelization)
- **Cost per execution**: $0.0001 - $0.0003
- **Monthly cost** (daily execution): ~$0.009

### Cost Comparison

| Schedule | Executions/Month | Est. Monthly Cost |
|----------|------------------|-------------------|
| Hourly | 720 | $0.22 |
| Daily | 30 | $0.009 |
| Weekly | 4 | $0.001 |

## Related Resources

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [ELB Security Best Practices](https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/security-best-practices.html)
- [AWS Security Hub](https://aws.amazon.com/security-hub/)

## Support

For issues, questions, or contributions:
1. Check CloudWatch logs for detailed error information
2. Review IAM permissions for ELB access
3. Verify network connectivity to target regions
4. Test with scan_all_regions=false first