# List ELBs and ALBs Inventory - Lambda Version

AWS Lambda function for automated load balancer inventory and documentation with parallel region processing.

## Overview

This serverless version of the list-elbs-and-albs tool provides:

- **🕐 Scheduled Execution**: Automated inventory on CloudWatch Events schedules
- **⚡ Parallel Processing**: Multi-region scanning with configurable concurrency (85-90% faster)
- **📊 Comprehensive Inventory**: Classic ELBs, ALBs, NLBs with full configuration details
- **🎯 Target Group Analysis**: Health status, protocols, and target counts
- **📋 Infrastructure Documentation**: Detailed reports for compliance and planning
- **🚨 Monitoring Integration**: Statistics and health metrics

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
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetHealth",
                "ec2:DescribeRegions",
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
cd helper-scripts/list-elbs-and-albs-lambda/

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
    --stack-name list-elbs-and-albs-stack \
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

Default schedule: `cron(0 6 1 * ? *)` (Monthly on 1st at 6 AM UTC)

Common schedule patterns:
```yaml
# Weekly on Monday at 6 AM UTC  
Schedule: "cron(0 6 ? * MON *)"

# Monthly on 1st at 6 AM UTC
Schedule: "cron(0 6 1 * ? *)"

# Quarterly (every 3 months on 1st)
Schedule: "cron(0 6 1 */3 ? *)"

# On-demand only (disable scheduled execution)
Schedule: "rate(365 days)"
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
# Inventory current region
aws lambda invoke \
    --function-name list-elbs-albs-function \
    --payload '{"params": {"scan_all_regions": false}}' \
    response.json

# Inventory all regions
aws lambda invoke \
    --function-name list-elbs-albs-function \
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
        "message": "ELB/ALB inventory completed successfully",
        "results": {
            "region_results": [
                {
                    "region": "us-east-1",
                    "classic_elbs": [
                        {
                            "LoadBalancerName": "web-elb",
                            "DNSName": "web-elb-123456.us-east-1.elb.amazonaws.com",
                            "Scheme": "internet-facing",
                            "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                            "Listeners": [
                                {
                                    "Protocol": "HTTP",
                                    "LoadBalancerPort": 80,
                                    "InstancePort": 80,
                                    "InstanceProtocol": "HTTP"
                                }
                            ],
                            "InstancesCount": 3,
                            "HealthCheck": {
                                "Target": "HTTP:80/health",
                                "Interval": 30,
                                "Timeout": 5
                            }
                        }
                    ],
                    "alb_nlbs": [
                        {
                            "LoadBalancerName": "api-alb",
                            "Type": "application",
                            "Scheme": "internal",
                            "State": "active",
                            "Listeners": [
                                {
                                    "Protocol": "HTTPS",
                                    "Port": 443,
                                    "TargetGroups": [
                                        {
                                            "TargetGroupName": "api-targets",
                                            "Protocol": "HTTP",
                                            "Port": 8080,
                                            "TargetsCount": 4,
                                            "HealthyTargets": 4
                                        }
                                    ]
                                }
                            ],
                            "ListenersCount": 1
                        }
                    ],
                    "statistics": {
                        "total_load_balancers": 2,
                        "classic_elbs_count": 1,
                        "alb_nlbs_count": 1,
                        "total_listeners": 2,
                        "total_target_groups": 1,
                        "total_targets": 4,
                        "healthy_targets": 4,
                        "internet_facing": 1,
                        "internal": 1
                    },
                    "errors": []
                }
            ],
            "summary": {
                "total_regions_processed": 1,
                "total_load_balancers": 2,
                "total_classic_elbs": 1,
                "total_alb_nlbs": 1,
                "total_listeners": 2,
                "total_target_groups": 1,
                "total_targets": 4,
                "total_healthy_targets": 4,
                "total_internet_facing": 1,
                "total_internal": 1,
                "regions_with_errors": 0,
                "total_errors": 0
            },
            "inventory_parameters": {
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

## Inventory Features

### Load Balancer Types

1. **Classic ELBs**
   - Listener configurations
   - Health check settings
   - Instance counts
   - Availability zones

2. **Application Load Balancers (ALB)**
   - HTTP/HTTPS listeners
   - Target group configurations
   - Routing rules
   - Health status

3. **Network Load Balancers (NLB)**
   - TCP/UDP listeners
   - Target group details
   - Connection handling

### Data Collection

- **Basic Information**: Names, ARNs, DNS names, schemes
- **Network Configuration**: VPCs, availability zones, security groups
- **Listener Details**: Protocols, ports, SSL certificates
- **Target Groups**: Health checks, target counts, protocols
- **Health Metrics**: Healthy vs unhealthy targets

## Performance Features

### Parallel Region Processing

- **ThreadPoolExecutor**: Thread-safe parallel execution
- **Configurable Concurrency**: 1-20 workers (default: 10)
- **Performance Gain**: 85-90% faster execution vs sequential
- **Example**: 35 regions scanned in 10-15 seconds vs 70-105 seconds

### Execution Time Estimates

| Regions | Workers | Load Balancers/Region | Estimated Time |
|---------|---------|----------------------|----------------|
| 1 | 1 | 20 | 3-8 seconds |
| 10 | 10 | 20 | 8-15 seconds |
| 35 | 15 | 20 | 10-15 seconds |
| 35 | 5 | 20 | 25-40 seconds |

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
- Load balancer discovery counts
- Target group health summaries
- Error details

### Custom Metrics

The function logs key statistics:
```
INFO Inventory completed. Regions processed: 3, Load balancers found: 45, Target groups: 28
INFO Completed inventory for us-east-1: 15 load balancers
```

## Integration

### CMDB Integration

Export inventory data to Configuration Management Database:
```python
def export_to_cmdb(inventory_data):
    # Format and send to CMDB system
    pass
```

### Cost Analysis Integration

Analyze load balancer costs:
```python
def calculate_lb_costs(inventory_data):
    # Estimate monthly costs based on load balancer hours
    pass
```

### Compliance Reporting

Generate compliance reports:
```python
def generate_compliance_report(inventory_data):
    # Check SSL certificates, security configurations
    pass
```

## Use Cases

### Infrastructure Documentation

1. **Network Architecture**: Map load balancer topology
2. **Capacity Planning**: Analyze target distribution
3. **Security Audits**: Review public vs internal load balancers
4. **Cost Optimization**: Identify underutilized load balancers

### Operational Monitoring

1. **Health Dashboards**: Monitor target group health
2. **Change Tracking**: Detect configuration changes
3. **Incident Response**: Quickly assess load balancer status
4. **Migration Planning**: Document current state before changes

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
   - Verify IAM role has required ELB permissions
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
# Test single region inventory
aws lambda invoke \
    --function-name list-elbs-albs-function \
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

1. **Regular Inventory**: Schedule monthly or quarterly inventory
2. **Environment Separation**: Separate functions for dev/staging/prod
3. **Alert Thresholds**: Monitor for inventory failures
4. **Data Retention**: Store historical inventory data

### Operational Guidelines

1. **Review Schedule**: Align with infrastructure review cycles
2. **Change Detection**: Compare inventory over time
3. **Documentation**: Use results for architecture documentation
4. **Automation**: Integrate with CI/CD pipelines

## Cost Optimization

### Lambda Execution Costs

Typical execution costs:
- **Memory**: 1024 MB
- **Duration**: 10-15 seconds (with parallelization)
- **Cost per execution**: $0.0002 - $0.0003
- **Monthly cost** (monthly execution): ~$0.0003

### Cost Comparison

| Schedule | Executions/Month | Est. Monthly Cost |
|----------|------------------|-------------------|
| Daily | 30 | $0.009 |
| Weekly | 4 | $0.001 |
| Monthly | 1 | $0.0003 |

## Related Resources

- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Elastic Load Balancing User Guide](https://docs.aws.amazon.com/elasticloadbalancing/)
- [AWS Config for ELB](https://docs.aws.amazon.com/config/latest/developerguide/elb-resources.html)

## Support

For issues, questions, or contributions:
1. Check CloudWatch logs for detailed error information
2. Review IAM permissions for ELB access
3. Verify network connectivity to target regions
4. Test with scan_all_regions=false first