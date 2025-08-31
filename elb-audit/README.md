# ELB/ALB Security Auditor & Scanner

A comprehensive security auditing tool that analyzes Classic ELBs and Application/Network Load Balancers (ALB/NLB) to identify potential security vulnerabilities, misconfigurations, and compliance issues.

## Description

This script performs detailed security analysis of your load balancers by:

- **Multi-Load Balancer Support**: Audits both Classic ELBs and modern ALB/NLB
- **Security Vulnerability Detection**: Identifies insecure protocols and public exposure
- **Target Health Monitoring**: Shows target health status and connectivity
- **Comprehensive Reporting**: Displays listeners, target groups, and security findings
- **Color-Coded Output**: Visual indicators for security risks and healthy configurations

## Prerequisites

### Required Python Packages
```bash
pip install boto3
```

### AWS Credentials
Configure AWS credentials using one of these methods:
- AWS CLI: `aws configure`
- Multiple profiles: `aws configure --profile production`
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- IAM roles (for EC2 instances)
- AWS credentials file

### Required AWS Permissions
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
                "elasticloadbalancing:DescribeRules"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Audit load balancers in specific region
python3 elb_audit_cli.py --region us-east-1

# Use specific AWS profile
python3 elb_audit_cli.py --profile production --region us-east-1

# Audit all regions with profile
python3 elb_audit_cli.py --profile production --all-regions

# Audit specific region with staging profile
python3 elb_audit_cli.py --profile staging --region eu-west-1
```

### Command Line Options
- `--region`: Specific AWS region to audit
- `--all-regions`: Audit all available AWS regions
- `--profile`: AWS profile to use for credentials

Note: You must specify either `--region` or `--all-regions`

### Examples
```bash
# Audit load balancers in US East 1 with default profile
python3 elb_audit_cli.py --region us-east-1

# Audit load balancers in EU West 1 with production profile
python3 elb_audit_cli.py --profile production --region eu-west-1

# Audit load balancers in Asia Pacific Sydney with staging profile
python3 elb_audit_cli.py --profile staging --region ap-southeast-2

# Comprehensive audit across all regions for production
python3 elb_audit_cli.py --profile production --all-regions

# Audit all regions with development profile
python3 elb_audit_cli.py --profile development --all-regions
```

## Example Output

### Classic ELB with Security Issues
```
=====================
Classic ELBs
=====================

Load Balancer: web-app-elb (internet-facing)
Listeners:
 - HTTP 80 -> instance 80 ⚠️ Insecure (HTTP on port 80)
 - HTTPS 443 -> instance 443
⚠️ Publicly accessible ELB detected!
```

### Secure Internal ALB
```
==========================================
Application/Network Load Balancers (ALB/NLB)
==========================================

Load Balancer: internal-app-alb (Type: application, Scheme: internal)
 - HTTPS port 443
   Target Group: app-targets (HTTPS:443)
     - Target: i-0a1b2c3d4e5f6g7h8, Health: healthy
     - Target: i-0b2c3d4e5f6g7h8i9, Health: healthy
✅ No security issues detected on this ALB/NLB.
```

### Public ALB with Mixed Security
```
Load Balancer: public-api-alb (Type: application, Scheme: internet-facing)
 - HTTP port 80 ⚠️ Insecure listener (HTTP)
 - HTTPS port 443
   Target Group: api-targets (HTTP:8080)
     - Target: i-0c3d4e5f6g7h8i9j0, Health: healthy
     - Target: i-0d4e5f6g7h8i9j0k1, Health: unhealthy
⚠️ Publicly accessible ALB/NLB detected!
```

## Understanding the Output

### Security Risk Indicators
- **🚨 Red**: Critical security issues (public access, insecure protocols)
- **⚠️ Yellow**: Security warnings (HTTP listeners, unhealthy targets)
- **✅ Green**: Secure configurations and healthy targets

### Load Balancer Types
- **Classic ELB**: Legacy load balancers (being phased out)
- **Application Load Balancer (ALB)**: Layer 7 load balancer for HTTP/HTTPS
- **Network Load Balancer (NLB)**: Layer 4 load balancer for TCP/UDP

### Scheme Types
- **internet-facing**: Publicly accessible from the internet (security risk)
- **internal**: Only accessible from within VPC (secure)

## Security Findings Explained

### Critical Security Issues

1. **Publicly Accessible Load Balancers**
   - **Risk**: Exposed to internet attacks
   - **Detection**: Scheme = "internet-facing"
   - **Remediation**: Use internal scheme or implement strict security groups

2. **Insecure HTTP Listeners**
   - **Risk**: Unencrypted data transmission
   - **Detection**: HTTP protocol on standard ports (80, 8080)
   - **Remediation**: Use HTTPS with SSL/TLS certificates

3. **Unhealthy Targets**
   - **Risk**: Service degradation and availability issues
   - **Detection**: Target health status != "healthy"
   - **Remediation**: Fix underlying application or infrastructure issues

## Remediation Guidelines

### Securing Public Load Balancers

1. **Implement HTTPS Only**
   ```bash
   # Redirect HTTP to HTTPS (default profile)
   aws elbv2 create-listener \
     --load-balancer-arn arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id \
     --protocol HTTP \
     --port 80 \
     --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'
   
   # Redirect HTTP to HTTPS (with profile)
   aws elbv2 create-listener \
     --load-balancer-arn arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id \
     --protocol HTTP \
     --port 80 \
     --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \
     --profile production
   ```

2. **Restrict Security Groups**
   ```bash
   # Allow only specific IP ranges (default profile)
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxxxxxxx \
     --protocol tcp \
     --port 443 \
     --cidr 203.0.113.0/24
   
   # Allow only specific IP ranges (with profile)
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxxxxxxx \
     --protocol tcp \
     --port 443 \
     --cidr 203.0.113.0/24 \
     --profile production
   ```

3. **Use Web Application Firewall (WAF)**
   ```bash
   # Associate WAF (default profile)
   aws wafv2 associate-web-acl \
     --web-acl-arn arn:aws:wafv2:region:account:regional/webacl/name/id \
     --resource-arn arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
   
   # Associate WAF (with profile)
   aws wafv2 associate-web-acl \
     --web-acl-arn arn:aws:wafv2:region:account:regional/webacl/name/id \
     --resource-arn arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id \
     --profile production
   ```

### Fixing Target Health Issues

1. **Check Target Registration**
   ```bash
   # With default profile
   aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:region:account:targetgroup/name/id
   
   # With specific profile
   aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:region:account:targetgroup/name/id --profile production
   ```

2. **Verify Health Check Configuration**
   ```bash
   # With default profile
   aws elbv2 describe-target-groups --target-group-arns arn:aws:elasticloadbalancing:region:account:targetgroup/name/id
   
   # With specific profile
   aws elbv2 describe-target-groups --target-group-arns arn:aws:elasticloadbalancing:region:account:targetgroup/name/id --profile production
   ```

3. **Update Health Check Settings**
   ```bash
   # With default profile
   aws elbv2 modify-target-group \
     --target-group-arn arn:aws:elasticloadbalancing:region:account:targetgroup/name/id \
     --health-check-path /health \
     --health-check-interval-seconds 30
   
   # With specific profile
   aws elbv2 modify-target-group \
     --target-group-arn arn:aws:elasticloadbalancing:region:account:targetgroup/name/id \
     --health-check-path /health \
     --health-check-interval-seconds 30 \
     --profile production
   ```

## Configuration Options

### Extending the Audit Script

#### Add SSL Certificate Validation
```python
def check_ssl_certificates(elbv2_client, listener_arn):
    """Check SSL certificate expiration"""
    try:
        certs = elbv2_client.describe_listener_certificates(ListenerArn=listener_arn)
        for cert in certs['Certificates']:
            # Check certificate expiration
            pass
    except Exception as e:
        pass
```

#### Add Security Group Analysis
```python
def analyze_security_groups(ec2_client, lb_security_groups):
    """Analyze load balancer security group rules"""
    for sg_id in lb_security_groups:
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])
        # Analyze ingress rules for overly permissive access
```

#### Add Access Logging Check
```python
def check_access_logging(elbv2_client, lb_arn):
    """Check if access logging is enabled"""
    try:
        attrs = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
        for attr in attrs['Attributes']:
            if attr['Key'] == 'access_logs.s3.enabled':
                return attr['Value'] == 'true'
    except Exception:
        return False
```

## Advanced Features

### Multi-Region Scanning
```bash
#!/bin/bash
# Manual multi-region scanning with default profile
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
for region in "${regions[@]}"; do
    echo "Auditing load balancers in $region"
    python3 elb_audit_cli.py --region "$region"
    echo "---"
done

# Manual multi-region scanning with specific profile
for region in "${regions[@]}"; do
    echo "Auditing load balancers in $region for production"
    python3 elb_audit_cli.py --profile production --region "$region"
    echo "---"
done

# Automated all-regions scanning (recommended)
python3 elb_audit_cli.py --profile production --all-regions
```

### Automated Reporting
```python
def generate_security_report(findings):
    """Generate comprehensive security report"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'critical_issues': [],
        'warnings': [],
        'compliant_resources': []
    }
    
    for finding in findings:
        if finding['severity'] == 'critical':
            report['critical_issues'].append(finding)
        elif finding['severity'] == 'warning':
            report['warnings'].append(finding)
        else:
            report['compliant_resources'].append(finding)
    
    return report
```

### Integration with Security Tools
```bash
#!/bin/bash
# Multi-environment security monitoring
for profile in production staging development; do
    echo "Auditing $profile environment..."
    python3 elb_audit_cli.py --profile $profile --all-regions > /tmp/elb-audit-$profile.log
    
    # Check for security issues and alert
    if grep -q "⚠️.*Publicly accessible" /tmp/elb-audit-$profile.log; then
        echo "Security issues found in $profile" | mail -s "ELB Security Alert - $profile" security@company.com
    fi
done

# Send findings to SIEM or security dashboard with profile
python3 elb_audit_cli.py --profile production --all-regions | \
curl -X POST -H "Content-Type: application/json" \
     -d @- https://security-dashboard.company.com/api/findings
```

## Troubleshooting

### Common Issues

1. **No Load Balancers Found**
   ```
   No Classic ELBs found.
   No ALBs/NLBs found.
   ```
   **Solution**: Verify you're scanning the correct region and have load balancers deployed.

2. **Permission Denied**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Ensure your AWS credentials have the required ELB permissions.

3. **Target Group Access Issues**
   ```
   Error accessing target group
   ```
   **Solution**: Verify your IAM permissions include target group describe actions.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Monitoring

### Scheduled Security Audits
```bash
# Weekly load balancer security audit for production (all regions)
0 8 * * 1 /usr/bin/python3 /path/to/elb_audit_cli.py --profile production --all-regions >> /var/log/elb-audit-prod.log 2>&1

# Daily load balancer audit for specific region with staging profile
0 9 * * * /usr/bin/python3 /path/to/elb_audit_cli.py --profile staging --region us-east-1 >> /var/log/elb-audit-staging.log 2>&1

# Weekly comprehensive audit for development environment
0 10 * * 0 /usr/bin/python3 /path/to/elb_audit_cli.py --profile development --all-regions >> /var/log/elb-audit-dev.log 2>&1
```

### CloudWatch Integration
```python
def send_security_metrics(findings, profile=None):
    """Send security metrics to CloudWatch"""
    import boto3
    
    if profile:
        session = boto3.Session(profile_name=profile)
        cloudwatch = session.client('cloudwatch')
    else:
        cloudwatch = boto3.client('cloudwatch')
    
    cloudwatch.put_metric_data(
        Namespace='Security/LoadBalancers',
        MetricData=[
            {
                'MetricName': 'PublicLoadBalancers',
                'Value': len([f for f in findings if f['public']]),
                'Unit': 'Count'
            },
            {
                'MetricName': 'InsecureListeners',
                'Value': len([f for f in findings if f['insecure']]),
                'Unit': 'Count'
            }
        ]
    )
```

### Alert Integration
```bash
#!/bin/bash
# Alert on critical security findings with default profile
output=$(python3 elb_audit_cli.py --region us-east-1)
if echo "$output" | grep -q "⚠️.*Publicly accessible"; then
    echo "$output" | mail -s "Load Balancer Security Alert" security@company.com
fi

# Alert on critical security findings for production environment
output=$(python3 elb_audit_cli.py --profile production --all-regions)
if echo "$output" | grep -q "⚠️.*Publicly accessible"; then
    echo "$output" | mail -s "Load Balancer Security Alert - Production" security@company.com
fi
```

## Compliance Frameworks

This tool helps meet requirements for:
- **SOC 2**: Security controls for customer data protection
- **PCI DSS**: Network security requirements for payment data
- **ISO 27001**: Information security management controls
- **NIST Cybersecurity Framework**: Network security monitoring
- **CIS AWS Foundations Benchmark**: Load balancer security controls

## Best Practices

### Security Configuration
1. **Use HTTPS Only**: Implement SSL/TLS for all public-facing load balancers
2. **Internal by Default**: Use internal scheme unless public access is required
3. **Restrict Security Groups**: Implement least privilege access rules
4. **Enable Access Logging**: Monitor and audit access patterns
5. **Regular Health Checks**: Ensure targets are healthy and responsive

### Operational Guidelines
1. **Regular Auditing**: Run security audits weekly or monthly
2. **Automated Monitoring**: Integrate with security monitoring systems
3. **Change Management**: Audit after infrastructure changes
4. **Documentation**: Maintain inventory of load balancer configurations
5. **Incident Response**: Have procedures for security finding remediation

## Related AWS Services

- **AWS WAF**: Web application firewall protection
- **AWS Shield**: DDoS protection for load balancers
- **AWS Certificate Manager**: SSL/TLS certificate management
- **AWS Config**: Configuration compliance monitoring
- **AWS Security Hub**: Centralized security findings management
- **AWS CloudTrail**: API call logging and monitoring

## Security Considerations

- This tool only reads load balancer metadata and configuration
- Results may contain sensitive load balancer names and configurations
- Regular security auditing should be part of your security program
- Consider implementing automated remediation for critical findings