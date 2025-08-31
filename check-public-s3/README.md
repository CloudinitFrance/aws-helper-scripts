# Public S3 Bucket Detector

A critical security auditing tool that identifies publicly accessible S3 buckets in your AWS account. Public S3 buckets can expose sensitive data and pose significant security risks.

## Description

This script performs a comprehensive security audit of your S3 buckets to identify potential data exposure risks by:

- **Public ACL Detection**: Checks bucket ACLs for public read/write permissions
- **Bucket Policy Analysis**: Examines bucket policies for public access configurations
- **Comprehensive Scanning**: Analyzes all buckets in your AWS account
- **Security Risk Assessment**: Identifies buckets accessible to anonymous users

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
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Scan with default AWS credentials
python3 check_public_s3_cli.py

# Use specific AWS profile
python3 check_public_s3_cli.py --profile production

# Export detailed report with profile
python3 check_public_s3_cli.py --profile staging --export-csv s3_security_report.csv

# Show only public buckets for production environment
python3 check_public_s3_cli.py --profile production --public-only

# Comprehensive audit with JSON export
python3 check_public_s3_cli.py --profile production --export-json s3_audit.json
```

The script automatically scans all S3 buckets in your AWS account and identifies those with public access.

## Example Output

### Public S3 Buckets Found (Security Risk)
```
Checking S3 buckets for public access...
  → company-website-assets  🌍 PUBLIC
  → backup-files-temp  ✅ Private
  → user-uploads-prod  🌍 PUBLIC
  → internal-logs  ✅ Private
  → public-downloads  🌍 PUBLIC
  → confidential-data  ✅ Private

⚠️ Public buckets found:
 - company-website-assets
 - user-uploads-prod
 - public-downloads
```

### No Public S3 Buckets (Good Security Posture)
```
Checking S3 buckets for public access...
  → secure-backups  ✅ Private
  → internal-docs  ✅ Private
  → application-logs  ✅ Private
  → encrypted-storage  ✅ Private

✅ No public buckets detected.
```

## Understanding the Output

### Status Indicators
- **🌍 PUBLIC**: Bucket is accessible to anonymous users (security risk)
- **✅ Private**: Bucket is properly secured with private access
- **Error**: Issues accessing bucket (permissions or configuration problems)

### Public Access Detection Methods
The script checks for public access through:
1. **Bucket ACLs**: Permissions granted to "All Users" group
2. **Bucket Policies**: Policies allowing public access via Principal "*"

## Security Implications

### Why Public S3 Buckets Are Dangerous
1. **Data Exposure**: Sensitive files accessible to anyone on the internet
2. **Data Breaches**: Potential for massive data leaks
3. **Compliance Violations**: May breach GDPR, HIPAA, PCI DSS requirements
4. **Reputation Damage**: Public exposure of confidential information
5. **Financial Impact**: Potential fines and legal consequences

### Common Causes of Public Buckets
- **Misconfiguration**: Incorrect ACL or policy settings
- **Legacy Settings**: Old buckets with outdated security configurations
- **Human Error**: Accidental public access grants
- **Development Practices**: Dev/test buckets inadvertently made public

## Remediation Steps

### Immediate Actions for Public Buckets

1. **Review Bucket Contents**
   ```bash
   # With default profile
   aws s3 ls s3://your-public-bucket --recursive
   
   # With specific profile
   aws s3 ls s3://your-public-bucket --recursive --profile production
   ```

2. **Check for Sensitive Data**
   ```bash
   # Look for common sensitive file types with default profile
   aws s3 ls s3://your-bucket --recursive | grep -E '\.(txt|csv|json|sql|key|pem)$'
   
   # Look for common sensitive file types with specific profile
   aws s3 ls s3://your-bucket --recursive --profile production | grep -E '\.(txt|csv|json|sql|key|pem)$'
   ```

3. **Remove Public ACL Permissions**
   ```bash
   # With default profile
   aws s3api put-bucket-acl --bucket your-bucket-name --acl private
   
   # With specific profile
   aws s3api put-bucket-acl --bucket your-bucket-name --acl private --profile production
   ```

4. **Remove Public Bucket Policies**
   ```bash
   # First check current policy with default profile
   aws s3api get-bucket-policy --bucket your-bucket-name
   
   # First check current policy with specific profile
   aws s3api get-bucket-policy --bucket your-bucket-name --profile production
   
   # Remove policy if it grants public access (default profile)
   aws s3api delete-bucket-policy --bucket your-bucket-name
   
   # Remove policy if it grants public access (specific profile)
   aws s3api delete-bucket-policy --bucket your-bucket-name --profile production
   ```

5. **Enable Block Public Access**
   ```bash
   # With default profile
   aws s3api put-public-access-block --bucket your-bucket-name --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
   
   # With specific profile
   aws s3api put-public-access-block --bucket your-bucket-name --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" --profile production
   ```

### Secure Bucket Configuration Example
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyPublicAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::your-bucket-name",
                "arn:aws:s3:::your-bucket-name/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```

## Security Best Practices

### Preventive Measures
1. **Block Public Access**: Enable at account and bucket level
2. **Principle of Least Privilege**: Grant minimum necessary permissions
3. **Regular Auditing**: Run this tool regularly
4. **Access Logging**: Enable S3 access logging
5. **Encryption**: Use server-side encryption for sensitive data

### Account-Level Public Access Block
```bash
# With default profile
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# With specific profile
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --profile production
```

### Monitoring and Alerting
```bash
# CloudTrail event for public bucket creation
{
    "eventName": "PutBucketAcl",
    "responseElements": {
        "x-amz-acl": "public-read"
    }
}
```

## Configuration Options

### Extending the Script
```python
def check_bucket_encryption(s3, bucket_name):
    """Check if bucket has encryption enabled"""
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        return True
    except:
        return False

def check_bucket_versioning(s3, bucket_name):
    """Check if bucket has versioning enabled"""
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        return response.get('Status') == 'Enabled'
    except:
        return False
```

### Filtering Specific Buckets
```python
# Add bucket name filters
EXCLUDE_BUCKETS = ['known-public-bucket', 'website-assets']
if bucket_name in EXCLUDE_BUCKETS:
    continue
```

## Troubleshooting

### Common Issues

1. **Access Denied for Bucket Policy**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Some buckets may deny policy access even to owners. This is normal for certain configurations.

2. **No Such Bucket Policy**
   ```
   NoSuchBucketPolicy: The bucket policy does not exist
   ```
   **Solution**: This is normal - not all buckets have policies. The script handles this gracefully.

3. **Forbidden Access**
   ```
   An error occurred (403) when calling the GetBucketAcl operation
   ```
   **Solution**: Your IAM user/role may lack permissions for certain buckets.

### Debug Mode
For detailed troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Monitoring

### Scheduled Security Audits
```bash
# Daily S3 public bucket check with default profile
0 9 * * * /usr/bin/python3 /path/to/check_public_s3_cli.py >> /var/log/s3-audit.log 2>&1

# Daily S3 public bucket check for production environment
0 8 * * * /usr/bin/python3 /path/to/check_public_s3_cli.py --profile production >> /var/log/s3-audit-prod.log 2>&1

# Weekly compliance report for staging
0 9 * * 1 /usr/bin/python3 /path/to/check_public_s3_cli.py --profile staging --export-csv /reports/staging_s3_$(date +\%Y\%m\%d).csv

# Daily alert for any public S3 buckets in production
0 10 * * * /usr/bin/python3 /path/to/check_public_s3_cli.py --profile production --public-only || echo "Public S3 buckets detected!"
```

### Integration with Security Tools
```bash
#!/bin/bash
# Multi-environment public S3 monitoring
for profile in production staging development; do
    echo "Checking $profile environment..."
    output=$(python3 check_public_s3_cli.py --profile $profile)
    
    if echo "$output" | grep -q "⚠️ Public buckets found"; then
        echo "$output" | mail -s "Public S3 Bucket Alert - $profile" security@company.com
    fi
done

# Simple alert with default profile
output=$(python3 check_public_s3_cli.py)
if echo "$output" | grep -q "⚠️ Public buckets found"; then
    echo "$output" | mail -s "Public S3 Bucket Alert" security@company.com
fi
```

### CloudWatch Metrics
```python
def send_public_bucket_metric(public_count, profile=None):
    import boto3
    
    if profile:
        session = boto3.Session(profile_name=profile)
        cloudwatch = session.client('cloudwatch')
    else:
        cloudwatch = boto3.client('cloudwatch')
    
    cloudwatch.put_metric_data(
        Namespace='Security/S3',
        MetricData=[{
            'MetricName': 'PublicBuckets',
            'Value': public_count,
            'Unit': 'Count'
        }]
    )
```

### AWS Config Rule
Create a custom AWS Config rule to monitor public S3 buckets:
```json
{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {
        "Owner": "AWS",
        "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
}
```

## Compliance Frameworks

This tool helps meet requirements for:
- **GDPR**: Data protection and privacy by design
- **HIPAA**: Safeguards for protected health information
- **PCI DSS**: Protection of cardholder data
- **SOC 2**: Security controls for customer data
- **ISO 27001**: Information security management
- **CIS AWS Foundations Benchmark**: S3 security controls

## Related AWS Services

- **AWS Config**: Automated compliance monitoring
- **AWS Security Hub**: Centralized security findings
- **AWS Macie**: Data security and data privacy service
- **AWS CloudTrail**: API call logging and monitoring
- **AWS Trusted Advisor**: Security recommendations

## Emergency Response

### Immediate Steps for Data Exposure
1. **Secure the Bucket**: Remove public access immediately
2. **Assess Impact**: Determine what data was exposed
3. **Notify Stakeholders**: Alert security team and management
4. **Document Incident**: Record timeline and actions taken
5. **Review Logs**: Check access logs for unauthorized activity
6. **Legal Compliance**: Consider notification requirements under applicable laws

## Security Considerations

- This tool only reads S3 metadata and doesn't access bucket contents
- Results may contain sensitive bucket names in logs
- Regular monitoring should be part of your security program
- Consider implementing automated remediation for critical buckets