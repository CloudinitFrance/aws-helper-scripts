# Public RDS Instance Detector

A critical security auditing tool that identifies publicly accessible RDS database instances in your AWS account. Public RDS instances pose significant security risks and should be carefully reviewed and secured.

## Description

This script performs a comprehensive security audit of your RDS instances to identify potential security vulnerabilities by:

- **Public Accessibility Detection**: Identifies RDS instances with `PubliclyAccessible` set to `true`
- **Multi-Region Support**: Scans RDS instances in any specified AWS region
- **Detailed Instance Information**: Shows engine type, instance class, and endpoint details
- **Security Risk Assessment**: Highlights instances that may be exposed to the internet

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
                "rds:DescribeDBInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Scan specific region
python3 check_public_rds_cli.py --region us-east-1

# Use specific AWS profile
python3 check_public_rds_cli.py --profile production --region us-east-1

# Scan all regions with profile
python3 check_public_rds_cli.py --profile staging --all-regions

# Export detailed report
python3 check_public_rds_cli.py --profile production --all-regions --export-csv rds_security_report.csv

# Show only public instances
python3 check_public_rds_cli.py --profile production --all-regions --public-only
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--profile` | AWS profile to use for credentials | None (uses default) |
| `--region` | Specific AWS region to check | None |
| `--all-regions` | Check all available regions | False |
| `--export-csv` | Export results to CSV file | None |
| `--export-json` | Export results to JSON file | None |
| `--public-only` | Show only publicly accessible instances | False |

### Examples
```bash
# Check RDS instances in US East 1 with production profile
python3 check_public_rds_cli.py --profile production --region us-east-1

# Check RDS instances in EU West 1 with staging profile
python3 check_public_rds_cli.py --profile staging --region eu-west-1

# Comprehensive multi-region scan for production environment
python3 check_public_rds_cli.py --profile production --all-regions --export-csv prod_rds_audit.csv
```

## Example Output

### Public RDS Instances Found (Security Risk)
```
DB Identifier             Engine     Class           Public Access   Endpoint
----------------------------------------------------------------------------------------------------
prod-webapp-db           mysql      db.t3.medium    True            prod-webapp-db.abc123.us-east-1.rds.amazonaws.com
analytics-db             postgres   db.r5.large     True            analytics-db.def456.us-east-1.rds.amazonaws.com
legacy-system-db         oracle-ee  db.m5.xlarge    True            legacy-system-db.ghi789.us-east-1.rds.amazonaws.com

🚨 WARNING: Publicly accessible RDS instances found:
 - prod-webapp-db
 - analytics-db
 - legacy-system-db
```

### No Public RDS Instances (Good Security Posture)
```
DB Identifier             Engine     Class           Public Access   Endpoint
----------------------------------------------------------------------------------------------------
internal-app-db          mysql      db.t3.medium    False           internal-app-db.abc123.us-east-1.rds.amazonaws.com
private-analytics        postgres   db.r5.large     False           private-analytics.def456.us-east-1.rds.amazonaws.com
secure-prod-db           mysql      db.m5.large     False           secure-prod-db.ghi789.us-east-1.rds.amazonaws.com

✅ No publicly accessible RDS instances detected.
```

## Understanding the Output

### Column Descriptions
- **DB Identifier**: The unique identifier for the RDS instance
- **Engine**: Database engine type (mysql, postgres, oracle-ee, sqlserver-ex, etc.)
- **Class**: Instance type and size (e.g., db.t3.medium, db.r5.large)
- **Public Access**: Whether the instance is publicly accessible (True/False)
- **Endpoint**: The database connection endpoint

### Security Risk Assessment
- **🚨 Critical Risk**: Instances with `Public Access: True`
- **✅ Secure**: Instances with `Public Access: False`

## Security Implications

### Why Public RDS Instances Are Risky
1. **Internet Exposure**: Accessible from anywhere on the internet
2. **Attack Surface**: Increased vulnerability to brute force attacks
3. **Data Breach Risk**: Direct access to sensitive database content
4. **Compliance Issues**: May violate data protection regulations

### Common Legitimate Use Cases
- **Development/Testing**: Temporary databases for external access
- **Third-Party Integration**: APIs requiring external database access
- **Data Analytics**: External tools needing database connectivity

## Remediation Steps

### Immediate Actions for Public RDS Instances

1. **Review Necessity**
   ```bash
   # Check if public access is actually required
   aws rds describe-db-instances --db-instance-identifier your-db-name
   ```

2. **Disable Public Access** (if not needed)
   ```bash
   aws rds modify-db-instance \
     --db-instance-identifier your-db-name \
     --no-publicly-accessible \
     --apply-immediately
   ```

3. **Review Security Groups**
   ```bash
   # Ensure security groups have restrictive rules
   aws ec2 describe-security-groups --group-ids sg-xxxxxxxx
   ```

4. **Implement VPC Endpoints** (for internal access)
   ```bash
   aws ec2 create-vpc-endpoint \
     --vpc-id vpc-xxxxxxxx \
     --service-name com.amazonaws.region.rds
   ```

### Security Best Practices

1. **Use Private Subnets**: Place RDS instances in private subnets
2. **Restrictive Security Groups**: Allow only necessary IP ranges
3. **VPN/Bastion Access**: Use VPN or bastion hosts for external access
4. **Database Encryption**: Enable encryption at rest and in transit
5. **Regular Auditing**: Run this tool regularly to monitor compliance

## Configuration Options

### Supported Database Engines
- **MySQL**: mysql
- **PostgreSQL**: postgres
- **Oracle**: oracle-ee, oracle-se2, oracle-se1, oracle-se
- **SQL Server**: sqlserver-ee, sqlserver-se, sqlserver-ex, sqlserver-web
- **MariaDB**: mariadb
- **Amazon Aurora**: aurora-mysql, aurora-postgresql

### Multi-Region Scanning
```bash
#!/bin/bash
# Scan multiple regions with specific profile
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
for region in "${regions[@]}"; do
    echo "Scanning region: $region"
    python3 check_public_rds_cli.py --profile production --region "$region"
    echo "---"
done

# Or scan all regions at once
python3 check_public_rds_cli.py --profile production --all-regions
```

## Troubleshooting

### Common Issues

1. **Invalid Region Error**
   ```
   Could not connect to the endpoint URL
   ```
   **Solution**: Verify the region name is correct and RDS is available in that region.

2. **Access Denied Error**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Ensure your AWS credentials have the required RDS permissions.

3. **No RDS Instances Found**
   ```
   No RDS instances found in region
   ```
   **Solution**: Verify you're scanning the correct region and have RDS instances.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Monitoring

### Scheduled Security Audits
```bash
# Daily public RDS check for production environment
0 8 * * * /usr/bin/python3 /path/to/check_public_rds_cli.py --profile production --all-regions >> /var/log/rds-audit.log 2>&1

# Weekly compliance report for staging
0 9 * * 1 /usr/bin/python3 /path/to/check_public_rds_cli.py --profile staging --all-regions --export-csv /reports/staging_rds_$(date +\%Y\%m\%d).csv

# Daily alert for any public RDS instances in production
0 10 * * * /usr/bin/python3 /path/to/check_public_rds_cli.py --profile production --all-regions --public-only || echo "Public RDS instances detected!"
```

### Integration with Security Tools
```bash
#!/bin/bash
# Multi-environment public RDS monitoring
for profile in production staging development; do
    echo "Checking $profile environment..."
    output=$(python3 check_public_rds_cli.py --profile $profile --all-regions)
    
    if echo "$output" | grep -q "🚨 WARNING"; then
        echo "$output" | mail -s "Public RDS Alert - $profile" security@company.com
    fi
done
```

### CloudWatch Integration
```python
import boto3

def send_cloudwatch_metric(public_instance_count):
    cloudwatch = boto3.client('cloudwatch')
    cloudwatch.put_metric_data(
        Namespace='Security/RDS',
        MetricData=[
            {
                'MetricName': 'PublicInstances',
                'Value': public_instance_count,
                'Unit': 'Count'
            }
        ]
    )
```

## Compliance Frameworks

This tool helps meet requirements for:
- **SOC 2**: Security controls for data protection
- **PCI DSS**: Network security requirements for cardholder data
- **HIPAA**: Safeguards for protected health information
- **GDPR**: Data protection and security measures
- **CIS AWS Foundations Benchmark**: Database security controls

## Related AWS Services

- **AWS Config**: Automated compliance monitoring
- **AWS Security Hub**: Centralized security findings
- **AWS VPC Flow Logs**: Network traffic monitoring
- **AWS GuardDuty**: Threat detection for databases
- **AWS Inspector**: Security assessment service

## Security Considerations

- This tool only reads RDS metadata and doesn't access database content
- Results may contain sensitive database identifiers
- Consider network security in addition to RDS public access settings
- Regular monitoring should be part of your security program