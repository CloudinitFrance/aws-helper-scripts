# IAM Users MFA Compliance Checker

A security auditing tool that identifies IAM users with console access but no Multi-Factor Authentication (MFA) devices enabled. This is critical for maintaining AWS account security and compliance with security best practices.

## Description

This script performs a comprehensive audit of your AWS IAM users to identify potential security risks by:

- **Console Access Detection**: Identifies users with login profiles (console access)
- **MFA Device Verification**: Checks for attached MFA devices (virtual, hardware, or SMS)
- **Security Gap Identification**: Highlights users who can access the console without MFA
- **Compliance Reporting**: Provides clear output for security audits and compliance reviews

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
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:ListMFADevices"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Basic MFA compliance check
python3 check_iam_users_no_mfa_cli.py

# Use specific AWS profile
python3 check_iam_users_no_mfa_cli.py --profile production

# Export detailed report to CSV with profile
python3 check_iam_users_no_mfa_cli.py --profile staging --export-csv mfa_report.csv

# Show only non-compliant users for production environment
python3 check_iam_users_no_mfa_cli.py --profile production --show-violations-only

# Export to JSON with full details
python3 check_iam_users_no_mfa_cli.py --export-json mfa_report.json --include-inactive
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--profile` | AWS profile to use for credentials | None (uses default) |
| `--export-csv` | Export results to CSV file | None |
| `--export-json` | Export results to JSON file | None |
| `--show-violations-only` | Show only users without MFA | False |
| `--include-inactive` | Include users who have never logged in | False |

The script will automatically scan all IAM users in your AWS account and generate a comprehensive report.

## Example Output

### Sample Console Output
```
User Name                 Console Access  MFA Devices
------------------------------------------------------------
admin-user               True            2
developer-john           True            1
service-account-ci       False           0
backup-operator          True            0
read-only-analyst        True            1
api-service-user         False           0
temp-contractor          True            0

🚨 Users with console access but no MFA:
 - backup-operator
 - temp-contractor
```

### All Users Have MFA (Good Security Posture)
```
User Name                 Console Access  MFA Devices
------------------------------------------------------------
admin-user               True            2
developer-john           True            1
service-account-ci       False           0
read-only-analyst        True            1
api-service-user         False           0

✅ All console users have MFA enabled.
```

## Understanding the Output

### Column Descriptions
- **User Name**: IAM username
- **Console Access**: Whether the user has a login profile (can access AWS Console)
- **MFA Devices**: Number of MFA devices attached to the user

### Security Risk Indicators
- **🚨 Red Flag**: Users listed in the "Users with console access but no MFA" section
- **✅ Good**: Users with console access AND MFA devices enabled
- **Neutral**: Service accounts without console access (expected behavior)

## Configuration Options

### MFA Device Types Detected
- **Virtual MFA Devices**: Mobile apps like Google Authenticator, Authy
- **Hardware MFA Devices**: Physical tokens like YubiKey
- **SMS MFA**: Text message-based authentication (deprecated by AWS)

### Customization
To modify the script for additional checks, you can extend the functionality:

```python
# Add additional security checks
def check_additional_security(username):
    # Check last login time
    # Check access key age
    # Check attached policies
    pass
```

## Security Best Practices

### Immediate Actions for Non-Compliant Users
1. **Enable MFA**: Require all console users to set up MFA immediately
2. **Temporary Access**: Consider disabling console access until MFA is configured
3. **Policy Enforcement**: Implement IAM policies that require MFA for sensitive actions

### Sample MFA Enforcement Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}
```

## Troubleshooting

### Common Issues

1. **Access Denied Error**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Ensure your AWS credentials have the required IAM permissions listed above.

2. **No Credentials Error**
   ```
   botocore.exceptions.NoCredentialsError: Unable to locate credentials
   ```
   **Solution**: Configure AWS credentials using `aws configure` or environment variables.

3. **Permission Boundary Issues**
   ```
   User has permission boundary restrictions
   ```
   **Solution**: Check if your IAM user/role has permission boundaries that restrict IAM access.

### Debug Mode
For detailed debugging, modify the script to include error details:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Integration

### Scheduled Monitoring
```bash
# Daily MFA compliance check for production environment
0 9 * * * /usr/bin/python3 /path/to/check_iam_users_no_mfa_cli.py --profile production >> /var/log/mfa-audit.log 2>&1

# Weekly compliance report for staging
0 8 * * 1 /usr/bin/python3 /path/to/check_iam_users_no_mfa_cli.py --profile staging --export-csv /reports/staging_mfa_$(date +\%Y\%m\%d).csv

# Daily alert for any MFA violations in production
0 10 * * * /usr/bin/python3 /path/to/check_iam_users_no_mfa_cli.py --profile production --show-violations-only || echo "MFA violations detected in production!"
```

### Integration with Security Tools
- **AWS Config**: Use as a custom compliance rule
- **AWS Security Hub**: Integrate findings into Security Hub
- **Slack/Teams**: Send alerts for non-compliant users
- **SIEM**: Feed results into security monitoring systems

### Sample Alert Script
```bash
#!/bin/bash
# Multi-environment MFA compliance check
for profile in production staging development; do
    echo "Checking MFA compliance for $profile environment..."
    python3 check_iam_users_no_mfa_cli.py --profile $profile > /tmp/mfa_check_$profile.txt
    
    if grep -q "🚨" /tmp/mfa_check_$profile.txt; then
        # Send alert to security team
        mail -s "MFA Compliance Alert - $profile" security@company.com < /tmp/mfa_check_$profile.txt
    fi
done
```

## Compliance Frameworks

This tool helps meet requirements for:
- **ISO 27001**: Access control and authentication requirements
- **SOC 2**: Security controls for user authentication
- **PCI DSS**: Multi-factor authentication for administrative access
- **CIS AWS Foundations Benchmark**: Control 1.2 - Ensure MFA is enabled for all IAM users
- **AWS Well-Architected Security Pillar**: Identity and access management best practices

## Related AWS Services

- **AWS IAM Access Analyzer**: For additional access analysis
- **AWS CloudTrail**: For monitoring authentication events
- **AWS Config**: For compliance monitoring automation
- **AWS Security Hub**: For centralized security findings management

## Security Considerations

- This tool only reads IAM metadata and does not modify any settings
- Results may contain sensitive usernames in logs
- Consider running from a secure environment with appropriate access controls
- Regular auditing should be part of your security maintenance routine