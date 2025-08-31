# AWS Lambda Deprecated Runtime Detector

A comprehensive AWS Lambda security and compliance tool that dynamically fetches the latest runtime deprecation information from AWS documentation and scans your Lambda functions to identify those using deprecated or soon-to-be-deprecated runtimes.

## Description

This script helps you proactively manage AWS Lambda runtime deprecations by:

- **Dynamic Runtime Information**: Fetches real-time deprecation data from AWS documentation
- **Intelligent Scanning**: Identifies Lambda functions using deprecated or soon-to-be-deprecated runtimes
- **Multi-Region Support**: Scans across all AWS regions or a specific region
- **Risk Assessment**: Categorizes findings by urgency (CRITICAL, HIGH, MEDIUM)
- **Detailed Reporting**: Provides comprehensive function details and deprecation timelines
- **Export Capabilities**: Saves results to JSON format for further analysis

## Prerequisites

### Required Python Packages
```bash
pip install boto3 requests beautifulsoup4
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
                "lambda:ListFunctions",
                "lambda:GetFunction",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Interactive mode with prompts
python3 detect_outdated_lambda_runtimes_cli.py

# Use specific AWS profile
python3 detect_outdated_lambda_runtimes_cli.py --profile production

# Non-interactive mode with parameters
python3 detect_outdated_lambda_runtimes_cli.py --months 12 --all-regions --save-json --no-interactive

# Scan all regions with custom output file
python3 detect_outdated_lambda_runtimes_cli.py --profile staging --all-regions --output staging_deprecated_lambdas.json
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--profile` | AWS profile to use for credentials | None (uses default) |
| `--months` | Check for runtimes deprecated within N months | 6 |
| `--all-regions` | Scan all AWS regions | False (current region only) |
| `--save-json` | Automatically save results to JSON file | False (prompt user) |
| `--no-interactive` | Run without interactive prompts | False |
| `--output` | Output JSON file name | deprecated_lambda_functions.json |

### Interactive Options
In interactive mode, the script will prompt you for:
1. **Time Window**: How many months ahead to check for deprecations (default: 6)
2. **Scan Scope**: Whether to scan all regions or just the current region

### Example Session
```
🚀 AWS Lambda Deprecated Runtime Detector
============================================================
Using AWS profile: production
🔐 AWS Account: 123456789012
👤 User/Role: arn:aws:sts::123456789012:assumed-role/LambdaAuditor/user

📥 Fetching latest runtime information from AWS documentation...
✅ Found 15 deprecated runtimes
✅ Found 25 supported runtimes

❓ Check for runtimes deprecated or deprecating within how many months? (default: 6): 12

📋 At-risk runtimes to check (8): ['python3.6', 'python3.7', 'nodejs12.x', 'nodejs14.x', 'java8', 'dotnetcore3.1', 'ruby2.5', 'go1.x']

❓ Scan all regions? (y/N): y

🌍 Scanning all AWS regions...
🔍 Scanning region: us-east-1
  ⚠️  Found 3 functions with at-risk runtimes
🔍 Scanning region: us-west-2
  ✅ No at-risk runtimes found
```

## Example Output

### Console Output
```
📊 CRITICAL ALERT: Found 3 Lambda functions using deprecated or soon-to-be-deprecated runtimes
====================================================================================================

🚨 Runtime: Python 3.6 (python3.6) - Deprecated: Jul 18, 2022
   Status: DEPRECATED
   Functions affected: 2
   • legacy-data-processor in us-east-1
     ARN: arn:aws:lambda:us-east-1:123456789012:function:legacy-data-processor
     Last Modified: 2022-01-15T10:30:00.000+0000

   • old-api-handler in us-east-1
     ARN: arn:aws:lambda:us-east-1:123456789012:function:old-api-handler
     Last Modified: 2021-11-22T14:45:00.000+0000

⚠️ Runtime: Node.js 14.x (nodejs14.x) - Deprecated: Nov 27, 2023
   Status: DEPRECATING_IN_45_DAYS
   Functions affected: 1
   • notification-service in us-east-1
     ARN: arn:aws:lambda:us-east-1:123456789012:function:notification-service
     Last Modified: 2023-08-10T09:15:00.000+0000
```

### JSON Output
```json
[
  {
    "region": "us-east-1",
    "function_name": "legacy-data-processor",
    "function_arn": "arn:aws:lambda:us-east-1:123456789012:function:legacy-data-processor",
    "runtime": "python3.6",
    "runtime_name": "Python 3.6",
    "deprecation_date": "Jul 18, 2022",
    "status": "DEPRECATED",
    "urgency": "CRITICAL",
    "last_modified": "2022-01-15T10:30:00.000+0000",
    "code_size": 1024576,
    "memory_size": 128,
    "timeout": 30
  }
]
```

## Configuration Options

### Runtime Types Detected
- **Python**: 2.7, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11
- **Node.js**: 10.x, 12.x, 14.x, 16.x, 18.x, 20.x
- **Java**: 8, 11, 17, 21
- **.NET**: Core 2.1, Core 3.1, 6, 8
- **Ruby**: 2.5, 2.7, 3.2
- **Go**: 1.x
- **Custom Runtimes**: provided, provided.al2

### Urgency Levels
- **CRITICAL**: Runtime is already deprecated
- **HIGH**: Runtime will be deprecated within 90 days
- **MEDIUM**: Runtime will be deprecated within specified timeframe (but > 90 days)

## Troubleshooting

### Common Issues

1. **No AWS Credentials Found**
   ```
   Error: AWS credentials not found. Please configure your credentials.
   ```
   **Solution**: Configure AWS credentials using `aws configure` or environment variables.

2. **AWS Profile Not Found**
   ```
   AWS profile 'production' not found.
   ```
   **Solution**: List available profiles with `aws configure list-profiles` and configure the missing profile.

3. **Network Connection Issues**
   ```
   Error fetching AWS documentation: Connection timeout
   ```
   **Solution**: Check internet connectivity and firewall settings.

4. **Insufficient Permissions**
   ```
   Error scanning region us-east-1: AccessDenied
   ```
   **Solution**: Ensure your AWS credentials/profile have the required Lambda permissions.

5. **Empty Results**
   ```
   No runtimes are deprecated or will be deprecated within 6 months.
   ```
   **Solution**: Increase the time window or check if you have any Lambda functions.

### Debug Mode
For verbose output, modify the script to enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Regional Scanning Issues
If specific regions fail to scan:
- Check if Lambda service is available in that region
- Verify your AWS credentials have cross-region permissions
- Some regions may require explicit opt-in

## Best Practices

1. **Regular Scanning**: Run this tool monthly to stay ahead of deprecations
2. **Automation**: Integrate into CI/CD pipelines or scheduled jobs with appropriate profiles
3. **Multi-Environment**: Use different AWS profiles for production, staging, and development scans
4. **Documentation**: Keep track of runtime upgrade plans per environment
5. **Testing**: Test function compatibility with newer runtimes in development environments
6. **Gradual Migration**: Plan phased upgrades for large numbers of functions

### Automation Examples

```bash
# Daily production scan via cron
0 9 * * * /usr/bin/python3 /path/to/detect_outdated_lambda_runtimes_cli.py --profile production --months 6 --all-regions --save-json --no-interactive

# Weekly staging environment check
0 8 * * 1 /usr/bin/python3 /path/to/detect_outdated_lambda_runtimes_cli.py --profile staging --months 3 --save-json --no-interactive --output staging_lambda_audit.json

# CI/CD integration for pre-deployment checks
python3 detect_outdated_lambda_runtimes_cli.py --profile development --months 12 --no-interactive || echo "Warning: Deprecated runtimes detected"
```

## Security Considerations

- This tool only reads Lambda function metadata
- No function code is accessed or modified
- Results may contain sensitive function names in output files
- Use appropriate access controls for generated reports

## Related AWS Documentation

- [AWS Lambda Runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Lambda Runtime Deprecation Policy](https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html)
- [Migrating Lambda Functions](https://docs.aws.amazon.com/lambda/latest/dg/runtime-migrate.html)