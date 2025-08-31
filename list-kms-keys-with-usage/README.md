# KMS Keys Usage Analyzer

A comprehensive AWS KMS (Key Management Service) auditing tool that lists all customer-managed keys with their usage status, helping you identify unused keys for cost optimization and security cleanup.

## Description

This script provides detailed analysis of your KMS key usage by:

- **Comprehensive Key Inventory**: Lists all customer-managed KMS keys
- **Usage Tracking**: Shows when each key was last used for cryptographic operations
- **Key Status Monitoring**: Displays key state (enabled, disabled, pending deletion)
- **Cost Optimization**: Identifies unused keys that may be candidates for deletion
- **Security Audit**: Helps maintain clean key inventory for better security posture

## Prerequisites

### Required Python Packages
```bash
pip install boto3
```

### AWS Credentials
Configure AWS credentials using one of these methods:
- AWS CLI: `aws configure`
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
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:GetKeyRotationStatus",
                "kms:GetKeyPolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
python3 list_kms_keys_with_usage_cli.py
```

The script automatically scans all KMS keys in your current AWS region and displays their usage information.

## Example Output

### Active KMS Keys Environment
```
Key ID                               Enabled  Key State    Last Used          Description
----------------------------------------------------------------------------------------------------
12345678-1234-1234-1234-123456789012 True     Enabled      2024-01-15 14:30 UTC  Production database encryption
23456789-2345-2345-2345-234567890123 True     Enabled      2024-01-14 09:15 UTC  S3 bucket encryption key
34567890-3456-3456-3456-345678901234 True     Enabled      2024-01-10 16:45 UTC  Lambda environment variables
45678901-4567-4567-4567-456789012345 True     Disabled     2023-12-20 11:20 UTC  Legacy application key
56789012-5678-5678-5678-567890123456 False    Enabled      Never                 Test environment key
67890123-6789-6789-6789-678901234567 True     Enabled      2024-01-16 08:00 UTC  CloudTrail log encryption
```

### Mixed Environment with Issues
```
Key ID                               Enabled  Key State    Last Used          Description
----------------------------------------------------------------------------------------------------
11111111-1111-1111-1111-111111111111 True     Enabled      2024-01-15 10:30 UTC  Active production key
22222222-2222-2222-2222-222222222222 False    Disabled     2023-10-01 14:20 UTC  Deprecated old key
33333333-3333-3333-3333-333333333333 True     Enabled      Never                 Unused test key
44444444-4444-4444-4444-444444444444 ERROR    Error: Access denied for key description
55555555-5555-5555-5555-555555555555 True     PendingDeletion 2023-11-15 09:00 UTC  Scheduled for deletion
```

## Understanding the Output

### Column Descriptions
- **Key ID**: Unique identifier for the KMS key
- **Enabled**: Whether the key is currently enabled for use
- **Key State**: Current state (Enabled, Disabled, PendingDeletion, etc.)
- **Last Used**: When the key was last used for cryptographic operations
- **Description**: User-provided description of the key's purpose

### Key States Explained
- **Enabled**: Key is active and can be used for encryption/decryption
- **Disabled**: Key is temporarily disabled but can be re-enabled
- **PendingDeletion**: Key is scheduled for deletion (7-30 day waiting period)
- **PendingImport**: Key material is being imported
- **Creating**: Key is being created
- **Unavailable**: Key is temporarily unavailable

### Usage Indicators
- **Recent Date**: Key is actively used (good)
- **Old Date**: Key may be abandoned or rarely used
- **Never**: Key has never been used for cryptographic operations (potential cleanup candidate)

## Cost Optimization Analysis

### KMS Pricing (as of 2024)
- **Customer-managed keys**: $1.00 per key per month
- **Key usage**: $0.03 per 10,000 requests

### Cost Calculation Example
```
If you have 50 KMS keys:
- Monthly cost: 50 × $1.00 = $50.00
- Annual cost: $600.00

If 20 keys are unused:
- Potential monthly savings: 20 × $1.00 = $20.00
- Potential annual savings: $240.00
```

### Identifying Cost Optimization Opportunities
1. **Never Used Keys**: Prime candidates for deletion
2. **Long Unused Keys**: Keys not used in 90+ days
3. **Disabled Keys**: May be safe to delete if no longer needed
4. **Test Environment Keys**: Often forgotten and left running

## Security and Compliance Benefits

### Key Inventory Management
- **Principle of Least Privilege**: Remove unnecessary keys
- **Attack Surface Reduction**: Fewer keys mean fewer potential targets
- **Compliance Auditing**: Clean inventory for SOC 2, ISO 27001, etc.
- **Key Rotation Planning**: Identify keys that need rotation

### Security Best Practices
1. **Regular Auditing**: Run this tool monthly
2. **Unused Key Cleanup**: Delete keys that haven't been used in 90+ days
3. **Key Rotation**: Enable automatic rotation for frequently used keys
4. **Access Monitoring**: Monitor key usage patterns for anomalies

## Remediation Actions

### Safe Key Deletion Process

1. **Verify Key Usage**
   ```bash
   # Check key usage in CloudTrail
   aws logs filter-log-events \
     --log-group-name CloudTrail/KMSKeyUsage \
     --start-time 1640995200000 \
     --filter-pattern "{ $.eventName = Decrypt || $.eventName = Encrypt }" \
     --query 'events[?responseElements.keyId==`12345678-1234-1234-1234-123456789012`]'
   ```

2. **Disable Key First** (reversible test)
   ```bash
   aws kms disable-key --key-id 12345678-1234-1234-1234-123456789012
   ```

3. **Monitor for Issues** (wait 24-48 hours)
   ```bash
   # Check for any applications failing due to disabled key
   aws logs filter-log-events \
     --log-group-name /aws/lambda/your-function \
     --filter-pattern "KMS"
   ```

4. **Schedule Deletion** (if no issues)
   ```bash
   aws kms schedule-key-deletion \
     --key-id 12345678-1234-1234-1234-123456789012 \
     --pending-window-in-days 30
   ```

### Key Cleanup Workflow
```bash
#!/bin/bash
# Automated key cleanup workflow

# Step 1: Generate unused key report
python3 list_kms_keys_with_usage_cli.py > kms_audit_$(date +%Y%m%d).txt

# Step 2: Identify keys unused for 90+ days
aws kms list-keys --query 'Keys[*].KeyId' --output text | \
while read key_id; do
    last_used=$(aws kms get-key-rotation-status --key-id $key_id 2>/dev/null)
    # Add your logic to check last usage date
done

# Step 3: Generate cleanup script
echo "#!/bin/bash" > cleanup_unused_keys.sh
echo "# Review this script before execution" >> cleanup_unused_keys.sh
```

## Configuration Options

### Extending the Script

#### Add Key Rotation Status
```python
def check_key_rotation(kms, key_id):
    """Check if automatic key rotation is enabled"""
    try:
        response = kms.get_key_rotation_status(KeyId=key_id)
        return response['KeyRotationEnabled']
    except Exception:
        return False

# Usage
rotation_enabled = check_key_rotation(kms, key_id)
print(f"Auto-rotation: {'Enabled' if rotation_enabled else 'Disabled'}")
```

#### Add Key Policy Analysis
```python
def analyze_key_policy(kms, key_id):
    """Analyze key policy for overly permissive access"""
    try:
        policy = kms.get_key_policy(KeyId=key_id, PolicyName='default')
        policy_doc = json.loads(policy['Policy'])
        
        # Check for wildcard principals
        for statement in policy_doc.get('Statement', []):
            if statement.get('Principal') == '*':
                return 'Public Access Detected'
        return 'Restricted Access'
    except Exception:
        return 'Policy Check Failed'
```

#### Add Usage Metrics Integration
```python
def get_detailed_usage_metrics(key_id, days=30):
    """Get detailed usage metrics from CloudWatch"""
    import boto3
    from datetime import datetime, timedelta
    
    cloudwatch = boto3.client('cloudwatch')
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/KMS',
            MetricName='NumberOfRequestsSucceeded',
            Dimensions=[{'Name': 'KeyId', 'Value': key_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # 1 day
            Statistics=['Sum']
        )
        
        total_requests = sum(point['Sum'] for point in response['Datapoints'])
        return total_requests
    except Exception:
        return 0
```

#### Export to Different Formats
```python
def export_to_csv(keys_data, filename='kms_keys_audit.csv'):
    """Export KMS key data to CSV format"""
    import csv
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['KeyId', 'Enabled', 'KeyState', 'LastUsed', 'Description', 'MonthlyUsage'])
        
        for key_data in keys_data:
            writer.writerow([
                key_data['key_id'],
                key_data['enabled'],
                key_data['key_state'],
                key_data['last_used'],
                key_data['description'],
                key_data.get('monthly_usage', 0)
            ])

def export_to_json(keys_data, filename='kms_keys_audit.json'):
    """Export KMS key data to JSON format"""
    import json
    
    with open(filename, 'w') as jsonfile:
        json.dump(keys_data, jsonfile, indent=2, default=str)
```

## Advanced Usage

### Multi-Region Analysis
```bash
#!/bin/bash
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
echo "KMS Keys Usage Report - $(date)" > kms_global_audit.txt
echo "======================================" >> kms_global_audit.txt

for region in "${regions[@]}"; do
    echo "" >> kms_global_audit.txt
    echo "Region: $region" >> kms_global_audit.txt
    echo "----------------" >> kms_global_audit.txt
    AWS_DEFAULT_REGION=$region python3 list_kms_keys_with_usage_cli.py >> kms_global_audit.txt
done
```

### Integration with Cost Management
```python
def calculate_potential_savings(unused_keys):
    """Calculate potential cost savings from key cleanup"""
    monthly_key_cost = 1.00  # USD per key per month
    monthly_savings = len(unused_keys) * monthly_key_cost
    annual_savings = monthly_savings * 12
    
    return {
        'unused_key_count': len(unused_keys),
        'monthly_savings': monthly_savings,
        'annual_savings': annual_savings
    }

def send_cost_metrics(savings_data):
    """Send cost optimization metrics to CloudWatch"""
    import boto3
    cloudwatch = boto3.client('cloudwatch')
    
    cloudwatch.put_metric_data(
        Namespace='Cost/KMSOptimization',
        MetricData=[
            {
                'MetricName': 'UnusedKeys',
                'Value': savings_data['unused_key_count'],
                'Unit': 'Count'
            },
            {
                'MetricName': 'PotentialMonthlySavings',
                'Value': savings_data['monthly_savings'],
                'Unit': 'None'
            }
        ]
    )
```

### Automated Alerting
```bash
#!/bin/bash
# Alert on excessive unused keys
output=$(python3 list_kms_keys_with_usage_cli.py)
unused_count=$(echo "$output" | grep "Never" | wc -l)

if [ $unused_count -gt 10 ]; then
    echo "WARNING: $unused_count unused KMS keys detected" | \
    mail -s "KMS Key Cleanup Required" finance@company.com
fi
```

## Troubleshooting

### Common Issues

1. **Access Denied for Key Description**
   ```
   ERROR Error: Access denied for key description
   ```
   **Solution**: Some keys may have restrictive policies. This is normal and handled gracefully.

2. **Key Not Found**
   ```
   InvalidKeyId.NotFound: Key 'arn:aws:kms:...' does not exist
   ```
   **Solution**: Key may have been deleted between listing and description calls.

3. **Rate Limiting**
   ```
   ThrottlingException: Rate exceeded
   ```
   **Solution**: The script includes basic error handling. For large numbers of keys, consider adding delays.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Monitoring

### Scheduled Auditing
```bash
# Monthly KMS key audit
0 9 1 * * /usr/bin/python3 /path/to/list_kms_keys_with_usage.py > /var/log/kms-audit-$(date +\%Y\%m).txt 2>&1
```

### Integration with ITSM
```python
def create_cleanup_ticket(unused_keys):
    """Create ITSM ticket for key cleanup"""
    import requests
    
    ticket_data = {
        'title': f'KMS Key Cleanup Required - {len(unused_keys)} unused keys',
        'description': f'Found {len(unused_keys)} unused KMS keys that may be deleted for cost optimization',
        'priority': 'Medium',
        'category': 'Cost Optimization'
    }
    
    response = requests.post(
        'https://itsm.company.com/api/tickets',
        json=ticket_data,
        headers={'Authorization': 'Bearer TOKEN'}
    )
```

### CloudWatch Dashboard Integration
```python
def create_kms_dashboard():
    """Create CloudWatch dashboard for KMS monitoring"""
    import boto3
    
    cloudwatch = boto3.client('cloudwatch')
    
    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "properties": {
                    "metrics": [["Cost/KMSOptimization", "UnusedKeys"]],
                    "period": 2592000,  # Monthly
                    "stat": "Average",
                    "region": "us-east-1",
                    "title": "Unused KMS Keys"
                }
            }
        ]
    }
    
    cloudwatch.put_dashboard(
        DashboardName='KMS-Cost-Optimization',
        DashboardBody=json.dumps(dashboard_body)
    )
```

## Best Practices

### Key Lifecycle Management
1. **Regular Auditing**: Run monthly audits to identify unused keys
2. **Staged Deletion**: Disable before deleting to test for dependencies
3. **Documentation**: Maintain key inventory with business justification
4. **Automated Cleanup**: Implement automated workflows for key lifecycle
5. **Cost Monitoring**: Track KMS costs and optimization opportunities

### Security Guidelines
1. **Principle of Least Privilege**: Only keep keys that are actively needed
2. **Key Rotation**: Enable automatic rotation for frequently used keys
3. **Access Monitoring**: Monitor key usage for unusual patterns
4. **Policy Reviews**: Regularly review key policies for overly permissive access
5. **Compliance**: Ensure key management meets regulatory requirements

## Compliance Frameworks

This tool helps meet requirements for:
- **SOC 2**: Controls for data encryption and key management
- **ISO 27001**: Information security management requirements
- **PCI DSS**: Cryptographic key management requirements
- **HIPAA**: Encryption key management for healthcare data
- **GDPR**: Data protection through proper encryption practices

## Related AWS Services

- **AWS CloudTrail**: Monitor KMS key usage activities
- **AWS Config**: Track KMS key configuration changes
- **AWS Cost Explorer**: Analyze KMS costs and trends
- **AWS Systems Manager**: Automate key management tasks
- **AWS Secrets Manager**: Alternative for application secrets

## Security Considerations

- This tool only reads KMS metadata and doesn't access encrypted data
- Key usage information may be sensitive for security planning
- Consider access controls for audit reports
- Regular key auditing should be part of your security program
- Maintain audit trails for all key deletion activities