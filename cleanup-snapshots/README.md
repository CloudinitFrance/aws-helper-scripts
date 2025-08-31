# EBS Snapshot Cleanup Tool

A cost optimization and storage management tool that identifies and deletes old, untagged EBS snapshots to reduce AWS storage costs and maintain clean snapshot inventories.

## Description

This script helps you manage EBS snapshot lifecycle and reduce storage costs by:

- **Age-Based Filtering**: Identifies snapshots older than a specified number of days
- **Tag-Based Protection**: Preserves snapshots with any tags (indicating they're managed/important)
- **Dry-Run Capability**: Preview deletions before executing them
- **Cost Optimization**: Reduces storage costs by removing unnecessary snapshots
- **Safety Features**: Only targets untagged snapshots to prevent accidental deletion

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
                "ec2:DescribeSnapshots",
                "ec2:DeleteSnapshot"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Dry run - see what would be deleted (recommended first step)
python3 cleanup_snapshots_cli.py --days 30 --dry-run

# Use specific AWS profile
python3 cleanup_snapshots_cli.py --profile production --days 30 --dry-run

# Actually delete old snapshots with profile
python3 cleanup_snapshots_cli.py --profile production --days 30

# Specify region and profile
python3 cleanup_snapshots_cli.py --profile staging --region us-west-2 --days 30 --dry-run

# Scan all regions with dry-run
python3 cleanup_snapshots_cli.py --profile production --all-regions --days 30 --dry-run

# Clean up all regions (not recommended without dry-run first)
python3 cleanup_snapshots_cli.py --profile staging --all-regions --days 60 --require-untagged
```

### Command Line Options
- `--days`: Age threshold in days (default: 30)
- `--dry-run`: Preview mode - show what would be deleted without actually deleting
- `--profile`: AWS profile to use for credentials
- `--region`: AWS region (default: uses profile/session region)
- `--all-regions`: Scan all AWS regions (overrides --region)
- `--require-untagged`: Only consider completely untagged snapshots (safer)
- `--force`: Skip interactive confirmation (not recommended)

### Examples
```bash
# Preview snapshots older than 60 days with default profile
python3 cleanup_snapshots_cli.py --days 60 --dry-run

# Preview snapshots older than 60 days with production profile
python3 cleanup_snapshots_cli.py --profile production --days 60 --dry-run

# Delete snapshots older than 7 days with staging profile (be careful!)
python3 cleanup_snapshots_cli.py --profile staging --days 7

# Clean up very old snapshots (1 year) in production
python3 cleanup_snapshots_cli.py --profile production --days 365 --dry-run

# More aggressive cleanup with production profile (only untagged, unused snapshots)
python3 cleanup_snapshots_cli.py --profile production --days 7 --require-untagged

# Multi-region snapshot cleanup examples
python3 cleanup_snapshots_cli.py --profile development --all-regions --days 30 --dry-run
python3 cleanup_snapshots_cli.py --profile staging --all-regions --days 60 --require-untagged --dry-run
python3 cleanup_snapshots_cli.py --profile production --all-regions --days 180 --require-untagged

# Region-specific examples for different environments
python3 cleanup_snapshots_cli.py --profile development --region us-east-1 --days 30 --dry-run
python3 cleanup_snapshots_cli.py --profile staging --region eu-west-1 --days 60 --dry-run
python3 cleanup_snapshots_cli.py --profile production --region ap-southeast-1 --days 90 --dry-run
```

## Example Output

### Dry Run Mode (Preview)
```
Found 12 untagged snapshots older than 30 days:
  snap-0a1b2c3d4e5f6g7h8
  snap-0b2c3d4e5f6g7h8i9
  snap-0c3d4e5f6g7h8i9j0
  snap-0d4e5f6g7h8i9j0k1
  snap-0e5f6g7h8i9j0k1l2
  snap-0f6g7h8i9j0k1l2m3
  snap-0g7h8i9j0k1l2m3n4
  snap-0h8i9j0k1l2m3n4o5
  snap-0i9j0k1l2m3n4o5p6
  snap-0j0k1l2m3n4o5p6q7
  snap-0k1l2m3n4o5p6q7r8
  snap-0l2m3n4o5p6q7r8s9
Dry run: no deletions performed.
```

### Actual Deletion
```
Found 5 untagged snapshots older than 30 days:
  snap-0a1b2c3d4e5f6g7h8
  snap-0b2c3d4e5f6g7h8i9
  snap-0c3d4e5f6g7h8i9j0
  snap-0d4e5f6g7h8i9j0k1
  snap-0e5f6g7h8i9j0k1l2
Deleted snap-0a1b2c3d4e5f6g7h8
Deleted snap-0b2c3d4e5f6g7h8i9
Deleted snap-0c3d4e5f6g7h8i9j0
Failed to delete snap-0d4e5f6g7h8i9j0k1: An error occurred (InvalidSnapshot.InUse)
Deleted snap-0e5f6g7h8i9j0k1l2
```

### No Snapshots to Clean
```
Found 0 untagged snapshots older than 30 days:
```

## Understanding the Output

### Snapshot Selection Criteria
- **Age**: Only snapshots older than specified days
- **Ownership**: Only snapshots owned by your account (OwnerIds=['self'])
- **Tags**: Only snapshots with NO tags (untagged)

### Safety Features
1. **Tag Protection**: Any snapshot with tags is preserved
2. **Dry Run**: Preview mode prevents accidental deletions
3. **Error Handling**: Continues processing if individual deletions fail
4. **Ownership Filter**: Only processes snapshots you own

## Cost Impact Analysis

### Estimating Cost Savings
```bash
# List snapshot sizes before cleanup with default profile
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?StartTime<`2023-01-01`].[SnapshotId,VolumeSize,StartTime]' --output table

# List snapshot sizes before cleanup with specific profile
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?StartTime<`2023-01-01`].[SnapshotId,VolumeSize,StartTime]' --output table --profile production

# Calculate approximate monthly cost (varies by region)
# General formula: GB * $0.05 per month (US regions)
```

### Example Cost Calculation
```
If you have 100 old snapshots averaging 20 GB each:
- Total storage: 2,000 GB
- Monthly cost: 2,000 * $0.05 = $100/month
- Annual savings: $1,200
```

## Configuration Options

### Customizing the Script

#### Add Volume Size Filtering
```python
def filter_by_size(snapshots, min_size_gb=10):
    """Only delete snapshots larger than min_size_gb"""
    return [s for s in snapshots if s['VolumeSize'] >= min_size_gb]
```

#### Add Description Filtering
```python
def filter_by_description(snapshots, exclude_patterns):
    """Exclude snapshots with specific description patterns"""
    import re
    filtered = []
    for snapshot in snapshots:
        description = snapshot.get('Description', '')
        if not any(re.search(pattern, description, re.IGNORECASE) 
                  for pattern in exclude_patterns):
            filtered.append(snapshot)
    return filtered

# Usage
exclude_patterns = ['backup', 'production', 'critical']
```

#### Add Interactive Mode
```python
def interactive_deletion(snapshot_ids):
    """Ask for confirmation before each deletion"""
    confirmed = []
    for snap_id in snapshot_ids:
        response = input(f"Delete {snap_id}? (y/N): ")
        if response.lower() == 'y':
            confirmed.append(snap_id)
    return confirmed
```

## Advanced Usage

### Multi-Region Cleanup
```bash
#!/bin/bash
# Cleanup with default profile
regions=("us-east-1" "us-west-2" "eu-west-1")
for region in "${regions[@]}"; do
    echo "Cleaning snapshots in $region"
    python3 cleanup_snapshots_cli.py --region $region --days 30 --dry-run
done

# Cleanup with specific profile
for region in "${regions[@]}"; do
    echo "Cleaning snapshots in $region for production"
    python3 cleanup_snapshots_cli.py --profile production --region $region --days 30 --dry-run
done
```

### Scheduled Cleanup
```bash
# Monthly cleanup cron job with default profile (first Sunday of each month at 2 AM)
0 2 1-7 * 0 /usr/bin/python3 /path/to/cleanup_snapshots_cli.py --days 90 >> /var/log/snapshot-cleanup.log 2>&1

# Monthly cleanup for production environment
0 2 1-7 * 0 /usr/bin/python3 /path/to/cleanup_snapshots_cli.py --profile production --days 90 >> /var/log/snapshot-cleanup-prod.log 2>&1

# Weekly cleanup for staging environment (Sundays at 3 AM)
0 3 * * 0 /usr/bin/python3 /path/to/cleanup_snapshots_cli.py --profile staging --days 30 --dry-run >> /var/log/snapshot-cleanup-staging.log 2>&1
```

### Integration with Monitoring
```python
import boto3

def send_cleanup_metrics(deleted_count, saved_gb, profile=None):
    """Send cleanup metrics to CloudWatch"""
    if profile:
        session = boto3.Session(profile_name=profile)
        cloudwatch = session.client('cloudwatch')
    else:
        cloudwatch = boto3.client('cloudwatch')
    
    cloudwatch.put_metric_data(
        Namespace='AWS/SnapshotCleanup',
        MetricData=[
            {
                'MetricName': 'SnapshotsDeleted',
                'Value': deleted_count,
                'Unit': 'Count'
            },
            {
                'MetricName': 'StorageFreed',
                'Value': saved_gb,
                'Unit': 'Gigabytes'
            }
        ]
    )
```

## Troubleshooting

### Common Issues

1. **Snapshot In Use Error**
   ```
   InvalidSnapshot.InUse: Snapshot snap-xxx is currently in use by ami-xxx
   ```
   **Solution**: Snapshot is being used by an AMI. This is expected behavior - the script continues with other snapshots.

2. **Permission Denied**
   ```
   UnauthorizedOperation: You are not authorized to perform this operation
   ```
   **Solution**: Ensure your IAM user/role has EC2 snapshot permissions.

3. **Snapshot Not Found**
   ```
   InvalidSnapshot.NotFound: The snapshot 'snap-xxx' does not exist
   ```
   **Solution**: Snapshot may have been deleted by another process. This is handled gracefully.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Snapshot Dependencies
```bash
# Check if snapshot is used by AMIs with default profile
aws ec2 describe-images --owners self --query 'Images[?BlockDeviceMappings[?Ebs.SnapshotId==`snap-xxx`]]'

# Check if snapshot is used by AMIs with specific profile
aws ec2 describe-images --owners self --query 'Images[?BlockDeviceMappings[?Ebs.SnapshotId==`snap-xxx`]]' --profile production

# Check if snapshot is being restored with default profile
aws ec2 describe-volumes --filters "Name=snapshot-id,Values=snap-xxx"

# Check if snapshot is being restored with specific profile
aws ec2 describe-volumes --filters "Name=snapshot-id,Values=snap-xxx" --profile production
```

## Safety Guidelines

### Pre-Cleanup Checklist
1. **Review Age Threshold**: Start with older snapshots (90+ days)
2. **Run Dry Mode First**: Always preview before deletion
3. **Check Critical Systems**: Ensure no important snapshots are untagged
4. **Backup Strategy**: Verify you have other backup mechanisms
5. **Test Restoration**: Ensure remaining snapshots are functional

### Recommended Tagging Strategy
```bash
# Tag important snapshots to protect them with default profile
aws ec2 create-tags --resources snap-xxx --tags Key=Purpose,Value=Production Key=Retention,Value=Long-term

# Tag important snapshots to protect them with specific profile
aws ec2 create-tags --resources snap-xxx --tags Key=Purpose,Value=Production Key=Retention,Value=Long-term --profile production
```

### Snapshot Lifecycle Management
Consider using AWS Data Lifecycle Manager (DLM) for automated snapshot management:
```json
{
    "ResourceTypes": ["VOLUME"],
    "TargetTags": [{"Key": "Backup", "Value": "true"}],
    "Schedules": [{
        "Name": "DailyBackups",
        "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS"},
        "RetainRule": {"Count": 7}
    }]
}
```

## Best Practices

### Operational Guidelines
1. **Start Conservative**: Begin with 90+ day old snapshots
2. **Regular Schedule**: Run monthly or quarterly cleanups
3. **Monitor Costs**: Track storage cost reductions
4. **Tag Everything**: Use consistent tagging for all important snapshots
5. **Document Process**: Maintain runbooks for snapshot management

### Automation Strategy
1. **Gradual Implementation**: Start with manual runs, then automate
2. **Monitoring Integration**: Alert on cleanup activities
3. **Cost Tracking**: Monitor storage cost trends
4. **Compliance**: Ensure cleanup aligns with data retention policies

## Related AWS Services

- **AWS Data Lifecycle Manager (DLM)**: Automated snapshot lifecycle management
- **AWS Cost Explorer**: Track snapshot storage costs
- **AWS Config**: Monitor snapshot compliance
- **AWS CloudWatch**: Metrics and monitoring for cleanup activities
- **AWS Systems Manager**: Automated maintenance tasks

## Security Considerations

- This tool can permanently delete data - use with caution
- Always test in non-production environments first
- Consider compliance and legal data retention requirements
- Monitor cleanup activities through CloudTrail
- Implement proper IAM controls for snapshot deletion permissions