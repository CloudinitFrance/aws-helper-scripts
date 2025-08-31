# Unused Security Groups Finder

A cost optimization and security cleanup tool that identifies unused EC2 Security Groups in your AWS account. Removing unused security groups helps maintain clean security configurations and reduces management overhead.

## Description

This script helps you identify and clean up unused security groups by:

- **Comprehensive Usage Detection**: Checks security group attachments to ENIs (Elastic Network Interfaces)
- **Default Security Group Protection**: Automatically excludes default security groups from cleanup
- **VPC-Aware Analysis**: Scans security groups across all VPCs in the specified region
- **Safe Identification**: Only identifies truly unused security groups for potential removal

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
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeVpcs"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
python3 find_unused_sgs_cli.py --region us-east-1
```

### Required Parameters
- `--region`: AWS region to scan (required)

### Examples
```bash
# Find unused security groups in US East 1
python3 find_unused_sgs_cli.py --region us-east-1

# Find unused security groups in EU West 1
python3 find_unused_sgs_cli.py --region eu-west-1

# Find unused security groups in Asia Pacific Tokyo
python3 find_unused_sgs_cli.py --region ap-northeast-1
```

## Example Output

### Unused Security Groups Found
```
🧹 Unused Security Groups (7):
 - sg-0a1b2c3d4e5f6g7h8 (old-web-servers)
 - sg-0b2c3d4e5f6g7h8i9 (legacy-app-tier)
 - sg-0c3d4e5f6g7h8i9j0 (test-environment)
 - sg-0d4e5f6g7h8i9j0k1 (temp-migration-sg)
 - sg-0e5f6g7h8i9j0k1l2 (unused-database-sg)
 - sg-0f6g7h8i9j0k1l2m3 (old-load-balancer-sg)
 - sg-0g7h8i9j0k1l2m3n4 (archived-project-sg)
```

### No Unused Security Groups (Clean Environment)
```
✅ No unused security groups found.
```

## Understanding the Output

### Security Group Information
- **Security Group ID**: Unique identifier (sg-xxxxxxxxx)
- **Security Group Name**: Descriptive name in parentheses
- **Usage Status**: Only unused security groups are displayed

### What Makes a Security Group "Used"
A security group is considered "used" if it's:
1. **Attached to ENIs**: Associated with EC2 instances, load balancers, RDS instances, etc.
2. **Default Security Group**: Default security groups are always considered used
3. **Referenced by Other Security Groups**: (Note: current script doesn't check this)

### What Makes a Security Group "Unused"
A security group is considered "unused" if it's:
1. **Not attached to any ENIs**
2. **Not a default security group**
3. **Has no active network interface associations**

## Safety Considerations

### Before Deleting Security Groups

1. **Verify No Dependencies**
   ```bash
   # Check if security group is referenced by other security groups
   aws ec2 describe-security-groups --filters "Name=ip-permission.group-id,Values=sg-xxxxxxxx"
   ```

2. **Check Launch Templates/Configurations**
   ```bash
   # Check Auto Scaling launch configurations
   aws autoscaling describe-launch-configurations --query 'LaunchConfigurations[?contains(SecurityGroups, `sg-xxxxxxxx`)]'
   
   # Check EC2 launch templates
   aws ec2 describe-launch-templates --query 'LaunchTemplates[*].LaunchTemplateId' --output text | \
   xargs -I {} aws ec2 describe-launch-template-versions --launch-template-id {} --query 'LaunchTemplateVersions[?LaunchTemplateData.SecurityGroupIds && contains(LaunchTemplateData.SecurityGroupIds, `sg-xxxxxxxx`)]'
   ```

3. **Review CloudFormation Stacks**
   ```bash
   # Search CloudFormation templates for security group references
   aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE | \
   jq -r '.StackSummaries[].StackName' | \
   xargs -I {} aws cloudformation get-template --stack-name {} --query 'TemplateBody' | \
   grep -l "sg-xxxxxxxx"
   ```

## Manual Cleanup Process

### Step 1: Verify Findings
```bash
# Double-check security group usage
aws ec2 describe-network-interfaces --filters "Name=group-id,Values=sg-xxxxxxxx"
```

### Step 2: Remove Unused Security Groups
```bash
# Delete individual security group
aws ec2 delete-security-group --group-id sg-xxxxxxxx

# Bulk delete (be very careful!)
for sg in sg-id1 sg-id2 sg-id3; do
    aws ec2 delete-security-group --group-id $sg
    echo "Deleted $sg"
done
```

### Step 3: Handle Dependency Errors
```bash
# If deletion fails due to dependencies, check what's blocking
aws ec2 delete-security-group --group-id sg-xxxxxxxx 2>&1 | \
grep -o "sg-[a-z0-9]*" | sort -u
```

## Configuration Options

### Extending the Script

#### Add Launch Template/Configuration Checks
```python
def check_launch_templates(ec2, sg_ids):
    """Check if security groups are used in launch templates"""
    used_sgs = set()
    try:
        templates = ec2.describe_launch_templates()['LaunchTemplates']
        for template in templates:
            versions = ec2.describe_launch_template_versions(
                LaunchTemplateId=template['LaunchTemplateId']
            )['LaunchTemplateVersions']
            
            for version in versions:
                sg_list = version.get('LaunchTemplateData', {}).get('SecurityGroupIds', [])
                for sg_id in sg_list:
                    if sg_id in sg_ids:
                        used_sgs.add(sg_id)
    except Exception as e:
        print(f"Error checking launch templates: {e}")
    
    return used_sgs
```

#### Add Security Group Rule Dependencies
```python
def check_sg_references(ec2, sg_ids):
    """Check if security groups reference each other"""
    used_sgs = set()
    try:
        all_sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in all_sgs:
            # Check ingress rules
            for rule in sg.get('IpPermissions', []):
                for group in rule.get('UserIdGroupPairs', []):
                    if group.get('GroupId') in sg_ids:
                        used_sgs.add(group.get('GroupId'))
            
            # Check egress rules
            for rule in sg.get('IpPermissionsEgress', []):
                for group in rule.get('UserIdGroupPairs', []):
                    if group.get('GroupId') in sg_ids:
                        used_sgs.add(group.get('GroupId'))
    except Exception as e:
        print(f"Error checking security group references: {e}")
    
    return used_sgs
```

#### Add Automated Deletion
```python
def delete_unused_security_groups(ec2, unused_sg_ids, dry_run=True):
    """Delete unused security groups with safety checks"""
    deleted = []
    errors = []
    
    for sg_id in unused_sg_ids:
        try:
            if not dry_run:
                ec2.delete_security_group(GroupId=sg_id)
                deleted.append(sg_id)
                print(f"Deleted {sg_id}")
            else:
                print(f"Would delete {sg_id}")
        except Exception as e:
            errors.append((sg_id, str(e)))
            print(f"Failed to delete {sg_id}: {e}")
    
    return deleted, errors
```

## Advanced Usage

### Multi-Region Cleanup
```bash
#!/bin/bash
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
for region in "${regions[@]}"; do
    echo "Finding unused security groups in $region"
    python3 find_unused_sgs_cli.py --region "$region"
    echo "---"
done
```

### Generate Cleanup Script
```python
def generate_cleanup_script(unused_sgs):
    """Generate a shell script for manual cleanup"""
    script_content = "#!/bin/bash\n\n"
    script_content += "# Generated security group cleanup script\n"
    script_content += "# Review carefully before execution\n\n"
    
    for sg_id, sg_name in unused_sgs.items():
        script_content += f"# Delete {sg_name}\n"
        script_content += f"aws ec2 delete-security-group --group-id {sg_id}\n\n"
    
    with open('cleanup_security_groups.sh', 'w') as f:
        f.write(script_content)
    
    print("Cleanup script generated: cleanup_security_groups.sh")
```

### Integration with Inventory Management
```python
def export_to_csv(unused_sgs, filename='unused_security_groups.csv'):
    """Export unused security groups to CSV for tracking"""
    import csv
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['SecurityGroupId', 'SecurityGroupName', 'VpcId', 'Description'])
        
        for sg_id, sg_info in unused_sgs.items():
            writer.writerow([
                sg_id,
                sg_info.get('GroupName', ''),
                sg_info.get('VpcId', ''),
                sg_info.get('Description', '')
            ])
```

## Troubleshooting

### Common Issues

1. **Dependency Errors During Deletion**
   ```
   DependencyViolation: resource sg-xxx has a dependent object
   ```
   **Solution**: Check for security group references in rules, launch templates, and CloudFormation stacks.

2. **Permission Denied**
   ```
   UnauthorizedOperation: You are not authorized to perform this operation
   ```
   **Solution**: Ensure your IAM user/role has the required EC2 permissions.

3. **Security Group Not Found**
   ```
   InvalidGroup.NotFound: The security group 'sg-xxx' does not exist
   ```
   **Solution**: Security group may have been deleted by another process.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Monitoring

### Scheduled Cleanup Reports
```bash
# Monthly unused security group report
0 9 1 * * /usr/bin/python3 /path/to/find_unused_sgs.py --region us-east-1 >> /var/log/sg-cleanup.log 2>&1
```

### Integration with Cost Management
```python
def estimate_cost_savings(unused_count):
    """Estimate management overhead savings"""
    # While security groups themselves don't cost money,
    # reducing management overhead has operational value
    management_hours_saved = unused_count * 0.1  # 6 minutes per SG per year
    hourly_rate = 50  # Example DevOps hourly rate
    annual_savings = management_hours_saved * hourly_rate
    
    return {
        'management_hours_saved': management_hours_saved,
        'estimated_annual_savings': annual_savings,
        'unused_security_groups': unused_count
    }
```

### CloudWatch Metrics
```python
def send_cleanup_metrics(unused_count, region):
    """Send cleanup metrics to CloudWatch"""
    import boto3
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    cloudwatch.put_metric_data(
        Namespace='Security/ResourceCleanup',
        MetricData=[{
            'MetricName': 'UnusedSecurityGroups',
            'Value': unused_count,
            'Unit': 'Count',
            'Dimensions': [{'Name': 'Region', 'Value': region}]
        }]
    )
```

## Best Practices

### Security Group Management
1. **Regular Cleanup**: Run monthly scans for unused security groups
2. **Naming Conventions**: Use descriptive names for easy identification
3. **Tagging Strategy**: Tag security groups with purpose and lifecycle information
4. **Documentation**: Maintain inventory of security group purposes
5. **Change Management**: Review security group changes before deletion

### Operational Guidelines
1. **Start Small**: Begin with obviously unused security groups
2. **Verify Dependencies**: Always check for hidden dependencies
3. **Backup Strategy**: Export security group rules before deletion
4. **Team Coordination**: Notify teams before bulk cleanup operations
5. **Monitoring**: Track cleanup activities and any issues

## Related AWS Services

- **AWS Config**: Monitor security group configurations and compliance
- **AWS Systems Manager**: Automate security group cleanup tasks
- **AWS CloudFormation**: Manage security groups as infrastructure as code
- **AWS Resource Groups**: Organize and manage security groups by project or environment

## Security Considerations

- This tool only identifies unused security groups and doesn't delete them
- Always verify findings manually before deletion
- Consider security group rule dependencies that aren't ENI-based
- Maintain audit trails for all security group deletions
- Test in non-production environments first