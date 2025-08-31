# RDS Instances Inventory Tool

A comprehensive AWS RDS inventory and configuration management tool that lists all RDS database instances with their detailed configurations including engine type, instance class, storage, and backup settings.

## Description

This script provides detailed inventory of your RDS database infrastructure by:

- **Complete Database Inventory**: Lists all RDS instances in the specified region
- **Configuration Details**: Shows engine, instance class, storage, and backup settings
- **Multi-AZ Information**: Displays high availability configuration status
- **Backup Configuration**: Shows backup retention period settings
- **Infrastructure Documentation**: Generates reports for compliance and planning

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
python3 list_rds_instances_cli.py --region us-east-1
```

### Required Parameters
- `--region`: AWS region to scan (required)

### Examples
```bash
# List RDS instances in US East 1
python3 list_rds_instances_cli.py --region us-east-1

# List RDS instances in EU West 1
python3 list_rds_instances_cli.py --region eu-west-1

# List RDS instances in Asia Pacific Tokyo
python3 list_rds_instances_cli.py --region ap-northeast-1
```

## Example Output

### Production RDS Environment
```
DB Identifier             Engine     Class           Storage(GB) Backups    Multi-AZ
------------------------------------------------------------------------------------------
prod-webapp-mysql        mysql      db.r5.xlarge    500         7          Yes
prod-analytics-postgres  postgres   db.r5.2xlarge   1000        14         Yes
staging-app-mysql        mysql      db.t3.large     200         3          No
dev-testing-postgres     postgres   db.t3.medium    100         1          No
legacy-oracle-db         oracle-ee  db.m5.large     300         30         Yes
microservice-mariadb     mariadb    db.t3.small     50          7          No
```

### Mixed Database Environment
```
DB Identifier             Engine     Class           Storage(GB) Backups    Multi-AZ
------------------------------------------------------------------------------------------
customer-data-mysql      mysql      db.r6g.large    250         7          Yes
analytics-warehouse      postgres   db.r5.4xlarge   2000        14         Yes
cache-redis-cluster      redis      cache.r6g.large N/A         N/A        Yes
document-store-mongo     docdb      db.t3.medium    100         5          No
search-elasticsearch     es         t3.small.elasticsearch 20  N/A        No
```

### No RDS Instances
```
DB Identifier             Engine     Class           Storage(GB) Backups    Multi-AZ
------------------------------------------------------------------------------------------
```

## Understanding the Output

### Column Descriptions
- **DB Identifier**: Unique identifier for the RDS instance
- **Engine**: Database engine type and version
- **Class**: Instance type and size (affects performance and cost)
- **Storage(GB)**: Allocated storage in gigabytes
- **Backups**: Backup retention period in days (0 = disabled)
- **Multi-AZ**: High availability configuration (Yes/No)

### Database Engines
- **MySQL**: mysql (MySQL Community Edition)
- **PostgreSQL**: postgres (PostgreSQL)
- **Oracle**: oracle-ee, oracle-se2, oracle-se1 (Oracle Database)
- **SQL Server**: sqlserver-ee, sqlserver-se, sqlserver-ex, sqlserver-web
- **MariaDB**: mariadb (MySQL-compatible)
- **Amazon Aurora**: aurora-mysql, aurora-postgresql

### Instance Classes
- **Burstable**: db.t3.micro, db.t3.small, db.t3.medium, db.t3.large, db.t3.xlarge
- **General Purpose**: db.m5.large, db.m5.xlarge, db.m5.2xlarge, db.m5.4xlarge
- **Memory Optimized**: db.r5.large, db.r5.xlarge, db.r5.2xlarge, db.r5.4xlarge
- **Compute Optimized**: db.c5.large, db.c5.xlarge, db.c5.2xlarge

## Use Cases

### Infrastructure Management
- **Cost Analysis**: Understand instance types and storage costs
- **Capacity Planning**: Track database resource allocation
- **Compliance Auditing**: Document database configurations
- **Migration Planning**: Inventory for upgrade or migration projects

### Operational Tasks
- **Backup Monitoring**: Verify backup retention policies
- **High Availability Review**: Check Multi-AZ configurations
- **Performance Planning**: Analyze instance class distribution
- **Security Assessment**: Review database deployment patterns

## Configuration Analysis

### Backup Policy Review
```bash
# Find databases with inadequate backup retention
python3 list_rds_instances_cli.py --region us-east-1 | awk '$5 < 7 && $5 != "Backups" {print "Low backup retention:", $1, "(" $5 "days)"}'

# Find databases with no backups
python3 list_rds_instances_cli.py --region us-east-1 | awk '$5 == 0 {print "No backups:", $1}'
```

### High Availability Analysis
```bash
# Find production databases without Multi-AZ
python3 list_rds_instances_cli.py --region us-east-1 | grep -E "prod|production" | awk '$6 == "No" {print "No Multi-AZ:", $1}'
```

### Cost Optimization Opportunities
```bash
# Find oversized development instances
python3 list_rds_instances_cli.py --region us-east-1 | grep -E "dev|test|staging" | awk '$3 ~ /xlarge|2xlarge/ {print "Potentially oversized:", $1, $3}'
```

## Extended Features

### Adding Detailed Configuration
```python
def get_detailed_db_info(rds_client, db_identifier):
    """Get detailed information about an RDS instance"""
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)
        db = response['DBInstances'][0]
        
        return {
            'endpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
            'port': db.get('Endpoint', {}).get('Port', 'N/A'),
            'publicly_accessible': db.get('PubliclyAccessible', False),
            'storage_type': db.get('StorageType', 'N/A'),
            'iops': db.get('Iops', 'N/A'),
            'encrypted': db.get('StorageEncrypted', False),
            'kms_key_id': db.get('KmsKeyId', 'N/A'),
            'auto_minor_version_upgrade': db.get('AutoMinorVersionUpgrade', False),
            'maintenance_window': db.get('PreferredMaintenanceWindow', 'N/A'),
            'backup_window': db.get('PreferredBackupWindow', 'N/A'),
            'parameter_group': db.get('DBParameterGroups', [{}])[0].get('DBParameterGroupName', 'N/A'),
            'security_groups': [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])],
            'subnet_group': db.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A')
        }
    except Exception as e:
        return None

# Usage in main function
details = get_detailed_db_info(rds, identifier)
if details:
    print(f"  Endpoint: {details['endpoint']}:{details['port']}")
    print(f"  Public: {details['publicly_accessible']}")
    print(f"  Encrypted: {details['encrypted']}")
```

### Cost Calculation Integration
```python
def estimate_monthly_cost(instance_class, storage_gb, backup_retention, multi_az):
    """Estimate monthly cost for RDS instance (approximate)"""
    
    # Sample pricing (varies by region and changes over time)
    instance_costs = {
        'db.t3.micro': 0.017,
        'db.t3.small': 0.034,
        'db.t3.medium': 0.068,
        'db.t3.large': 0.136,
        'db.m5.large': 0.192,
        'db.m5.xlarge': 0.384,
        'db.r5.large': 0.240,
        'db.r5.xlarge': 0.480
    }
    
    # Hourly instance cost
    hourly_cost = instance_costs.get(instance_class, 0.100)  # Default estimate
    monthly_instance_cost = hourly_cost * 24 * 30
    
    # Multi-AZ doubles the instance cost
    if multi_az:
        monthly_instance_cost *= 2
    
    # Storage cost (approximate $0.115 per GB per month for gp2)
    monthly_storage_cost = storage_gb * 0.115
    
    # Backup storage cost (first 100% of db storage is free)
    backup_storage_gb = storage_gb * (backup_retention / 7)  # Rough estimate
    monthly_backup_cost = max(0, backup_storage_gb - storage_gb) * 0.095
    
    return {
        'instance_cost': monthly_instance_cost,
        'storage_cost': monthly_storage_cost,
        'backup_cost': monthly_backup_cost,
        'total_cost': monthly_instance_cost + monthly_storage_cost + monthly_backup_cost
    }
```

### Security Assessment
```python
def assess_security_configuration(rds_client, db_identifier):
    """Assess security configuration of RDS instance"""
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)
        db = response['DBInstances'][0]
        
        security_issues = []
        
        # Check for public accessibility
        if db.get('PubliclyAccessible', False):
            security_issues.append('Publicly accessible')
        
        # Check for encryption
        if not db.get('StorageEncrypted', False):
            security_issues.append('Storage not encrypted')
        
        # Check backup retention
        if db.get('BackupRetentionPeriod', 0) < 7:
            security_issues.append('Inadequate backup retention')
        
        # Check for automated backups
        if db.get('BackupRetentionPeriod', 0) == 0:
            security_issues.append('Automated backups disabled')
        
        # Check for Multi-AZ in production environments
        if 'prod' in db_identifier.lower() and not db.get('MultiAZ', False):
            security_issues.append('Production database without Multi-AZ')
        
        return security_issues
    except Exception as e:
        return [f"Error assessing security: {str(e)}"]
```

### Output Formatting Options

#### JSON Export
```python
import json

def export_to_json(instances_data):
    """Export RDS inventory to JSON format"""
    output = {
        'timestamp': datetime.now().isoformat(),
        'region': 'us-east-1',  # Make this dynamic
        'instances': []
    }
    
    for instance in instances_data:
        output['instances'].append({
            'identifier': instance['DBInstanceIdentifier'],
            'engine': instance['Engine'],
            'instance_class': instance['DBInstanceClass'],
            'allocated_storage': instance['AllocatedStorage'],
            'backup_retention': instance['BackupRetentionPeriod'],
            'multi_az': instance['MultiAZ'],
            'status': instance['DBInstanceStatus']
        })
    
    return json.dumps(output, indent=2, default=str)
```

#### CSV Export
```python
import csv

def export_to_csv(instances_data, filename='rds_inventory.csv'):
    """Export RDS inventory to CSV format"""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'DBIdentifier', 'Engine', 'InstanceClass', 'StorageGB',
            'BackupRetention', 'MultiAZ', 'Status', 'Endpoint',
            'PubliclyAccessible', 'Encrypted'
        ])
        
        for instance in instances_data:
            writer.writerow([
                instance['DBInstanceIdentifier'],
                instance['Engine'],
                instance['DBInstanceClass'],
                instance['AllocatedStorage'],
                instance['BackupRetentionPeriod'],
                'Yes' if instance['MultiAZ'] else 'No',
                instance['DBInstanceStatus'],
                instance.get('Endpoint', {}).get('Address', 'N/A'),
                instance.get('PubliclyAccessible', False),
                instance.get('StorageEncrypted', False)
            ])
```

## Advanced Usage

### Multi-Region Inventory
```bash
#!/bin/bash
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
echo "RDS Instances Global Inventory - $(date)" > rds_global_inventory.txt
echo "=============================================" >> rds_global_inventory.txt

for region in "${regions[@]}"; do
    echo "" >> rds_global_inventory.txt
    echo "Region: $region" >> rds_global_inventory.txt
    echo "----------------------------" >> rds_global_inventory.txt
    python3 list_rds_instances_cli.py --region "$region" >> rds_global_inventory.txt
done
```

### Compliance Reporting
```python
def generate_compliance_report(instances):
    """Generate compliance report for RDS instances"""
    report = {
        'total_instances': len(instances),
        'encrypted_instances': 0,
        'multi_az_instances': 0,
        'adequate_backups': 0,
        'public_instances': 0,
        'compliance_issues': []
    }
    
    for instance in instances:
        if instance.get('StorageEncrypted', False):
            report['encrypted_instances'] += 1
        
        if instance.get('MultiAZ', False):
            report['multi_az_instances'] += 1
        
        if instance.get('BackupRetentionPeriod', 0) >= 7:
            report['adequate_backups'] += 1
        
        if instance.get('PubliclyAccessible', False):
            report['public_instances'] += 1
            report['compliance_issues'].append(
                f"Public access: {instance['DBInstanceIdentifier']}"
            )
        
        if not instance.get('StorageEncrypted', False):
            report['compliance_issues'].append(
                f"Not encrypted: {instance['DBInstanceIdentifier']}"
            )
    
    # Calculate compliance percentages
    total = report['total_instances']
    if total > 0:
        report['encryption_compliance'] = (report['encrypted_instances'] / total) * 100
        report['ha_compliance'] = (report['multi_az_instances'] / total) * 100
        report['backup_compliance'] = (report['adequate_backups'] / total) * 100
    
    return report
```

### Integration with Monitoring
```python
def get_rds_metrics(cloudwatch, db_identifier):
    """Get CloudWatch metrics for RDS instance"""
    from datetime import datetime, timedelta
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    try:
        # Get CPU utilization
        cpu_metrics = cloudwatch.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_identifier}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Average', 'Maximum']
        )
        
        # Get database connections
        connection_metrics = cloudwatch.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='DatabaseConnections',
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_identifier}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Average', 'Maximum']
        )
        
        return {
            'avg_cpu': sum(point['Average'] for point in cpu_metrics['Datapoints']) / len(cpu_metrics['Datapoints']) if cpu_metrics['Datapoints'] else 0,
            'max_cpu': max((point['Maximum'] for point in cpu_metrics['Datapoints']), default=0),
            'avg_connections': sum(point['Average'] for point in connection_metrics['Datapoints']) / len(connection_metrics['Datapoints']) if connection_metrics['Datapoints'] else 0
        }
    except Exception as e:
        return {'error': str(e)}
```

## Troubleshooting

### Common Issues

1. **No RDS Instances Found**
   ```
   (Empty table output)
   ```
   **Solution**: Verify you're scanning the correct region and have RDS instances deployed.

2. **Permission Denied**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Ensure your AWS credentials have RDS:DescribeDBInstances permission.

3. **Region Not Available**
   ```
   Could not connect to the endpoint URL
   ```
   **Solution**: Verify the region name is correct and RDS is available in that region.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Integration

### Scheduled Inventory Updates
```bash
# Weekly RDS inventory update
0 9 * * 1 /usr/bin/python3 /path/to/list_rds_instances.py --region us-east-1 > /var/inventory/rds_inventory_$(date +\%Y\%m\%d).txt
```

### Integration with Asset Management
```python
def sync_with_asset_db(instances_data):
    """Sync RDS inventory with asset management database"""
    import requests
    
    for instance in instances_data:
        asset_record = {
            'name': instance['DBInstanceIdentifier'],
            'type': 'RDS Database',
            'engine': instance['Engine'],
            'environment': detect_environment(instance['DBInstanceIdentifier']),
            'owner': detect_owner(instance['DBInstanceIdentifier']),
            'status': instance['DBInstanceStatus']
        }
        
        response = requests.post(
            'https://assets.company.com/api/databases',
            json=asset_record,
            headers={'Authorization': 'Bearer TOKEN'}
        )
```

### Cost Monitoring Integration
```python
def send_cost_metrics(instances_data, region):
    """Send RDS cost metrics to CloudWatch"""
    import boto3
    cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    total_estimated_cost = 0
    for instance in instances_data:
        cost_estimate = estimate_monthly_cost(
            instance['DBInstanceClass'],
            instance['AllocatedStorage'],
            instance['BackupRetentionPeriod'],
            instance['MultiAZ']
        )
        total_estimated_cost += cost_estimate['total_cost']
    
    cloudwatch.put_metric_data(
        Namespace='Cost/RDS',
        MetricData=[{
            'MetricName': 'EstimatedMonthlyCost',
            'Value': total_estimated_cost,
            'Unit': 'None',
            'Dimensions': [{'Name': 'Region', 'Value': region}]
        }]
    )
```

## Best Practices

### Database Management
1. **Regular Inventory**: Run weekly or monthly inventory reports
2. **Cost Optimization**: Regular review of instance types and storage
3. **Security Configuration**: Monitor encryption and access settings
4. **Backup Strategy**: Ensure adequate backup retention policies
5. **High Availability**: Use Multi-AZ for production databases

### Operational Guidelines
1. **Standardized Naming**: Use consistent naming conventions for databases
2. **Tagging Strategy**: Tag databases with environment, purpose, and owner
3. **Change Management**: Document all database configuration changes
4. **Monitoring Setup**: Configure CloudWatch alarms for all databases
5. **Disaster Recovery**: Plan and test backup restoration procedures

## Related AWS Services

- **Amazon RDS**: Managed relational database service
- **Amazon Aurora**: MySQL and PostgreSQL-compatible relational database
- **Amazon DynamoDB**: NoSQL database service
- **AWS Database Migration Service**: Database migration tool
- **Amazon ElastiCache**: In-memory caching service
- **AWS CloudWatch**: Monitoring and observability

## Security Considerations

- This tool only reads RDS metadata and configuration
- Results may contain sensitive database identifiers and configurations
- Consider access controls for inventory reports containing infrastructure details
- Regular inventory helps identify misconfigured or unauthorized databases
- Monitor for databases with public access or inadequate encryption