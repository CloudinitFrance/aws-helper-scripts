# ELB and ALB Inventory Tool

A comprehensive load balancer inventory and documentation tool that lists all Classic ELBs and Application/Network Load Balancers (ALB/NLB) with their detailed configurations including listeners, target groups, and routing rules.

## Description

This script provides detailed inventory of your load balancer infrastructure by:

- **Multi-Load Balancer Support**: Lists both Classic ELBs and modern ALB/NLB
- **Comprehensive Configuration Details**: Shows listeners, protocols, ports, and target groups
- **Target Group Analysis**: Displays target group configurations and protocols
- **Infrastructure Documentation**: Generates detailed reports for compliance and planning
- **Organized Output**: Clear, structured display of load balancer hierarchies

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
# List load balancers with default AWS credentials
python3 list_elbs_and_albs_cli.py --region us-east-1

# Use specific AWS profile
python3 list_elbs_and_albs_cli.py --profile production --region us-east-1

# Scan all regions with default profile
python3 list_elbs_and_albs_cli.py --all-regions

# Scan all regions with specific profile
python3 list_elbs_and_albs_cli.py --profile production --all-regions
```

### Command Line Options
- `--region`: AWS region to scan (overridden by --all-regions)
- `--all-regions`: Scan all AWS regions
- `--profile`: AWS profile to use for credentials (optional)

### Examples
```bash
# List load balancers in US East 1 with default profile
python3 list_elbs_and_albs_cli.py --region us-east-1

# List load balancers in EU West 1 with production profile
python3 list_elbs_and_albs_cli.py --profile production --region eu-west-1

# List load balancers in Asia Pacific Tokyo with staging profile
python3 list_elbs_and_albs_cli.py --profile staging --region ap-northeast-1

# List load balancers in multiple environments (single region)
python3 list_elbs_and_albs_cli.py --profile development --region us-west-2
python3 list_elbs_and_albs_cli.py --profile staging --region us-west-2
python3 list_elbs_and_albs_cli.py --profile production --region us-west-2

# Multi-region inventory examples
python3 list_elbs_and_albs_cli.py --all-regions
python3 list_elbs_and_albs_cli.py --profile production --all-regions
python3 list_elbs_and_albs_cli.py --profile staging --all-regions
python3 list_elbs_and_albs_cli.py --profile development --all-regions

# Specific region examples for different environments
python3 list_elbs_and_albs_cli.py --profile development --region us-east-1
python3 list_elbs_and_albs_cli.py --profile staging --region eu-west-1
python3 list_elbs_and_albs_cli.py --profile production --region ap-southeast-1
```

## Example Output

### Classic ELB Configuration
```
=== Classic ELBs ===

Load Balancer Name: web-app-classic-elb
Scheme: internet-facing
Listeners:
 - HTTP 80 -> instance 80
 - HTTPS 443 -> instance 443

Load Balancer Name: internal-api-elb
Scheme: internal
Listeners:
 - HTTP 8080 -> instance 8080
 - TCP 3306 -> instance 3306
```

### Application Load Balancer Configuration
```
=== Application/Network Load Balancers ===

Load Balancer Name: production-web-alb (Type: application, Scheme: internet-facing)
Listeners:
 - HTTP port 80
   Target Group: web-servers-tg, Protocol: HTTP, Port: 80
 - HTTPS port 443
   Target Group: web-servers-tg, Protocol: HTTP, Port: 80

Load Balancer Name: microservices-alb (Type: application, Scheme: internal)
Listeners:
 - HTTPS port 443
   Target Group: api-service-tg, Protocol: HTTP, Port: 8080
   Target Group: auth-service-tg, Protocol: HTTP, Port: 9000

Load Balancer Name: database-nlb (Type: network, Scheme: internal)
Listeners:
 - TCP port 3306
   Target Group: mysql-cluster-tg, Protocol: TCP, Port: 3306
```

### No Load Balancers Found
```
=== Classic ELBs ===
No Classic ELBs found.

=== Application/Network Load Balancers ===
No ALBs/NLBs found.
```

## Understanding the Output

### Load Balancer Information
- **Load Balancer Name**: Unique identifier for the load balancer
- **Type**: Application (ALB), Network (NLB), or Classic (ELB)
- **Scheme**: internet-facing (public) or internal (private)

### Listener Configuration
- **Protocol**: HTTP, HTTPS, TCP, UDP, TLS
- **Port**: Port number the load balancer listens on
- **Target Mapping**: Where traffic is forwarded (Classic ELB only)

### Target Group Details
- **Target Group Name**: Identifier for the target group
- **Protocol**: Protocol used to communicate with targets
- **Port**: Port number on the target instances

## Use Cases

### Infrastructure Documentation
- **Compliance Audits**: Document load balancer configurations
- **Migration Planning**: Inventory existing infrastructure before migration
- **Capacity Planning**: Understand current load balancer usage patterns
- **Security Reviews**: Identify public vs. internal load balancers

### Operational Tasks
- **Troubleshooting**: Understand traffic routing configurations
- **Change Management**: Document current state before modifications
- **Cost Optimization**: Identify underutilized load balancers
- **Monitoring Setup**: Configure monitoring for all load balancers

## Configuration Options

### Extending the Script

#### Add Load Balancer Attributes
```python
def get_load_balancer_attributes(elbv2_client, lb_arn):
    """Get additional load balancer attributes"""
    try:
        attrs = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
        attributes = {attr['Key']: attr['Value'] for attr in attrs['Attributes']}
        return attributes
    except Exception as e:
        return {}

# Usage in main function
attributes = get_load_balancer_attributes(elbv2_client, lb_arn)
if attributes.get('access_logs.s3.enabled') == 'true':
    print(f"   Access Logs: Enabled (Bucket: {attributes.get('access_logs.s3.bucket', 'N/A')})")
```

#### Add Target Health Information
```python
def get_target_health(elbv2_client, target_group_arn):
    """Get health status of targets in target group"""
    try:
        health = elbv2_client.describe_target_health(TargetGroupArn=target_group_arn)
        healthy_count = sum(1 for t in health['TargetHealthDescriptions'] 
                           if t['TargetHealth']['State'] == 'healthy')
        total_count = len(health['TargetHealthDescriptions'])
        return f"{healthy_count}/{total_count} healthy"
    except Exception as e:
        return "Unknown"

# Usage
health_status = get_target_health(elbv2_client, tg_arn)
print(f"   Target Health: {health_status}")
```

#### Add Security Group Information
```python
def get_security_groups(ec2_client, sg_ids):
    """Get security group names for load balancer"""
    try:
        sgs = ec2_client.describe_security_groups(GroupIds=sg_ids)
        return [f"{sg['GroupId']} ({sg['GroupName']})" for sg in sgs['SecurityGroups']]
    except Exception as e:
        return sg_ids

# Usage
if 'SecurityGroups' in lb:
    sg_names = get_security_groups(ec2_client, lb['SecurityGroups'])
    print(f"Security Groups: {', '.join(sg_names)}")
```

### Output Formatting Options

#### JSON Output Format
```python
import json

def format_as_json(elbs, albs):
    """Format output as JSON for programmatic use"""
    output = {
        'classic_elbs': [],
        'application_network_lbs': []
    }
    
    for elb in elbs:
        output['classic_elbs'].append({
            'name': elb['LoadBalancerName'],
            'scheme': elb['Scheme'],
            'listeners': [
                {
                    'protocol': l['Listener']['Protocol'],
                    'port': l['Listener']['LoadBalancerPort'],
                    'instance_port': l['Listener']['InstancePort']
                }
                for l in elb['ListenerDescriptions']
            ]
        })
    
    return json.dumps(output, indent=2)
```

#### CSV Export
```python
import csv

def export_to_csv(load_balancers, filename='load_balancers.csv'):
    """Export load balancer inventory to CSV"""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Name', 'Type', 'Scheme', 'Protocol', 'Port', 'Target'])
        
        for lb in load_balancers:
            # Write load balancer data rows
            pass
```

## Advanced Usage

### Multi-Region Inventory
```bash
#!/bin/bash
# All-regions inventory with default profile
echo "Load Balancer Inventory Report - $(date)" > lb_inventory.txt
echo "===========================================" >> lb_inventory.txt
python3 list_elbs_and_albs_cli.py --all-regions >> lb_inventory.txt

# All-regions inventory with specific profile
echo "Load Balancer Inventory Report (Production) - $(date)" > lb_inventory_prod.txt
echo "=======================================================" >> lb_inventory_prod.txt
python3 list_elbs_and_albs_cli.py --profile production --all-regions >> lb_inventory_prod.txt

# Multi-environment all-regions inventory
for profile in development staging production; do
    echo "Load Balancer Inventory Report ($profile) - $(date)" > "lb_inventory_$profile.txt"
    echo "=======================================================" >> "lb_inventory_$profile.txt"
    python3 list_elbs_and_albs_cli.py --profile "$profile" --all-regions >> "lb_inventory_$profile.txt"
done

# Traditional region-specific inventory (if you only want specific regions)
regions=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")
echo "Load Balancer Inventory Report (Specific Regions) - $(date)" > lb_inventory_regions.txt
echo "==========================================================" >> lb_inventory_regions.txt

for region in "${regions[@]}"; do
    echo "" >> lb_inventory_regions.txt
    echo "Region: $region" >> lb_inventory_regions.txt
    echo "-------------------" >> lb_inventory_regions.txt
    python3 list_elbs_and_albs_cli.py --region "$region" >> lb_inventory_regions.txt
done
```

### Integration with CMDB
```python
def sync_with_cmdb(load_balancers):
    """Sync load balancer inventory with Configuration Management Database"""
    import requests
    
    for lb in load_balancers:
        cmdb_record = {
            'name': lb['name'],
            'type': 'Load Balancer',
            'environment': detect_environment(lb['name']),
            'status': 'Active',
            'configuration': lb
        }
        
        # POST to CMDB API
        response = requests.post(
            'https://cmdb.company.com/api/assets',
            json=cmdb_record,
            headers={'Authorization': 'Bearer TOKEN'}
        )
```

### Automated Documentation Generation
```python
def generate_markdown_report(elbs, albs, region):
    """Generate markdown documentation"""
    report = f"# Load Balancer Inventory - {region}\n\n"
    report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    if elbs:
        report += "## Classic Load Balancers\n\n"
        for elb in elbs:
            report += f"### {elb['LoadBalancerName']}\n"
            report += f"- **Scheme**: {elb['Scheme']}\n"
            report += f"- **Listeners**:\n"
            for listener in elb['ListenerDescriptions']:
                protocol = listener['Listener']['Protocol']
                port = listener['Listener']['LoadBalancerPort']
                instance_port = listener['Listener']['InstancePort']
                report += f"  - {protocol} {port} → instance {instance_port}\n"
            report += "\n"
    
    return report
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
   IndexError: list index out of range
   ```
   **Solution**: The script may encounter target groups with no rules. This is handled in the current version.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Integration

### Scheduled Inventory Updates
```bash
# Daily all-regions load balancer inventory with default profile
0 9 * * * /usr/bin/python3 /path/to/list_elbs_and_albs.py --all-regions > /var/inventory/lb_inventory_$(date +\%Y\%m\%d).txt

# Daily all-regions inventory for different environments
0 8 * * * /usr/bin/python3 /path/to/list_elbs_and_albs.py --profile production --all-regions > /var/inventory/lb_inventory_prod_$(date +\%Y\%m\%d).txt
0 9 * * * /usr/bin/python3 /path/to/list_elbs_and_albs.py --profile staging --all-regions > /var/inventory/lb_inventory_staging_$(date +\%Y\%m\%d).txt
0 10 * * * /usr/bin/python3 /path/to/list_elbs_and_albs.py --profile development --all-regions > /var/inventory/lb_inventory_dev_$(date +\%Y\%m\%d).txt

# Traditional region-specific inventory (if you only need specific regions)
0 11 * * 1 /usr/bin/python3 /path/to/list_elbs_and_albs.py --profile production --region us-east-1 > /var/inventory/lb_inventory_us_east_$(date +\%Y\%m\%d).txt
```

### Integration with Monitoring Systems
```python
def send_inventory_metrics(elb_count, alb_count, region, profile=None):
    """Send inventory metrics to monitoring system"""
    import boto3
    
    if profile:
        session = boto3.Session(profile_name=profile)
        cloudwatch = session.client('cloudwatch', region_name=region)
    else:
        cloudwatch = boto3.client('cloudwatch', region_name=region)
    
    cloudwatch.put_metric_data(
        Namespace='Infrastructure/Inventory',
        MetricData=[
            {
                'MetricName': 'ClassicELBCount',
                'Value': elb_count,
                'Unit': 'Count',
                'Dimensions': [{'Name': 'Region', 'Value': region}]
            },
            {
                'MetricName': 'ALBNLBCount',
                'Value': alb_count,
                'Unit': 'Count',
                'Dimensions': [{'Name': 'Region', 'Value': region}]
            }
        ]
    )
```

### Change Detection
```bash
#!/bin/bash
# Detect changes in load balancer inventory (all regions)
current_inventory=$(python3 list_elbs_and_albs_cli.py --all-regions)
if [ -f /tmp/previous_lb_inventory.txt ]; then
    if ! diff -q <(echo "$current_inventory") /tmp/previous_lb_inventory.txt > /dev/null; then
        echo "Load balancer configuration changed across all regions!"
        echo "$current_inventory" | mail -s "LB Inventory Change (All Regions)" ops@company.com
    fi
fi
echo "$current_inventory" > /tmp/previous_lb_inventory.txt

# Multi-environment change detection (all regions)
for profile in production staging development; do
    echo "Checking $profile environment across all regions..."
    current_inventory=$(python3 list_elbs_and_albs_cli.py --profile $profile --all-regions)
    if [ -f /tmp/previous_lb_inventory_$profile.txt ]; then
        if ! diff -q <(echo "$current_inventory") /tmp/previous_lb_inventory_$profile.txt > /dev/null; then
            echo "Load balancer configuration changed in $profile!"
            echo "$current_inventory" | mail -s "LB Inventory Change - $profile (All Regions)" ops@company.com
        fi
    fi
    echo "$current_inventory" > /tmp/previous_lb_inventory_$profile.txt
done

# Region-specific change detection (if you only monitor specific regions)
for region in us-east-1 eu-west-1 ap-southeast-1; do
    echo "Checking region $region..."
    current_inventory=$(python3 list_elbs_and_albs_cli.py --region $region)
    if [ -f /tmp/previous_lb_inventory_$region.txt ]; then
        if ! diff -q <(echo "$current_inventory") /tmp/previous_lb_inventory_$region.txt > /dev/null; then
            echo "Load balancer configuration changed in $region!"
            echo "$current_inventory" | mail -s "LB Inventory Change - $region" ops@company.com
        fi
    fi
    echo "$current_inventory" > /tmp/previous_lb_inventory_$region.txt
done
```

## Best Practices

### Documentation Management
1. **Regular Updates**: Run inventory reports weekly or monthly
2. **Version Control**: Store reports in version control systems
3. **Change Tracking**: Monitor configuration changes over time
4. **Team Access**: Make inventory accessible to relevant teams
5. **Automation**: Integrate with existing documentation workflows

### Operational Guidelines
1. **Standardized Naming**: Use consistent naming conventions for load balancers
2. **Tagging Strategy**: Tag load balancers with environment, purpose, and owner
3. **Lifecycle Management**: Track load balancer lifecycle from creation to retirement
4. **Capacity Planning**: Use inventory data for capacity and scaling decisions

## Related AWS Services

- **AWS Application Load Balancer (ALB)**: Layer 7 load balancing
- **AWS Network Load Balancer (NLB)**: Layer 4 load balancing
- **AWS Classic Load Balancer (ELB)**: Legacy load balancing (being phased out)
- **AWS Auto Scaling**: Integration with load balancers for scaling
- **AWS CloudFormation**: Infrastructure as code for load balancers
- **AWS Config**: Configuration change tracking

## Security Considerations

- This tool only reads load balancer metadata and configuration
- Results may contain sensitive load balancer names and configurations
- Consider access controls for inventory reports containing infrastructure details
- Regular inventory helps identify unauthorized or misconfigured load balancers