# Route 53 DNS Inventory Tool

A comprehensive AWS Route 53 DNS management and auditing tool that lists all hosted zones and their DNS records, providing detailed inventory for DNS infrastructure management and compliance.

## Description

This script provides complete inventory of your Route 53 DNS infrastructure by:

- **Complete Zone Listing**: Shows all hosted zones in your AWS account
- **Detailed Record Analysis**: Lists all DNS records within each zone
- **Record Type Classification**: Displays A, AAAA, CNAME, MX, TXT, and other record types
- **TTL Configuration Review**: Shows time-to-live settings for each record
- **DNS Infrastructure Documentation**: Generates comprehensive reports for compliance

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
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
python3 list_route53_zones_and_records_cli.py
```

The script automatically scans all Route 53 hosted zones in your AWS account and displays their DNS records.

## Example Output

### Active DNS Environment
```
🌍 Hosted Zone: example.com. (ID: Z1234567890ABC)
------------------------------------------------------------
A      www.example.com.                         TTL: 300    Values: 203.0.113.10
A      app.example.com.                         TTL: 300    Values: 203.0.113.20
AAAA   www.example.com.                         TTL: 300    Values: 2001:0db8:85a3::8a2e:0370:7334
CNAME  staging.example.com.                     TTL: 600    Values: staging-env.us-east-1.elb.amazonaws.com
MX     example.com.                             TTL: 3600   Values: 10 mail.example.com
TXT    example.com.                             TTL: 300    Values: v=spf1 include:_spf.google.com ~all
TXT    _dmarc.example.com.                      TTL: 300    Values: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
NS     example.com.                             TTL: 172800 Values: ns-123.awsdns-12.com., ns-456.awsdns-45.net.
SOA    example.com.                             TTL: 900    Values: ns-123.awsdns-12.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

🌍 Hosted Zone: internal.company.local. (ID: Z2345678901BCD)
------------------------------------------------------------
A      api.internal.company.local.              TTL: 300    Values: 10.0.1.100
A      db.internal.company.local.               TTL: 300    Values: 10.0.2.50
CNAME  dev-api.internal.company.local.          TTL: 300    Values: api-dev.us-west-2.elb.amazonaws.com
```

### Complex DNS Configuration
```
🌍 Hosted Zone: microservices.io. (ID: Z3456789012CDE)
------------------------------------------------------------
A      auth.microservices.io.                   TTL: 60     Values: 198.51.100.10, 198.51.100.11
A      api.microservices.io.                    TTL: 60     Values: Alias or empty
AAAA   cdn.microservices.io.                    TTL: 300    Values: 2001:0db8:85a3::8a2e:0370:7335
CNAME  www.microservices.io.                    TTL: 300    Values: microservices.io
MX     microservices.io.                        TTL: 3600   Values: 5 alt1.aspmx.l.google.com., 10 alt2.aspmx.l.google.com.
TXT    microservices.io.                        TTL: 300    Values: google-site-verification=abc123def456
TXT    _acme-challenge.microservices.io.        TTL: 60     Values: temporary-validation-token
SRV    _sip._tcp.microservices.io.              TTL: 300    Values: 10 5 5060 sip.microservices.io.
CAA    microservices.io.                        TTL: 3600   Values: 0 issue "letsencrypt.org"
```

### No Hosted Zones
```
No hosted zones found.
```

## Understanding the Output

### Zone Information
- **Zone Name**: The domain name (e.g., example.com.)
- **Zone ID**: AWS-assigned unique identifier for the hosted zone
- **Record Count**: Number of DNS records in the zone

### Record Types Explained
- **A**: Maps domain to IPv4 address
- **AAAA**: Maps domain to IPv6 address
- **CNAME**: Creates an alias to another domain name
- **MX**: Specifies mail exchange servers for email delivery
- **TXT**: Contains text information (SPF, DKIM, DMARC, verification)
- **NS**: Specifies authoritative name servers for the domain
- **SOA**: Start of Authority record with zone metadata
- **SRV**: Service record for service discovery
- **CAA**: Certificate Authority Authorization
- **PTR**: Pointer record for reverse DNS lookups

### TTL Values
- **Low TTL (60-300s)**: Fast updates, higher DNS query load
- **Medium TTL (300-3600s)**: Balanced update speed and performance
- **High TTL (3600s+)**: Slower updates, better performance and caching

### Value Interpretation
- **IP Addresses**: Direct resolution to server addresses
- **Domain Names**: CNAME or alias targets
- **"Alias or empty"**: AWS Route 53 alias records (to ELB, CloudFront, etc.)
- **Multiple Values**: Load balancing or redundancy

## Use Cases

### DNS Management
- **Infrastructure Audit**: Complete DNS record inventory
- **Migration Planning**: Document current DNS configuration
- **Security Review**: Identify potentially problematic records
- **Compliance Documentation**: Generate DNS configuration reports

### Operational Tasks
- **Troubleshooting**: Understand current DNS resolution paths
- **Change Management**: Document baseline DNS configuration
- **Performance Optimization**: Review TTL settings and record efficiency
- **Disaster Recovery**: Backup DNS configuration documentation

## Configuration Analysis

### Security Assessment
```bash
# Find domains with low TTL that might indicate frequent changes
python3 list_route53_zones_and_records_cli.py | grep "TTL: [0-9]\{1,2\} "

# Look for TXT records that might contain security configurations
python3 list_route53_zones_and_records_cli.py | grep "TXT.*v="

# Find wildcard records that might be security risks
python3 list_route53_zones_and_records_cli.py | grep "\*\."
```

### Performance Analysis
```bash
# Find records with very low TTL (potential performance impact)
python3 list_route53_zones_and_records_cli.py | awk '/TTL:/ && $3 < 300 {print "Low TTL:", $1, $2, $3}'

# Find records with very high TTL (potential update delay)
python3 list_route53_zones_and_records_cli.py | awk '/TTL:/ && $3 > 7200 {print "High TTL:", $1, $2, $3}'
```

## Extended Features

### Adding Health Check Information
```python
def get_health_checks(route53_client):
    """Get Route 53 health checks"""
    try:
        response = route53_client.list_health_checks()
        health_checks = {}
        
        for check in response['HealthChecks']:
            check_id = check['Id']
            config = check['HealthCheckConfig']
            health_checks[check_id] = {
                'type': config['Type'],
                'resource_path': config.get('ResourcePath', '/'),
                'fqdn': config.get('FullyQualifiedDomainName', 'N/A'),
                'ip_address': config.get('IPAddress', 'N/A'),
                'port': config.get('Port', 'N/A')
            }
        
        return health_checks
    except Exception as e:
        return {}
```

### DNS Record Validation
```python
def validate_dns_records(zone_name, records):
    """Validate DNS records for common issues"""
    issues = []
    
    for record in records:
        record_name = record['Name']
        record_type = record['Type']
        ttl = record.get('TTL', 0)
        values = [r['Value'] for r in record.get('ResourceRecords', [])]
        
        # Check for very low TTL on critical records
        if record_type in ['A', 'AAAA'] and ttl < 60:
            issues.append(f"Very low TTL ({ttl}s) on {record_type} record: {record_name}")
        
        # Check for missing MX records on root domain
        if record_name == zone_name and record_type == 'A':
            mx_exists = any(r['Type'] == 'MX' and r['Name'] == zone_name for r in records)
            if not mx_exists:
                issues.append(f"Root domain has A record but no MX record: {zone_name}")
        
        # Check for CNAME conflicts
        if record_type == 'CNAME':
            conflicting_types = ['A', 'AAAA', 'MX', 'TXT']
            for other_record in records:
                if (other_record['Name'] == record_name and 
                    other_record['Type'] in conflicting_types):
                    issues.append(f"CNAME conflict with {other_record['Type']} record: {record_name}")
        
        # Check for proper SPF record format
        if record_type == 'TXT' and any('v=spf1' in v for v in values):
            for value in values:
                if 'v=spf1' in value and not any(value.endswith(ending) for ending in ['~all', '-all', '?all']):
                    issues.append(f"SPF record missing proper ending: {record_name}")
    
    return issues
```

### Cost Analysis
```python
def calculate_route53_costs(zones_count, queries_per_month):
    """Calculate estimated Route 53 costs"""
    
    # Route 53 pricing (as of 2024, varies by region)
    cost_per_hosted_zone = 0.50  # per month
    cost_per_million_queries = 0.40  # first 1 billion queries
    
    monthly_zone_cost = zones_count * cost_per_hosted_zone
    monthly_query_cost = (queries_per_month / 1_000_000) * cost_per_million_queries
    
    return {
        'zones_cost': monthly_zone_cost,
        'queries_cost': monthly_query_cost,
        'total_monthly_cost': monthly_zone_cost + monthly_query_cost,
        'annual_cost': (monthly_zone_cost + monthly_query_cost) * 12
    }
```

### Output Formatting Options

#### JSON Export
```python
import json

def export_to_json(zones_data):
    """Export DNS inventory to JSON format"""
    output = {
        'timestamp': datetime.now().isoformat(),
        'zones': []
    }
    
    for zone in zones_data:
        zone_data = {
            'zone_name': zone['Name'],
            'zone_id': zone['Id'].split('/')[-1],
            'records': []
        }
        
        for record in zone['records']:
            record_data = {
                'name': record['Name'],
                'type': record['Type'],
                'ttl': record.get('TTL', 'N/A'),
                'values': [r['Value'] for r in record.get('ResourceRecords', [])]
            }
            zone_data['records'].append(record_data)
        
        output['zones'].append(zone_data)
    
    return json.dumps(output, indent=2)
```

#### CSV Export
```python
import csv

def export_to_csv(zones_data, filename='route53_inventory.csv'):
    """Export DNS inventory to CSV format"""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ZoneName', 'ZoneID', 'RecordName', 'RecordType', 'TTL', 'Values'])
        
        for zone in zones_data:
            zone_name = zone['Name']
            zone_id = zone['Id'].split('/')[-1]
            
            for record in zone['records']:
                values = ', '.join([r['Value'] for r in record.get('ResourceRecords', [])])
                writer.writerow([
                    zone_name,
                    zone_id,
                    record['Name'],
                    record['Type'],
                    record.get('TTL', 'N/A'),
                    values
                ])
```

#### BIND Zone File Format
```python
def export_to_bind_format(zone_name, records):
    """Export zone to BIND zone file format"""
    bind_content = f"; Zone file for {zone_name}\n"
    bind_content += f"; Generated on {datetime.now().isoformat()}\n\n"
    
    # Find SOA record first
    soa_record = next((r for r in records if r['Type'] == 'SOA'), None)
    if soa_record:
        soa_values = soa_record['ResourceRecords'][0]['Value'].split()
        bind_content += f"$ORIGIN {zone_name}\n"
        bind_content += f"$TTL {soa_record.get('TTL', 3600)}\n\n"
        bind_content += f"@\t\tIN\tSOA\t{soa_values[0]} {soa_values[1]} (\n"
        bind_content += f"\t\t\t\t{soa_values[2]}\t; serial\n"
        bind_content += f"\t\t\t\t{soa_values[3]}\t; refresh\n"
        bind_content += f"\t\t\t\t{soa_values[4]}\t; retry\n"
        bind_content += f"\t\t\t\t{soa_values[5]}\t; expire\n"
        bind_content += f"\t\t\t\t{soa_values[6]}\t; minimum\n"
        bind_content += "\t\t\t\t)\n\n"
    
    # Add other records
    for record in records:
        if record['Type'] == 'SOA':
            continue
        
        name = record['Name'].replace(zone_name, '@') if record['Name'] == zone_name else record['Name']
        ttl = record.get('TTL', '')
        record_type = record['Type']
        
        for resource_record in record.get('ResourceRecords', []):
            value = resource_record['Value']
            bind_content += f"{name}\t{ttl}\tIN\t{record_type}\t{value}\n"
    
    return bind_content
```

## Advanced Usage

### DNS Propagation Checker
```python
def check_dns_propagation(domain, record_type='A', nameservers=None):
    """Check DNS propagation across different nameservers"""
    import dns.resolver
    
    if nameservers is None:
        nameservers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']  # Google, Cloudflare, OpenDNS
    
    results = {}
    for ns in nameservers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            answers = resolver.resolve(domain, record_type)
            results[ns] = [str(answer) for answer in answers]
        except Exception as e:
            results[ns] = f"Error: {str(e)}"
    
    return results
```

### DNS Security Analysis
```python
def analyze_dns_security(zones_data):
    """Analyze DNS configuration for security issues"""
    security_report = {
        'spf_records': [],
        'dmarc_records': [],
        'dkim_records': [],
        'caa_records': [],
        'security_issues': []
    }
    
    for zone in zones_data:
        zone_name = zone['Name']
        
        for record in zone['records']:
            record_name = record['Name']
            record_type = record['Type']
            
            if record_type == 'TXT':
                values = [r['Value'] for r in record.get('ResourceRecords', [])]
                for value in values:
                    if 'v=spf1' in value:
                        security_report['spf_records'].append({
                            'zone': zone_name,
                            'record': record_name,
                            'value': value
                        })
                    elif 'v=DMARC1' in value:
                        security_report['dmarc_records'].append({
                            'zone': zone_name,
                            'record': record_name,
                            'value': value
                        })
                    elif 'k=rsa' in value or 'v=DKIM1' in value:
                        security_report['dkim_records'].append({
                            'zone': zone_name,
                            'record': record_name,
                            'value': value
                        })
            
            elif record_type == 'CAA':
                security_report['caa_records'].append({
                    'zone': zone_name,
                    'record': record_name,
                    'values': [r['Value'] for r in record.get('ResourceRecords', [])]
                })
        
        # Check for missing security records
        has_spf = any('v=spf1' in str(r) for r in zone['records'] if r['Type'] == 'TXT')
        has_dmarc = any('_dmarc' in r['Name'] for r in zone['records'] if r['Type'] == 'TXT')
        
        if not has_spf:
            security_report['security_issues'].append(f"Missing SPF record: {zone_name}")
        if not has_dmarc:
            security_report['security_issues'].append(f"Missing DMARC record: {zone_name}")
    
    return security_report
```

### Automated Backup
```bash
#!/bin/bash
# Automated DNS backup script
backup_date=$(date +%Y%m%d_%H%M%S)
backup_dir="/backup/dns/$backup_date"
mkdir -p "$backup_dir"

# Export DNS configuration
python3 list_route53_zones_and_records_cli.py > "$backup_dir/dns_inventory.txt"

# Compress backup
tar -czf "/backup/dns/dns_backup_$backup_date.tar.gz" -C "/backup/dns" "$backup_date"
rm -rf "$backup_dir"

echo "DNS backup completed: dns_backup_$backup_date.tar.gz"
```

## Troubleshooting

### Common Issues

1. **No Hosted Zones Found**
   ```
   No hosted zones found.
   ```
   **Solution**: Verify you have Route 53 hosted zones configured and proper permissions.

2. **Permission Denied**
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDenied)
   ```
   **Solution**: Ensure your AWS credentials have Route 53 read permissions.

3. **Rate Limiting**
   ```
   Throttling: Rate exceeded
   ```
   **Solution**: The script handles basic rate limiting, but large numbers of zones may need additional delays.

### Debug Mode
Add verbose logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Automation and Integration

### Scheduled DNS Audits
```bash
# Weekly DNS inventory and backup
0 2 * * 0 /usr/bin/python3 /path/to/list_route53_zones_and_records_cli.py > /var/backup/dns_inventory_$(date +\%Y\%m\%d).txt
```

### Integration with Monitoring
```python
def send_dns_metrics(zones_count, total_records):
    """Send DNS metrics to CloudWatch"""
    import boto3
    cloudwatch = boto3.client('cloudwatch')
    
    cloudwatch.put_metric_data(
        Namespace='DNS/Route53',
        MetricData=[
            {
                'MetricName': 'HostedZonesCount',
                'Value': zones_count,
                'Unit': 'Count'
            },
            {
                'MetricName': 'TotalDNSRecords',
                'Value': total_records,
                'Unit': 'Count'
            }
        ]
    )
```

### Change Detection
```bash
#!/bin/bash
# DNS change detection
current_dns=$(python3 list_route53_zones_and_records_cli.py)
if [ -f /tmp/previous_dns_config.txt ]; then
    if ! diff -q <(echo "$current_dns") /tmp/previous_dns_config.txt > /dev/null; then
        echo "DNS configuration changed!"
        echo "$current_dns" | mail -s "DNS Configuration Change" dns-admin@company.com
    fi
fi
echo "$current_dns" > /tmp/previous_dns_config.txt
```

## Best Practices

### DNS Management
1. **Regular Backups**: Export DNS configuration regularly
2. **Change Control**: Document all DNS changes
3. **Security Configuration**: Implement SPF, DMARC, and CAA records
4. **TTL Optimization**: Balance update speed with performance
5. **Monitoring**: Track DNS resolution and health

### Operational Guidelines
1. **Documentation**: Maintain DNS architecture documentation
2. **Access Control**: Limit DNS modification permissions
3. **Testing**: Test DNS changes in staging environments
4. **Rollback Planning**: Have procedures for DNS rollbacks
5. **Performance Monitoring**: Monitor DNS query performance

## Related AWS Services

- **Amazon Route 53**: DNS web service and domain registration
- **AWS CloudFront**: CDN that integrates with Route 53
- **AWS Certificate Manager**: SSL/TLS certificate management
- **AWS Application Load Balancer**: Integrates with Route 53 for load balancing
- **AWS Global Accelerator**: Improves application performance with Route 53

## Security Considerations

- This tool only reads DNS configuration and doesn't modify records
- DNS configuration may contain sensitive infrastructure information
- Consider access controls for DNS inventory reports
- Regular DNS auditing helps identify security misconfigurations
- Monitor for unauthorized DNS changes or suspicious records