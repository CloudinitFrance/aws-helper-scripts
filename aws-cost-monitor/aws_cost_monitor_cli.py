#!/usr/bin/env python3
"""
AWS Cost Monitor - Track and alert on AWS spending
Monitors daily/monthly costs and sends alerts when thresholds are exceeded
"""

import boto3
import json
import argparse
import sys
import os
from datetime import datetime, timedelta
from decimal import Decimal
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import Dict, List


def validate_aws_credentials(session=None):
    """Validate AWS credentials before proceeding."""
    try:
        if session:
            sts = session.client('sts')
        else:
            sts = boto3.client('sts')
        
        response = sts.get_caller_identity()
        print(f"Using AWS Account: {response.get('Account', 'Unknown')}")
        print(f"User/Role: {response.get('Arn', 'Unknown')}")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error: AWS credentials not found or incomplete: {e}")
        print("Please configure your credentials using 'aws configure' or environment variables.")
        return False
    except ClientError as e:
        print(f"Error validating credentials: {e.response['Error']['Message']}")
        return False


def get_cost_and_usage(start_date, end_date, granularity='DAILY', session=None):
    """Retrieve cost and usage data from AWS Cost Explorer"""
    try:
        if session:
            client = session.client('ce', region_name='us-east-1')
        else:
            client = boto3.client('ce', region_name='us-east-1')
        
        response = client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity=granularity,
            Metrics=['UnblendedCost'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'}
            ]
        )
        return response
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("Error: Insufficient permissions to access Cost Explorer. Required permissions:")
            print("- ce:GetCostAndUsage")
            print("- ce:GetUsageReport")
        else:
            print(f"AWS API Error: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        print(f"Error fetching cost data: {e}")
        return None


def format_cost_report(cost_data, show_trends=False):
    """Format cost data into a readable report"""
    if not cost_data:
        return "No cost data available", []
    
    report = []
    report.append("=" * 60)
    report.append("AWS COST REPORT")
    report.append("=" * 60)
    
    total_cost = Decimal('0')
    daily_costs = []
    
    for result in cost_data['ResultsByTime']:
        date = result['TimePeriod']['Start']
        report.append(f"\nDate: {date}")
        report.append("-" * 40)
        
        daily_total = Decimal('0')
        services = []
        
        for group in result['Groups']:
            service = group['Keys'][0]
            cost = Decimal(group['Metrics']['UnblendedCost']['Amount'])
            
            if cost > 0:
                services.append((service, cost))
                daily_total += cost
        
        # Sort services by cost (highest first)
        services.sort(key=lambda x: x[1], reverse=True)
        
        for service, cost in services:
            report.append(f"  {service:<30} ${cost:>10.2f}")
        
        report.append("-" * 40)
        report.append(f"  {'DAILY TOTAL':<30} ${daily_total:>10.2f}")
        total_cost += daily_total
        daily_costs.append((date, daily_total))
    
    report.append("\n" + "=" * 60)
    report.append(f"  {'PERIOD TOTAL':<30} ${total_cost:>10.2f}")
    report.append("=" * 60)
    
    # Add cost trend analysis if requested
    if show_trends and len(daily_costs) >= 2:
        recent_avg = sum(cost for _, cost in daily_costs[-3:]) / min(3, len(daily_costs))
        overall_avg = total_cost / len(daily_costs)
        trend = "increasing" if recent_avg > overall_avg else "stable/decreasing"
        
        report.append("")
        report.append("COST TREND ANALYSIS")
        report.append("=" * 60)
        report.append(f"Recent 3-day average: ${recent_avg:.2f}")
        report.append(f"Period average: ${overall_avg:.2f}")
        report.append(f"Trend: {trend}")
        report.append("=" * 60)
    
    return "\n".join(report), daily_costs


def check_threshold(cost_data, daily_threshold=None, monthly_threshold=None):
    """Check if costs exceed specified thresholds"""
    alerts = []
    
    if not cost_data:
        return alerts
    
    # Check daily threshold
    if daily_threshold:
        for result in cost_data['ResultsByTime']:
            date = result['TimePeriod']['Start']
            daily_total = sum(
                Decimal(group['Metrics']['UnblendedCost']['Amount'])
                for group in result['Groups']
            )
            
            if daily_total > daily_threshold:
                alerts.append(
                    f"ALERT: Daily cost on {date} (${daily_total:.2f}) "
                    f"exceeds threshold (${daily_threshold:.2f})"
                )
    
    # Check monthly threshold
    if monthly_threshold:
        total_cost = sum(
            Decimal(group['Metrics']['UnblendedCost']['Amount'])
            for result in cost_data['ResultsByTime']
            for group in result['Groups']
        )
        
        if total_cost > monthly_threshold:
            alerts.append(
                f"ALERT: Monthly cost (${total_cost:.2f}) "
                f"exceeds threshold (${monthly_threshold:.2f})"
            )
    
    return alerts


def send_finops_notifications(cost_data: Dict, alerts: List[str], account_id: str, period: Dict, thresholds: Dict, sns_topic_arn: str = None, session=None) -> None:
    """Send SNS notifications for cost threshold breaches to FinOps team."""
    try:
        if not sns_topic_arn:
            print("Warning: No SNS topic ARN provided, skipping FinOps notifications")
            return
        
        if not alerts:
            print("No cost threshold breaches to notify")
            return
        
        if session:
            sns_client = session.client('sns')
        else:
            sns_client = boto3.client('sns')
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Calculate cost metrics
        total_cost = Decimal('0')
        daily_costs = []
        service_costs = {}
        
        for result in cost_data['ResultsByTime']:
            date = result['TimePeriod']['Start']
            daily_total = Decimal('0')
            
            for group in result['Groups']:
                service = group['Keys'][0]
                cost = Decimal(group['Metrics']['UnblendedCost']['Amount'])
                daily_total += cost
                
                if service in service_costs:
                    service_costs[service] += cost
                else:
                    service_costs[service] = cost
            
            daily_costs.append((date, daily_total))
            total_cost += daily_total
        
        # Sort services by cost (highest first)
        top_services = sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Determine alert severity
        critical_alerts = [a for a in alerts if "Monthly cost" in a]
        high_alerts = [a for a in alerts if "Daily cost" in a]
        
        if critical_alerts:
            severity = "CRITICAL"
            subject = f"🚨 CRITICAL FinOps Alert - Monthly Budget Exceeded - Account {account_id}"
        elif high_alerts:
            severity = "HIGH"
            subject = f"⚠️ HIGH FinOps Alert - Daily Spending Threshold Exceeded - Account {account_id}"
        else:
            severity = "MEDIUM"
            subject = f"🟡 FinOps Alert - Cost Threshold Breached - Account {account_id}"
        
        # Build notification message
        message_parts = [
            f"AWS COST THRESHOLD ALERT",
            f"Severity: {severity}",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"COST SUMMARY:",
            f"• Period: {period['start_date']} to {period['end_date']}",
            f"• Total cost: ${total_cost:.2f}",
            f"• Alert count: {len(alerts)}",
            f""
        ]
        
        # Add threshold information
        if thresholds['daily'] or thresholds['monthly']:
            message_parts.append("CONFIGURED THRESHOLDS:")
            if thresholds['daily']:
                message_parts.append(f"• Daily threshold: ${thresholds['daily']:.2f}")
            if thresholds['monthly']:
                message_parts.append(f"• Monthly threshold: ${thresholds['monthly']:.2f}")
            message_parts.append("")
        
        # Add specific alerts
        message_parts.append("🔴 THRESHOLD BREACHES:")
        for alert in alerts:
            message_parts.append(f"  • {alert}")
        message_parts.append("")
        
        # Add top services breakdown
        if top_services:
            message_parts.append("💰 TOP COST DRIVERS:")
            for service, cost in top_services[:5]:  # Top 5 services
                percentage = (cost / total_cost) * 100 if total_cost > 0 else 0
                message_parts.append(f"  • {service}: ${cost:.2f} ({percentage:.1f}%)")
            message_parts.append("")
        
        # Add daily cost trend
        if len(daily_costs) > 1:
            message_parts.append("📊 DAILY COST TREND:")
            for date, daily_cost in daily_costs[-7:]:  # Last 7 days
                status = ""
                if thresholds['daily'] and daily_cost > thresholds['daily']:
                    status = " ⚠️ OVER THRESHOLD"
                message_parts.append(f"  • {date}: ${daily_cost:.2f}{status}")
            message_parts.append("")
        
        # Add cost optimization recommendations
        message_parts.extend([
            "💡 IMMEDIATE ACTIONS RECOMMENDED:",
            "1. Review top cost-driving services for optimization opportunities",
            "2. Analyze usage patterns for unexpected spikes",
            "3. Check for untagged or orphaned resources",
            "4. Review Reserved Instance and Savings Plan coverage",
            "5. Implement cost allocation tags for better visibility",
            "6. Set up AWS Budgets for proactive monitoring",
            "",
            "🔧 COST OPTIMIZATION TOOLS:",
            "• AWS Cost Explorer: Detailed cost analysis and recommendations",
            "• AWS Trusted Advisor: Cost optimization recommendations",
            "• AWS Compute Optimizer: Right-sizing recommendations",
            "• AWS Cost Anomaly Detection: Automated anomaly alerts",
            "",
            "📋 INVESTIGATION CHECKLIST:",
            "□ Check for new service deployments or scaling events",
            "□ Review data transfer costs (especially cross-region)",
            "□ Analyze storage costs and lifecycle policies",
            "□ Verify auto-scaling group configurations",
            "□ Check for development/test resources left running",
            "",
            "🎯 COST CONTROL BEST PRACTICES:",
            "• Implement resource tagging strategy for cost allocation",
            "• Use AWS Organizations for centralized billing management",
            "• Regular cost reviews and budget planning sessions",
            "• Automate resource lifecycle management",
            "• Monitor and optimize data transfer patterns",
            "",
        ])
        
        # Add cost trend analysis
        if len(daily_costs) >= 2:
            recent_avg = sum(cost for _, cost in daily_costs[-3:]) / min(3, len(daily_costs))
            overall_avg = total_cost / len(daily_costs)
            trend = "increasing" if recent_avg > overall_avg else "stable/decreasing"
            
            message_parts.extend([
                "📈 COST TREND ANALYSIS:",
                f"• Recent 3-day average: ${recent_avg:.2f}",
                f"• Period average: ${overall_avg:.2f}",
                f"• Trend: {trend}",
                ""
            ])
        
        message_parts.extend([
            "For detailed cost analysis, access AWS Cost Explorer or Cost Management dashboard.",
            "",
            "This alert was generated by the automated AWS Cost Monitoring function."
        ])
        
        message = "\n".join(message_parts)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        print(f"FinOps SNS notification sent successfully. MessageId: {message_id}")
        print(f"Notified about {len(alerts)} cost threshold breaches (${total_cost:.2f} total)")
        
    except Exception as e:
        print(f"Failed to send FinOps SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main cost monitoring process


def save_report(report, alerts, output_file='aws_cost_report.txt'):
    """Save report and alerts to file"""
    with open(output_file, 'w') as f:
        if alerts:
            f.write("⚠️  COST ALERTS ⚠️\n")
            f.write("=" * 60 + "\n")
            for alert in alerts:
                f.write(f"{alert}\n")
            f.write("\n")
        
        f.write(report)
    
    print(f"Report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor AWS costs and set alerts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic cost monitoring for last 7 days
  ./aws_cost_monitor.py
  
  # Monitor last 30 days with daily alert threshold
  ./aws_cost_monitor.py --days 30 --daily-threshold 50.00
  
  # Monitor current month with monthly threshold using specific AWS profile
  ./aws_cost_monitor.py --current-month --monthly-threshold 500.00 --profile production
  
  # Export detailed report with custom filename
  ./aws_cost_monitor.py --days 14 --output monthly_costs.txt
  
  # Send comprehensive FinOps alerts with trend analysis
  ./aws_cost_monitor.py --daily-threshold 100 --finops-alert --sns-topic arn:aws:sns:us-east-1:123456789012:cost-alerts
  
  # Show cost trend analysis in report
  ./aws_cost_monitor.py --days 14 --show-trends

REQUIRED PERMISSIONS:
- ce:GetCostAndUsage
- ce:GetUsageReport
- sns:Publish (if using --finops-alert)
"""
    )
    parser.add_argument(
        '--days', type=int, default=7,
        help='Number of days to analyze (default: 7)'
    )
    parser.add_argument(
        '--daily-threshold', type=float,
        help='Daily cost threshold for alerts (USD). Can also be set via DAILY_THRESHOLD env var'
    )
    parser.add_argument(
        '--monthly-threshold', type=float,
        help='Monthly cost threshold for alerts (USD). Can also be set via MONTHLY_THRESHOLD env var'
    )
    parser.add_argument(
        '--output', type=str, default='aws_cost_report.txt',
        help='Output file for report (default: aws_cost_report.txt)'
    )
    parser.add_argument(
        '--current-month', action='store_true',
        help='Analyze current month instead of last N days'
    )
    parser.add_argument(
        '--profile', type=str,
        help='AWS profile to use for credentials'
    )
    parser.add_argument(
        '--finops-alert', action='store_true',
        help='Send comprehensive FinOps notifications via SNS'
    )
    parser.add_argument(
        '--sns-topic', type=str,
        help='SNS topic ARN for FinOps notifications'
    )
    parser.add_argument(
        '--show-trends', action='store_true',
        help='Show detailed cost trend analysis'
    )
    
    args = parser.parse_args()
    
    # Add environment variable fallback for thresholds (align with Lambda version)
    if args.daily_threshold is None and os.environ.get('DAILY_THRESHOLD'):
        try:
            args.daily_threshold = float(os.environ.get('DAILY_THRESHOLD'))
            print(f"Using daily threshold from environment: ${args.daily_threshold:.2f}")
        except ValueError:
            print("Warning: Invalid DAILY_THRESHOLD environment variable, ignoring")
    
    if args.monthly_threshold is None and os.environ.get('MONTHLY_THRESHOLD'):
        try:
            args.monthly_threshold = float(os.environ.get('MONTHLY_THRESHOLD'))
            print(f"Using monthly threshold from environment: ${args.monthly_threshold:.2f}")
        except ValueError:
            print("Warning: Invalid MONTHLY_THRESHOLD environment variable, ignoring")
    
    # Validate threshold values
    if args.daily_threshold is not None and args.daily_threshold <= 0:
        print("Error: Daily threshold must be positive")
        sys.exit(1)
    
    if args.monthly_threshold is not None and args.monthly_threshold <= 0:
        print("Error: Monthly threshold must be positive")
        sys.exit(1)
    
    # Create AWS session with profile if specified
    session = None
    if args.profile:
        try:
            session = boto3.Session(profile_name=args.profile)
            print(f"Using AWS profile: {args.profile}")
        except ProfileNotFound:
            print(f"Error: AWS profile '{args.profile}' not found.")
            print("Available profiles can be listed with: aws configure list-profiles")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading AWS profile '{args.profile}': {e}")
            sys.exit(1)
    
    # Validate credentials
    if not validate_aws_credentials(session):
        sys.exit(1)
    
    # Set date range
    end_date = datetime.now()
    
    if args.current_month:
        start_date = end_date.replace(day=1)
        print(f"Analyzing current month costs from {start_date.date()} to {end_date.date()}")
    else:
        start_date = end_date - timedelta(days=args.days)
        print(f"Analyzing last {args.days} days costs from {start_date.date()} to {end_date.date()}")
    
    # Get cost data
    print("Fetching AWS cost data from Cost Explorer...")
    cost_data = get_cost_and_usage(start_date, end_date, session=session)
    
    if not cost_data:
        print("Failed to retrieve cost data")
        sys.exit(1)
    
    # Generate report
    report, daily_costs = format_cost_report(cost_data, args.show_trends)
    print(report)
    
    # Check thresholds
    alerts = check_threshold(
        cost_data,
        args.daily_threshold,
        args.monthly_threshold
    )
    
    if alerts:
        print("\n" + "⚠️  COST ALERTS ⚠️")
        for alert in alerts:
            print(f"  {alert}")
    
    # Send FinOps notifications if requested
    if args.finops_alert and alerts:
        # Get account ID
        if session:
            sts_client = session.client('sts')
        else:
            sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account', 'Unknown')
        
        # Prepare period info
        period = {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d')
        }
        
        # Prepare thresholds
        thresholds = {
            'daily': args.daily_threshold,
            'monthly': args.monthly_threshold
        }
        
        # Send notifications
        send_finops_notifications(cost_data, alerts, account_id, period, thresholds, args.sns_topic, session)
    
    # Save report
    save_report(report, alerts, args.output)
    
    # Return appropriate exit code
    if alerts:
        print(f"\n⚠️  WARNING: {len(alerts)} cost threshold(s) exceeded!")
        sys.exit(1)
    else:
        print("\n✅ All costs are within specified thresholds.")
        sys.exit(0)


if __name__ == "__main__":
    main()
