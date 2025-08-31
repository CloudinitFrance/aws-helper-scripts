import json
import boto3
import logging
import os
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Any, List
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def validate_aws_credentials():
    """Validate AWS credentials before proceeding."""
    try:
        sts = boto3.client('sts')
        response = sts.get_caller_identity()
        logger.info(f"Using AWS Account: {response.get('Account', 'Unknown')}")
        logger.info(f"User/Role: {response.get('Arn', 'Unknown')}")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        logger.error(f"AWS credentials not found or incomplete: {e}")
        return False
    except ClientError as e:
        logger.error(f"Error validating credentials: {e.response['Error']['Message']}")
        return False

def get_cost_and_usage(start_date, end_date, granularity='DAILY'):
    """Retrieve cost and usage data from AWS Cost Explorer"""
    try:
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
            logger.error("Insufficient permissions to access Cost Explorer")
        else:
            logger.error(f"AWS API Error: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        logger.error(f"Error fetching cost data: {e}")
        return None

def format_cost_report(cost_data):
    """Format cost data into a readable report"""
    if not cost_data:
        return "No cost data available"
    
    report = []
    report.append("=" * 60)
    report.append("AWS COST REPORT")
    report.append("=" * 60)
    
    total_cost = Decimal('0')
    
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
    
    report.append("\n" + "=" * 60)
    report.append(f"  {'PERIOD TOTAL':<30} ${total_cost:>10.2f}")
    report.append("=" * 60)
    
    return "\n".join(report)

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

def send_finops_notifications(cost_data: Dict, alerts: List[str], account_id: str, period: Dict, thresholds: Dict) -> None:
    """Send SNS notifications for cost threshold breaches to FinOps team."""
    try:
        sns_client = boto3.client('sns')
        finops_topic_arn = os.environ.get('FINOPS_TOPIC_ARN')
        
        if not finops_topic_arn:
            logger.warning("FINOPS_TOPIC_ARN not configured, skipping FinOps notifications")
            return
        
        if not alerts:
            logger.info("No cost threshold breaches to notify")
            return
        
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
            TopicArn=finops_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        logger.info(f"FinOps SNS notification sent successfully. MessageId: {message_id}")
        logger.info(f"Notified about {len(alerts)} cost threshold breaches (${total_cost:.2f} total)")
        
    except Exception as e:
        logger.error(f"Failed to send FinOps SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main cost monitoring process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for aws-cost-monitor
    
    Args:
        event: Lambda event object containing parameters
        context: Lambda context object
        
    Returns:
        Dict with execution results
    """
    try:
        logger.info("Starting AWS Cost Monitor execution")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        days = params.get('days', int(os.environ.get('DAYS', 7)))
        daily_threshold = params.get('daily_threshold')
        monthly_threshold = params.get('monthly_threshold')
        current_month = params.get('current_month', False)
        
        # Use environment variables if not provided in event
        if daily_threshold is None:
            daily_threshold = float(os.environ.get('DAILY_THRESHOLD', 0)) if os.environ.get('DAILY_THRESHOLD') else None
        if monthly_threshold is None:
            monthly_threshold = float(os.environ.get('MONTHLY_THRESHOLD', 0)) if os.environ.get('MONTHLY_THRESHOLD') else None
        
        # Validate credentials
        if not validate_aws_credentials():
            raise Exception("AWS credentials validation failed")
        
        # Set date range
        end_date = datetime.now()
        
        if current_month:
            start_date = end_date.replace(day=1)
            logger.info(f"Analyzing current month costs from {start_date.date()} to {end_date.date()}")
        else:
            start_date = end_date - timedelta(days=days)
            logger.info(f"Analyzing last {days} days costs from {start_date.date()} to {end_date.date()}")
        
        # Get cost data
        logger.info("Fetching AWS cost data from Cost Explorer...")
        cost_data = get_cost_and_usage(start_date, end_date)
        
        if not cost_data:
            raise Exception("Failed to retrieve cost data")
        
        # Generate report
        report = format_cost_report(cost_data)
        logger.info("Cost report generated successfully")
        
        # Check thresholds
        alerts = check_threshold(cost_data, daily_threshold, monthly_threshold)
        
        # Get account ID for notifications
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account', 'Unknown')
        
        if alerts:
            # Send FinOps notifications for cost threshold breaches
            send_finops_notifications(cost_data, alerts, account_id, {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d'),
                'days': days if not current_month else None,
                'current_month': current_month
            }, {
                'daily': daily_threshold,
                'monthly': monthly_threshold
            })
            
            logger.warning(f"Cost alerts triggered: {len(alerts)}")
            for alert in alerts:
                logger.warning(alert)
        else:
            logger.info("All costs are within specified thresholds")
        
        # Calculate service-level costs for response
        service_costs = {}
        total_cost = Decimal('0')
        
        for result in cost_data['ResultsByTime']:
            for group in result['Groups']:
                service = group['Keys'][0]
                cost = Decimal(group['Metrics']['UnblendedCost']['Amount'])
                
                if service in service_costs:
                    service_costs[service] += cost
                else:
                    service_costs[service] = cost
                
                total_cost += cost
        
        # Sort services by cost and get top 10
        sorted_services = sorted(service_costs.items(), key=lambda x: x[1], reverse=True)
        top_services = []
        
        for service, cost in sorted_services[:10]:
            percentage = (cost / total_cost) * 100 if total_cost > 0 else 0
            top_services.append({
                'service': service,
                'cost': float(cost),
                'percentage': round(percentage, 2)
            })
        
        # Prepare response
        results = {
            'report': report,
            'alerts': alerts,
            'period': {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d'),
                'days': days if not current_month else None,
                'current_month': current_month
            },
            'thresholds': {
                'daily': daily_threshold,
                'monthly': monthly_threshold
            },
            'alert_count': len(alerts),
            'service_costs': {
                'top_services': top_services,
                'total_cost': float(total_cost),
                'service_count': len(service_costs)
            }
        }
        
        # Format response
        response = {
            'statusCode': 200 if not alerts else 201,  # 201 indicates alerts
            'body': json.dumps({
                'message': 'Cost monitoring completed successfully',
                'results': results,
                'executionId': context.aws_request_id,
                'alerts_triggered': len(alerts) > 0
            }, default=str)
        }
        
        logger.info("Execution completed successfully")
        return response
        
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'executionId': context.aws_request_id
            })
        }