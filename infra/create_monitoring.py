#!/usr/bin/env python3
"""
05_create_monitoring.py
=======================
Sets up CloudWatch dashboard and alarms for the blog1 LLM chatbot.

Creates:
  - SNS topic for security alerts
  - Alarm: injection spike (5+ attempts in 60 seconds)
  - Alarm: any output block (potential data exfiltration)
  - Alarm: Lambda error rate
  - Dashboard: real-time security posture view

Usage: python3 05_create_monitoring.py
"""

import boto3
import json
import os

REGION     = "us-east-1"
NAMESPACE  = "LLMSecurity/Blog1"
FN_NAME    = "blog1-chatbot"
DIMS       = [{"Name": "Function", "Value": FN_NAME}]

cw  = boto3.client("cloudwatch", region_name=REGION)
sns = boto3.client("sns",        region_name=REGION)
lmb = boto3.client("lambda",     region_name=REGION)
sts = boto3.client("sts")
ACCOUNT_ID = sts.get_caller_identity()["Account"]


def create_sns_topic() -> str:
    print("creating SNS topic")
    topic_arn = sns.create_topic(
        Name="blog1-security-alerts",
        Tags=[{"Key": "Project", "Value": "blog1-llm-security"}]
    )["TopicArn"]
    print(f"topic ARN: {topic_arn}")
    print(f'subscribe: aws sns subscribe --topic-arn "{topic_arn}" --protocol email --notification-endpoint "you@example.com"')
    return topic_arn


def create_alarms(topic_arn: str):
    print("creating CloudWatch alarms")

    alarms = [

        # Alarm 1: Injection spike
        # Fires when 5+ injection attempts hit in any 60-second window
        {
            "AlarmName": "blog1-injection-spike",
            "AlarmDescription": (
                "SECURITY: 5+ prompt injection attempts in 60 seconds. "
                "Investigate immediately."
            ),
            "Namespace": NAMESPACE,
            "MetricName": "InjectionBlocked",
            "Dimensions": DIMS,
            "Statistic": "Sum",
            "Period": 60,
            "EvaluationPeriods": 1,
            "Threshold": 5,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
            "AlarmActions": [topic_arn],
            "OKActions": [topic_arn],
        },

        # Alarm 2: Any output blocked
        # Even one blocked output is worth knowing about immediately
        {
            "AlarmName": "blog1-output-blocked",
            "AlarmDescription": (
                "SECURITY: LLM output was blocked by output validator. "
                "Potential data exfiltration attempt detected."
            ),
            "Namespace": NAMESPACE,
            "MetricName": "OutputBlocked",
            "Dimensions": DIMS,
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
            "AlarmActions": [topic_arn],
        },

        # Alarm 3: Lambda error rate
        # Catches unexpected failures that could indicate abuse
        {
            "AlarmName": "blog1-lambda-errors",
            "AlarmDescription": (
                "Lambda function error rate elevated. "
                "Check CloudWatch Logs for details."
            ),
            "Namespace": "AWS/Lambda",
            "MetricName": "Errors",
            "Dimensions": [{"Name": "FunctionName", "Value": FN_NAME}],
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 2,
            "Threshold": 10,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
            "AlarmActions": [topic_arn],
        },

        # Alarm 4: Input too long (potential DoS probing)
        {
            "AlarmName": "blog1-input-too-long",
            "AlarmDescription": (
                "Repeated oversized inputs detected. "
                "Possible denial-of-service probing."
            ),
            "Namespace": NAMESPACE,
            "MetricName": "InputTooLong",
            "Dimensions": DIMS,
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 20,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
            "AlarmActions": [topic_arn],
        },
    ]

    for alarm in alarms:
        cw.put_metric_alarm(**alarm)
        print(f"  alarm: {alarm['AlarmName']}")


def _metric_widget(x, y, w, h, title, metrics, stat="Sum"):
    return {
        "type": "metric",
        "x": x, "y": y, "width": w, "height": h,
        "properties": {
            "title": title,
            "view": "timeSeries",
            "stacked": False,
            "stat": stat,
            "period": 300,
            "region": REGION,
            "metrics": metrics,
        },
    }


def create_dashboard():
    print("creating CloudWatch dashboard")

    widgets = [
        # Row 1 — security metrics (4 × 6-wide)
        _metric_widget(0,  0, 6, 6, "Injection Attempts Blocked",
                       [[NAMESPACE, "InjectionBlocked", "Function", FN_NAME]]),
        _metric_widget(6,  0, 6, 6, "Output Blocks",
                       [[NAMESPACE, "OutputBlocked",   "Function", FN_NAME]]),
        _metric_widget(12, 0, 6, 6, "Successful Responses",
                       [[NAMESPACE, "Success",         "Function", FN_NAME]]),
        _metric_widget(18, 0, 6, 6, "Input Too Long (DoS probe)",
                       [[NAMESPACE, "InputTooLong",    "Function", FN_NAME]]),

        # Row 2 — Lambda health (3 × 8-wide)
        _metric_widget(0,  6, 8, 6, "Lambda Duration (ms)",
                       [["AWS/Lambda", "Duration",    "FunctionName", FN_NAME]], stat="Average"),
        _metric_widget(8,  6, 8, 6, "Lambda Errors",
                       [["AWS/Lambda", "Errors",      "FunctionName", FN_NAME]]),
        _metric_widget(16, 6, 8, 6, "Lambda Invocations",
                       [["AWS/Lambda", "Invocations", "FunctionName", FN_NAME]]),
    ]

    body = json.dumps({"widgets": widgets})
    try:
        cw.put_dashboard(DashboardName="blog1-llm-security", DashboardBody=body)
    except Exception as e:
        print(f"\n    ERROR: {e}")
        print("\n    Dashboard JSON sent:")
        print(body)
        raise

    print("dashboard created: blog1-llm-security")


def setup_log_insights():
    print(f"log group: /aws/lambda/{FN_NAME}")


def main():
    topic_arn = create_sns_topic()
    create_alarms(topic_arn)
    create_dashboard()
    setup_log_insights()

    with open(".sns_topic_arn", "w") as f:
        f.write(topic_arn)

    print("\ndone - view dashboard at CloudWatch -> Dashboards -> blog1-llm-security")


if __name__ == "__main__":
    main()
