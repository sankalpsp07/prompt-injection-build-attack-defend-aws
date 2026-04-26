#!/usr/bin/env python3
"""
01_create_role.py
=================
Creates the IAM execution role for the blog1 Lambda function.
Least-privilege: scoped to specific Bedrock model ARN only.

Run first before any other script.
Usage: python3 01_create_role.py
"""

import boto3
import json
import time

REGION    = "us-east-1"
ROLE_NAME = "blog1-lambda-role"

iam        = boto3.client("iam")
sts        = boto3.client("sts")
ACCOUNT_ID = sts.get_caller_identity()["Account"]

MODEL_ARN = (
    f"arn:aws:bedrock:{REGION}::foundation-model/"
    "amazon.nova-micro-v1:0"
)

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

bedrock_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "BedrockInvokeScoped",
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:ApplyGuardrail"
            ],
            "Resource": [
                MODEL_ARN,
                f"arn:aws:bedrock:{REGION}:{ACCOUNT_ID}:guardrail/*"
            ]
        },
        {
            "Sid": "CloudWatchMetrics",
            "Effect": "Allow",
            "Action": ["cloudwatch:PutMetricData"],
            "Resource": "*"
        }
    ]
}


def main():
    print("creating IAM role")
    try:
        role = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Blog1 LLM security demo - Lambda execution role",
            Tags=[
                {"Key": "Project", "Value": "blog1-llm-security"},
                {"Key": "ManagedBy", "Value": "boto3"},
            ]
        )
        role_arn = role["Role"]["Arn"]
        print(f"created role: {role_arn}")
    except iam.exceptions.EntityAlreadyExistsException:
        role_arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
        print(f"role already exists: {role_arn}")

    print("attaching AWSLambdaBasicExecutionRole")
    try:
        iam.attach_role_policy(
            RoleName=ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
    except Exception:
        pass  # already attached

    print("adding bedrock inline policy")
    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="BedrockScopedAndCloudWatch",
        PolicyDocument=json.dumps(bedrock_policy)
    )
    print(f"bedrock access scoped to: {MODEL_ARN}")

    print("waiting 12s for IAM propagation")
    time.sleep(12)

    print(f"\nrole ARN: {role_arn}")

    # Save ARN for other scripts
    with open(".role_arn", "w") as f:
        f.write(role_arn)


if __name__ == "__main__":
    main()
