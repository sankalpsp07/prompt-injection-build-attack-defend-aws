#!/usr/bin/env python3
"""
06_teardown.py
==============
Removes ALL resources created by the blog1 demo scripts.
Run this when you are done with the lab to avoid ongoing AWS charges.

Resources removed:
  - Lambda function
  - API Gateway HTTP API
  - Bedrock Guardrail
  - WAF WebACL
  - CloudWatch alarms + dashboard
  - SNS topic
  - IAM role + policies

Usage: python3 06_teardown.py
"""

import boto3
import json
import os

REGION = "us-east-1"

lmb      = boto3.client("lambda",     region_name=REGION)
apigw    = boto3.client("apigateway", region_name=REGION)    # REST API v1
apigw_v2 = boto3.client("apigatewayv2", region_name=REGION) # HTTP API v2 (legacy cleanup)
bedrock = boto3.client("bedrock",      region_name=REGION)
waf     = boto3.client("wafv2",        region_name=REGION)
cw      = boto3.client("cloudwatch",   region_name=REGION)
sns_c   = boto3.client("sns",          region_name=REGION)
iam     = boto3.client("iam")
sts     = boto3.client("sts")

ACCOUNT_ID = sts.get_caller_identity()["Account"]


def confirm():
    print("this will delete all blog1 demo resources")
    answer = input("type 'yes' to confirm: ").strip().lower()
    if answer != "yes":
        print("aborted")
        exit(0)


def delete_lambda():
    print("deleting lambda")
    try:
        lmb.delete_function(FunctionName="blog1-chatbot")
        print("deleted blog1-chatbot")
    except lmb.exceptions.ResourceNotFoundException:
        print("blog1-chatbot not found")
    except Exception as e:
        print(f"error: {e}")


def delete_api_gateway():
    print("deleting API gateway")
    deleted = False

    try:
        for api in apigw.get_rest_apis().get("items", []):
            if api["name"] == "blog1-api":
                apigw.delete_rest_api(restApiId=api["id"])
                print(f"deleted REST API: {api['id']}")
                deleted = True
    except Exception as e:
        print(f"REST API error: {e}")

    try:
        for api in apigw_v2.get_apis().get("Items", []):
            if api["Name"] == "blog1-api":
                apigw_v2.delete_api(ApiId=api["ApiId"])
                print(f"deleted HTTP API: {api['ApiId']}")
                deleted = True
    except Exception as e:
        print(f"HTTP API error: {e}")

    if not deleted:
        print("blog1-api not found")


def delete_guardrail():
    print("deleting guardrail")
    guardrail_id = ""
    if os.path.exists(".guardrail_id"):
        guardrail_id = open(".guardrail_id").read().strip()

    if not guardrail_id:
        try:
            for g in bedrock.list_guardrails().get("guardrails", []):
                if g["name"] == "blog1-injection-guard":
                    guardrail_id = g["id"]
                    break
        except Exception as e:
            print(f"error listing guardrails: {e}")

    if guardrail_id:
        try:
            bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
            print(f"deleted guardrail: {guardrail_id}")
        except Exception as e:
            print(f"error: {e}")
    else:
        print("guardrail not found")


def delete_waf():
    print("deleting WAF")
    try:
        for acl in waf.list_web_acls(Scope="REGIONAL")["WebACLs"]:
            if acl["Name"] == "blog1-llm-waf":
                acl_id  = acl["Id"]
                acl_arn = acl["ARN"]

                try:
                    for arn in waf.list_resources_for_web_acl(WebACLArn=acl_arn).get("ResourceArns", []):
                        waf.disassociate_web_acl(ResourceArn=arn)
                        print(f"disassociated from: {arn}")
                except Exception as e:
                    print(f"disassociation warning: {e}")

                lock_token = waf.get_web_acl(Name="blog1-llm-waf", Scope="REGIONAL", Id=acl_id)["LockToken"]
                waf.delete_web_acl(Name="blog1-llm-waf", Scope="REGIONAL", Id=acl_id, LockToken=lock_token)
                print(f"deleted WAF: {acl_id}")
                return

        print("WAF not found")
    except Exception as e:
        print(f"error: {e}")


def delete_cloudwatch():
    print("deleting CloudWatch alarms")
    try:
        cw.delete_alarms(AlarmNames=[
            "blog1-injection-spike", "blog1-output-blocked",
            "blog1-lambda-errors",   "blog1-input-too-long",
        ])
        print("alarms deleted")
    except Exception as e:
        print(f"error: {e}")

    print("deleting CloudWatch dashboard")
    try:
        cw.delete_dashboards(DashboardNames=["blog1-llm-security"])
        print("dashboard deleted")
    except Exception as e:
        print(f"error: {e}")


def delete_sns():
    print("deleting SNS topic")
    topic_arn = (open(".sns_topic_arn").read().strip() if os.path.exists(".sns_topic_arn")
                 else f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:blog1-security-alerts")
    try:
        sns_c.delete_topic(TopicArn=topic_arn)
        print(f"deleted topic: {topic_arn}")
    except Exception as e:
        print(f"error: {e}")


def delete_iam_role():
    print("deleting IAM role")
    role_name = "blog1-lambda-role"
    try:
        for policy in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy)

        for policy in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])

        iam.delete_role(RoleName=role_name)
        print(f"deleted role: {role_name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"role not found: {role_name}")
    except Exception as e:
        print(f"error: {e}")


def cleanup_local_files():
    state_files = [
        ".role_arn", ".api_endpoint", ".endpoint_url", ".api_id",
        ".guardrail_id", ".waf_acl_arn", ".sns_topic_arn"
    ]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_dirs = [os.getcwd(), script_dir]

    removed = []
    for d in search_dirs:
        for f in state_files:
            path = os.path.join(d, f)
            if os.path.exists(path):
                os.remove(path)
                removed.append(os.path.relpath(path))
    if removed:
        print(f"removed: {', '.join(removed)}")


def main():
    confirm()

    delete_lambda()
    delete_api_gateway()
    delete_guardrail()
    delete_waf()
    delete_cloudwatch()
    delete_sns()
    delete_iam_role()
    cleanup_local_files()

    print("\ndone")


if __name__ == "__main__":
    main()
