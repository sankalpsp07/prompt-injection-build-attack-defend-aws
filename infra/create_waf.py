#!/usr/bin/env python3
"""
04_create_waf.py
================
Creates an AWS WAF WebACL and attaches it to the API Gateway stage.
WAF is the outermost defence layer - blocks attacks before Lambda runs.

Protections applied:
  - Rate limiting: 100 requests per 5 min per IP
  - AWS Managed: Known Bad Inputs (SQLi, XSS, Log4j, etc.)
  - AWS Managed: Core Rule Set
  - AWS Managed: Anonymous IP list (Tor, VPN, proxies)

AWS managed rule groups are continuously updated by AWS security teams -
you get protection against new attack patterns without managing rules yourself.

Usage: python3 04_create_waf.py
"""

import boto3
import json
import os

REGION   = "us-east-1"
ACL_NAME = "blog1-llm-waf"

waf = boto3.client("wafv2", region_name=REGION)


def get_api_id() -> str:
    if os.path.exists(".api_id"):
        return open(".api_id").read().strip()
    return ""


def create_web_acl() -> tuple:
    print("creating WAF WebACL")

    try:
        acls = waf.list_web_acls(Scope="REGIONAL")["WebACLs"]
        for acl in acls:
            if acl["Name"] == ACL_NAME:
                acl_id  = acl["Id"]
                acl_arn = acl["ARN"]
                print(f"WebACL already exists: {acl_id}")
                return acl_id, acl_arn
    except Exception:
        pass

    response = waf.create_web_acl(
        Name=ACL_NAME,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Description="Blog1 LLM security demo - WAF protection for Bedrock chatbot",
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": ACL_NAME,
        },
        Tags=[
            {"Key": "Project", "Value": "blog1-llm-security"},
        ],
        Rules=[

            # ── Rule 1: Rate Limiting ──────────────────────────────────
            # Blocks IPs sending more than 100 requests in 5 minutes.
            # Prevents automated injection scanning and credential stuffing.
            {
                "Name": "RateLimitPerIP",
                "Priority": 1,
                "Action": {"Block": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "RateLimitPerIP",
                },
                "Statement": {
                    "RateBasedStatement": {
                        "Limit": 100,
                        "AggregateKeyType": "IP",
                    }
                },
            },

            # ── Rule 2: AWS Managed - Known Bad Inputs ─────────────────
            # Blocks: Log4j exploits, SSRF attempts, JavaDeserialisation,
            # size restrictions violations, and other known bad payloads.
            # Updated automatically by AWS.
            {
                "Name": "AWSManagedKnownBadInputs",
                "Priority": 2,
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWSManagedKnownBadInputs",
                },
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                    }
                },
            },

            # ── Rule 3: AWS Managed - Core Rule Set ────────────────────
            # Blocks common web attacks: SQLi, XSS, path traversal,
            # protocol violations, and more.
            {
                "Name": "AWSManagedCoreRuleSet",
                "Priority": 3,
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWSManagedCoreRuleSet",
                },
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesCommonRuleSet",
                        # Exclude size restriction rule - LLM inputs can be long
                        "ExcludedRules": [
                            {"Name": "SizeRestrictions_BODY"}
                        ],
                    }
                },
            },

            # ── Rule 4: AWS Managed - Anonymous IP List ────────────────
            # Blocks requests from Tor exit nodes, VPNs, and anonymising
            # proxies - common attack infrastructure.
            {
                "Name": "AWSManagedAnonymousIPList",
                "Priority": 4,
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWSManagedAnonymousIPList",
                },
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesAnonymousIpList",
                    }
                },
            },

        ],
    )

    acl     = response["Summary"]
    acl_id  = acl["Id"]
    acl_arn = acl["ARN"]
    print(f"WebACL created: {acl_id}")
    return acl_id, acl_arn


def associate_with_api(acl_arn: str, api_id: str):
    import time
    print(f"associating WAF with API stage {api_id}/prod")

    stage_arn = f"arn:aws:apigateway:{REGION}::/restapis/{api_id}/stages/prod"

    for attempt in range(5):
        try:
            waf.associate_web_acl(WebACLArn=acl_arn, ResourceArn=stage_arn)
            print("associated")
            return
        except waf.exceptions.WAFNonexistentItemException:
            print(f"stage not found ({api_id}/prod) - run deploy_lambda.py first")
            return
        except Exception as e:
            if "WAFUnavailableEntityException" in str(e) and attempt < 4:
                print(f"stage not ready yet, retrying in 10s ({attempt+1}/5)")
                time.sleep(10)
            else:
                print(f"association failed: {e}")
                return


def main():
    api_id = get_api_id()
    if not api_id:
        print("no .api_id found - run deploy_lambda.py first")

    acl_id, acl_arn = create_web_acl()

    if api_id:
        associate_with_api(acl_arn, api_id)

    with open(".waf_acl_arn", "w") as f:
        f.write(acl_arn)

    print(f"\nWebACL ARN: {acl_arn}")


if __name__ == "__main__":
    main()
