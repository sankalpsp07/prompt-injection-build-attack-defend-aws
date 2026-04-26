#!/bin/bash
set -e

echo "Step 1: Create IAM Role"
python3 infra/create_role.py

echo "Step 2: Create Bedrock Guardrail"
python3 infra/create_guardrail.py

echo "Step 3: Deploy Lambda and API Gateway"
python3 infra/deploy_lambda.py

echo "Step 4: Create and Attach WAF"
python3 infra/create_waf.py

echo "Step 5: Set Up Monitoring and Alerts"
python3 infra/create_monitoring.py

echo "Deployment Complete"
