#!/bin/bash

# AWS SAM Deployment Script for List ELBs and ALBs Inventory
set -e

# Configuration
STACK_NAME="list-elbs-and-albs-stack"
REGION="eu-west-1"
ENVIRONMENT="${1:-dev}"

echo "🚀 Deploying List ELBs and ALBs Inventory Lambda to $ENVIRONMENT environment..."

# Validate SAM template
echo "📋 Validating SAM template..."
sam validate

# Build the application
echo "🔨 Building application..."
sam build

# Deploy with guided prompts (first time) or using saved config
if [ "$2" = "--guided" ]; then
    echo "🎯 Deploying with guided configuration..."
    sam deploy --guided \
        --stack-name $STACK_NAME \
        --region $REGION \
        --parameter-overrides Environment=$ENVIRONMENT
else
    echo "🎯 Deploying using saved configuration..."
    sam deploy \
        --stack-name $STACK_NAME \
        --region $REGION \
        --parameter-overrides Environment=$ENVIRONMENT
fi

# Get outputs
echo "📊 Deployment outputs:"
aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --region $REGION \
    --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
    --output table

echo "✅ Deployment complete!"
echo "🔗 Function ARN: $(aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION --query 'Stacks[0].Outputs[?OutputKey==`ListELBsALBsFunction`].OutputValue' --output text)"

# Test the function (optional)
if [ "$3" = "--test" ]; then
    echo "🧪 Testing function..."
    aws lambda invoke \
        --function-name $(aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION --query 'Stacks[0].Outputs[?OutputKey==`ListELBsALBsFunction`].OutputValue' --output text) \
        --region $REGION \
        --payload '{"params": {"scan_all_regions": false}}' \
        response.json
    
    echo "📋 Test response:"
    cat response.json | python -m json.tool
    rm response.json
fi