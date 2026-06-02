# AWS GuardDuty Alerting Pipeline

## Overview

This project demonstrates a serverless security monitoring solution on AWS.

When GuardDuty detects a security finding, Amazon EventBridge captures the event and triggers an AWS Lambda function. The Lambda function processes the finding and publishes an alert to Amazon SNS, which sends an email notification to subscribed administrators.

## Architecture

GuardDuty → EventBridge → Lambda → SNS → Email

## AWS Services Used

* Amazon GuardDuty
* Amazon EventBridge
* AWS Lambda
* Amazon SNS
* AWS IAM

## Features

* Real-time security alerting
* Serverless architecture
* Event-driven automation
* Email notifications for GuardDuty findings

## Sample Alert

Finding Type: UnauthorizedAccess:IAMUser

Severity: 8

## Learning Outcomes

* Event-driven security automation
* AWS IAM permissions management
* Lambda development and testing
* SNS notification workflows
* Cloud security monitoring

## Future Improvements

* Slack integration
* Security Hub integration
* Severity-based routing
* Infrastructure as Code (Terraform)
* Automated remediation workflows
