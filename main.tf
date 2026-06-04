terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── GUARDDUTY ──────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  enable = true
}

# ── SNS TOPIC ──────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── DYNAMODB ───────────────────────────────────────────────
resource "aws_dynamodb_table" "incidents" {
  name         = "guardduty-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incidentId"

  attribute {
    name = "incidentId"
    type = "S"
  }
}

# ── LAMBDA ─────────────────────────────────────────────────
resource "aws_lambda_function" "guardduty_processor" {
  filename      = "lambda.zip"
  function_name = "guardduty-alert-processor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"

  environment {
    variables = {
      TOPIC_ARN      = aws_sns_topic.security_alerts.arn
      DYNAMODB_TABLE = aws_dynamodb_table.incidents.name
    }
  }
}

# ── EVENTBRIDGE ────────────────────────────────────────────
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-high-severity"
  description = "Triggers Lambda for GuardDuty findings severity 7+"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "guardduty-lambda"
  arn       = aws_lambda_function.guardduty_processor.arn
}

# ── IAM ROLE ───────────────────────────────────────────────
resource "aws_iam_role" "lambda_role" {
  name = "guardduty-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dynamodb" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "sns" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

resource "aws_iam_role_policy_attachment" "cloudtrail" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "iam_full" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}