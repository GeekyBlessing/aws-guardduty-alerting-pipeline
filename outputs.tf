output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

output "lambda_function_arn" {
  value = aws_lambda_function.guardduty_processor.arn
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.incidents.name
}