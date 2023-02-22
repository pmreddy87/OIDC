resource "aws_cloudwatch_event_rule" "lambda_event_rule" {
  name = "ssl-expiry-check-lambda-event-rule"
  description = "Run ACM ssl check two minutes"
  // schedule_expression = "rate(2 minutes)"
  schedule_expression = "cron(0/2 * ? * * *)"
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  arn = aws_lambda_function.ssl-expiry-check.arn
  rule = aws_cloudwatch_event_rule.lambda_event_rule.name
}

resource "aws_lambda_permission" "allow_cloudwatch_lambda" {
  statement_id = "AllowExecutionFromCloudWatch"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ssl-expiry-check.function_name
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_event_rule.arn
  }
