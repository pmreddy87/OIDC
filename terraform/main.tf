resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

  data "archive_file" "ssl-expiry-check" {
  type        = "zip"
  source_dir = "../lambda/ssl-expiry-check/"
  output_path = "ssl-expiry-check.zip"
}
resource "aws_lambda_function" "ssl-expiry-check" {
  # depends_on    = [aws_iam_role_policy_attachment.ssl-expiry-check]
  filename      = data.archive_file.ssl-expiry-check.output_path
  function_name = "ssl-expiry-check"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.lambda_handler"
  source_code_hash  = "${data.archive_file.ssl-expiry-check.output_base64sha256}"
  timeout       = "15"

  runtime = "python3.9"

  environment {
    variables = {
      ALERT_METHOD = "SMTP"
      EMAIL_USERNAME = var.email_username
      EMAIL_TOKEN = var.email_token
      EMAIL_HOST = var.email_host
      EMAIL_PORT = var.email_port
      EMAIL_FROM = var.email_from
      EMAIL_TO = var.email_to
      EMAIL_ORIGIN = var.email_origin
      // SNS_ARN   =   var.sns_arn
    }
  }
}


# Allow full ec2 permission
resource "aws_iam_role_policy" "extra_lambda_permissions" {
  name   = "full_ec2_ssl_expiry_check_lambda"
  role   = aws_iam_role.iam_for_lambda.name
  policy = jsonencode({
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:logs:*:*:*",
        },
        {
            "Action": "ec2:*",
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "acm:DescribeCertificate",
                "acm:ListCertificates",
                "acm:GetCertificate",
                "acm:ListTagsForCertificate",
                "acm:GetAccountConfiguration"
            ],
            "Resource": "*"
        }
    ]
}
  )
}
