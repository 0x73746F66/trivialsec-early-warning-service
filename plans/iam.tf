data "aws_iam_policy_document" "early_warning_service_assume_role_policy" {
  statement {
    sid     = "${var.app_env}EarlyWarningServiceAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "early_warning_service_iam_policy" {
  statement {
    sid = "${var.app_env}EarlyWarningServiceLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${local.aws_default_region}:${local.aws_master_account_id}:log-group:/aws/lambda/${local.function_name}:*"
    ]
  }
  statement {
    sid = "${var.app_env}EarlyWarningServiceObjList"
    actions = [
      "s3:Head*",
      "s3:List*",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}",
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}/*",
    ]
  }
  statement {
    sid = "${var.app_env}EarlyWarningServiceObjAccess"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${data.terraform_remote_state.trivialscan_s3.outputs.trivialscan_store_bucket}/${var.app_env}/*",
    ]
  }
  statement {
    sid = "${var.app_env}EarlyWarningServiceSecrets"
    actions = [
      "ssm:GetParameter",
    ]
    resources = [
      "arn:aws:ssm:${local.aws_default_region}:${local.aws_master_account_id}:parameter/${var.app_env}/${var.app_name}/*",
    ]
  }
  statement {
    sid = "${var.app_env}EarlyWarningServiceSQS"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:Get*",
    ]
    resources = [
      aws_sqs_queue.early_warning_service_queue.arn
    ]
  }
  statement {
    sid = "${var.app_env}EarlyWarningServiceDynamoDB"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem"
    ]
    resources = [
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_observed_identifiers",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_early_warning_service",
    ]
  }
  statement {
    sid = "${var.app_env}EarlyWarningServiceDynamoDBQuery"
    actions = [
      "dynamodb:Query"
    ]
    resources = [
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_observed_identifiers/*",
      "arn:aws:dynamodb:${local.aws_default_region}:${local.aws_master_account_id}:table/${lower(var.app_env)}_early_warning_service/*",
    ]
  }
}
resource "aws_iam_role" "early_warning_service_role" {
  name               = "${lower(var.app_env)}_early_warning_service_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.early_warning_service_assume_role_policy.json
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_iam_policy" "early_warning_service_policy" {
  name   = "${lower(var.app_env)}_early_warning_service_lambda_policy"
  path   = "/"
  policy = data.aws_iam_policy_document.early_warning_service_iam_policy.json
}
resource "aws_iam_role_policy_attachment" "policy_attach" {
  role       = aws_iam_role.early_warning_service_role.name
  policy_arn = aws_iam_policy.early_warning_service_policy.arn
}
