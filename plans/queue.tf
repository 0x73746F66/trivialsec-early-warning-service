resource "aws_sqs_queue" "early_warning_service_dlq" {
  name                          = "${lower(var.app_env)}-early-warning-service-dlq"
  tags                          = local.tags
}

resource "aws_sqs_queue" "early_warning_service_queue" {
  name                          = "${lower(var.app_env)}-early-warning-service"
  visibility_timeout_seconds    = 300
  message_retention_seconds     = 86400
  redrive_policy                = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.early_warning_service_dlq.arn}\",\"maxReceiveCount\":2}"
  tags                          = local.tags
}
