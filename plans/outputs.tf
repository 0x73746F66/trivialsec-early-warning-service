# output "early_warning_service_arn" {
#   value = aws_lambda_function.early_warning_service.arn
# }
output "early_warning_service_role" {
  value = aws_iam_role.early_warning_service_role.name
}
output "early_warning_service_role_arn" {
  value = aws_iam_role.early_warning_service_role.arn
}
output "early_warning_service_policy_arn" {
  value = aws_iam_policy.early_warning_service_policy.arn
}
output "early_warning_service_dlq_arn" {
  value = aws_sqs_queue.early_warning_service_dlq.arn
}
output "early_warning_service_queue_arn" {
  value = aws_sqs_queue.early_warning_service_queue.arn
}
output "early_warning_service_queue_name" {
  value = aws_sqs_queue.early_warning_service_queue.name
}
