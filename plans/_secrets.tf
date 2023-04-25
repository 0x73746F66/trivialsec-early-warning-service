variable "aws_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY"
  type        = string
  sensitive   = true
}
variable "sendgrid_api_key" {
  description = "SENDGRID_API_KEY"
  type        = string
  sensitive   = true
}
variable "pusher_secret" {
  description = "PUSHER_SECRET"
  type        = string
  sensitive   = true
}
variable "dynatrace_token" {
  description = "DYNATRACE_TOKEN"
  type        = string
  sensitive   = true
}
variable "lumigo_token" {
  description = "LUMIGO_TOKEN"
  type        = string
  sensitive   = true
}
