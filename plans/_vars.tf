variable "aws_access_key_id" {
  description = "AWS_ACCESS_KEY_ID"
  type        = string
}
variable "log_level" {
  description = "LOG_LEVEL"
  type        = string
  default     = "WARNING"
}
variable "app_env" {
  description = "default Dev"
  type        = string
  default     = "Dev"
}
variable "app_name" {
  description = "default early-warning-service"
  type        = string
  default     = "early-warning-service"
}
variable "build_env" {
  description = "BUILD_ENV"
  type        = string
  default     = "development"
}
variable "pusher_app_id" {
  description = "PUSHER_APP_ID"
  type        = string
}
variable "pusher_key" {
  description = "PUSHER_KEY"
  type        = string
}
