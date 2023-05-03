locals {
  aws_master_account_id = 984310022655
  aws_default_region    = "ap-southeast-2"
  python_version        = "python3.10"
  source_file           = "${lower(var.app_env)}-${var.app_name}.zip"
  function_name         = "${lower(var.app_env)}-early-warning-service"
  queue_batch_size      = 20
  tags = {
    ProjectName      = "early-warning-service"
    ProjectLeadEmail = "chris@trivialsec.com"
    CostCenter       = var.app_env != "Prod" ? "randd" : "opex"
    SecurityTags     = "customer-data"
    AutomationTool   = "Terraform"
    LUMIGO_TAG       = var.app_env == "Prod" ? "Production" : "Development"
  }
  timeout           = 900
  memory_size       = 512
  retention_in_days = var.app_env == "Prod" ? 30 : 7
  enable_dynatrace  = false # var.app_env == "Prod"
}
