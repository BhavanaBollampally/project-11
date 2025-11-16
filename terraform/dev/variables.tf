# variables.tf — Project-11 common variables

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "project" {
  description = "Project name prefix"
  type        = string
  default     = "project11"
}

variable "env" {
  description = "Environment (dev/prod)"
  type        = string
  default     = "dev"
}

variable "s3_logs_bucket" {
  description = "Main logs S3 bucket name"
  type        = string
  default     = "bhavana-p11-logs-dev-bhv123"
}

variable "monitor_bucket" {
  description = "External monitor bucket name used by monitor.sh (if different)"
  type        = string
  default     = "bhavana-monitor-logs"
}

variable "key_name" {
  description = "EC2 keypair name (exists in AWS)"
  type        = string
  default     = "bhavana-key"
}

variable "private_key_path" {
  description = "Local path to private key used for provisioner connection"
  type        = string
  default     = "/home/bhavana/bhavana-key.pem"
}

variable "ami" {
  description = "AMI id for EC2"
  type        = string
  default     = "ami-0dee22c13ea7a9a67"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "lambda_timeout" {
  description = "Lambda timeout (seconds)"
  type        = number
  default     = 15
}

variable "alerts_email" {
  description = "Email for SNS alerts"
  type        = string
  default     = "bhavanabollampally3@gmail.com"
}

# Glue & Athena related variables
variable "glue_database_name" {
  description = "Glue database name"
  type        = string
  default     = "project11_logs_db"
}

variable "raw_prefix" {
  description = "S3 prefix where raw CloudTrail logs are stored"
  type        = string
  default     = "raw/"
}

variable "processed_prefix" {
  description = "S3 prefix for processed logs"
  type        = string
  default     = "processed/"
}

variable "archived_prefix" {
  description = "S3 prefix for archived logs"
  type        = string
  default     = "archived/"
}

variable "athena_results_prefix" {
  description = "S3 prefix for Athena query results"
  type        = string
  default     = "athena-results/"
}

variable "glue_role_name" {
  description = "Name of the Glue service role"
  type        = string
  default     = "project11-glue-service-role-v2"
}
