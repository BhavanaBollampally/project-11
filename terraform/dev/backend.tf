terraform {
  backend "s3" {
    bucket         = "bhavana-p11-terraform-state-bhv123"
    key            = "dev/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "p11-tf-locks"
    encrypt        = true
  }
}
