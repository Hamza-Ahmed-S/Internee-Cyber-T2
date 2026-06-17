terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state is recommended for real deployments. Configure and uncomment:
  #
  # backend "s3" {
  #   bucket         = "internee-terraform-state"
  #   key            = "prod/cloud-security.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "internee-terraform-locks"
  #   encrypt        = true
  # }
}
