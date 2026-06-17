terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
      # This module operates in two regions, so the caller must pass both a
      # primary and a replica provider configuration.
      configuration_aliases = [aws.primary, aws.replica]
    }
  }
}
