terraform {
  required_providers {
    local = {
      source = "hashicorp/local"
      version = "2.4.1"
    }
  }
}

provider "local" {
  # Configuration options
}

variable "ip_address" {
  type = string
}

resource "local_file" "foo" {
  content  = var.ip_address
  filename = "msg.txt"
}
