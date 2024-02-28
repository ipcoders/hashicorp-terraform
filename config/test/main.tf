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

resource "local_file" "foo" {
  content  = "Jenkins Demo for Tony and Nathaniel"
  filename = "hello.txt"
}
