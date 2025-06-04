variable "aws_region" {
  default = "us-east-1"
}

variable "ssh_key_name" {
  description = "Name of the SSH key to use for EC2"
  type        = string
  default     = "keypair"
}

variable "my_ip_cidr" {
  description = "Your IP in CIDR notation (for SSH access)"
  type        = string
  default     = "83.20.251.151/32"
}

variable "ec2_ami_id" {
  description = "AMI ID for EC2 (Amazon Linux 2)"
  type        = string
  default     = "ami-0554aa6767e249943"
}

variable "eks_version" {
  type    = string
  default = "1.29"
}
