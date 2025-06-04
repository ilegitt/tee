terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

#
# VPC
#
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "4.0.0"

  name = "eks-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = {
    Name = "eks-vpc"
  }
}

#
# IAM Role for EC2 Bastion (to access EKS)
#
resource "aws_iam_role" "ec2_eks_access_role" {
  name = "ec2-eks-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.ec2_eks_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "ecr_readonly" {
  role       = aws_iam_role.ec2_eks_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs" {
  role       = aws_iam_role.ec2_eks_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.ec2_eks_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_policy" "eks_describe_cluster_policy" {
  name        = "eks-describe-cluster-policy"
  description = "Allow EKS DescribeCluster action"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["eks:DescribeCluster"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy_attachment" "attach_describe_cluster_policy" {
  name       = "attach-describe-cluster-policy"
  policy_arn = aws_iam_policy.eks_describe_cluster_policy.arn
  roles      = [aws_iam_role.ec2_eks_access_role.name]
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-eks-access-instance-profile"
  role = aws_iam_role.ec2_eks_access_role.name
}

#
# EKS Cluster (module 18.x supports `map_roles`)
#
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "18.31.2"

  cluster_name    = "secure-cluster"
  cluster_version = var.eks_version

  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = false

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  # Managed Node Group (still compatible with v18.x syntax)
  eks_managed_node_groups = {
    default = {
      desired_size   = 1
      max_size       = 2
      min_size       = 1
      instance_types = ["t3.medium"]
      subnet_ids     = module.vpc.private_subnets
    }
  }

  # Map the EC2 bastion role to system:masters
  manage_aws_auth_configmap = true

  map_roles = [
    {
      rolearn  = aws_iam_role.ec2_eks_access_role.arn
      username = "ec2-bastion"
      groups   = ["system:masters"]
    }
  ]

  tags = {
    Environment = "production"
    Name        = "secure-cluster"
  }
}

#
# Security Group for Bastion
#
resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg"
  description = "Allow SSH access from my IP"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion-sg"
  }
}

#
# EC2 Bastion Host (with IAM instance profile)
#
resource "aws_instance" "bastion" {
  ami                         = var.ec2_ami_id
  instance_type               = "t3.micro"
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  key_name                    = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail

    yum update -y
    yum install -y curl unzip bash-completion jq

    # Install AWS CLI v2
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install

    # Install kubectl matching cluster version
    curl -LO "https://dl.k8s.io/release/v${var.eks_version}/bin/linux/amd64/kubectl"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/

    # Set up kubeconfig for the bastion
    mkdir -p /home/ec2-user/.kube
    chown ec2-user:ec2-user /home/ec2-user/.kube

    CLUSTER_NAME="secure-cluster"
    REGION="${var.aws_region}"
    ENDPOINT=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION \
               --query "cluster.endpoint" --output text)
    CERT=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION \
             --query "cluster.certificateAuthority.data" --output text)

    cat <<CONFIG > /home/ec2-user/.kube/config
apiVersion: v1
clusters:
- cluster:
    server: $ENDPOINT
    certificate-authority-data: $CERT
  name: eks
contexts:
- context:
    cluster: eks
    user: aws
  name: eks
current-context: eks
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws
      args:
        - "eks"
        - "get-token"
        - "--cluster-name"
        - "$CLUSTER_NAME"
CONFIG

    chown ec2-user:ec2-user /home/ec2-user/.kube/config
  EOF

  tags = {
    Name = "eks-bastion"
  }
}

#
# Outputs
#
output "ec2_eks_access_role_arn" {
  value = aws_iam_role.ec2_eks_access_role.arn
}

output "cluster_name" {
  value = module.eks.cluster_id
}

output "kubeconfig_certificate_authority_data" {
  value = module.eks.cluster_certificate_authority_data
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "bastion_private_ip" {
  value = aws_instance.bastion.private_ip
}

output "bastion_ssh_command" {
  value = "ssh -i keypair.pem ec2-user@${aws_instance.bastion.private_ip}"
}

output "bastion_public_ip" {
  value = aws_instance.bastion.public_ip
}

output "vpc_id" {
  value = module.vpc.vpc_id
}
