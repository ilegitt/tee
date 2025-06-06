############################
# Terraform & Providers
############################
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

############################
# 1) VPC
############################
# Discover the first three AZs in the chosen region so that the
# configuration adapts automatically across regions without hard‑coding.

data "aws_availability_zones" "available" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"

  name = "eks-vpc"
  cidr = "10.0.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  private_subnets = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = {
    Terraform   = "true"
    Environment = "production"
  }
}

############################
# 2) IAM Roles & Policies
############################
# -- Bastion host role (minimal EKS DescribeCluster) --
resource "aws_iam_role" "bastion_access_role" {
  name = "bastion-access-role-v9"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# Grant only DescribeCluster so the bastion can fetch the cluster endpoint/cert
resource "aws_iam_policy" "eks_describe_cluster_policy" {
  name        = "eks-describe-cluster-policy-v9"
  description = "Allow DescribeCluster for generating kubeconfig"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["eks:DescribeCluster"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy_attachment" "bastion_describe_cluster" {
  name       = "attach-bastion-describe-cluster-policy-v9"
  policy_arn = aws_iam_policy.eks_describe_cluster_policy.arn
  roles      = [aws_iam_role.bastion_access_role.name]
}

resource "aws_iam_instance_profile" "bastion_instance_profile" {
  name = "bastion-instance-profile-v9"
  role = aws_iam_role.bastion_access_role.name
}

# -- Worker‑node role (full EKS worker policies) --
resource "aws_iam_role" "eks_worker_role" {
  name = "eks-worker-node-role-v9"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker_node_policies" {
  for_each = {
    eks_worker        = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
    ecr_readonly      = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    cni               = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
    cloudwatch_logs   = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
  }
  role       = aws_iam_role.eks_worker_role.name
  policy_arn = each.value
}

############################
# 3) EKS Control Plane (no node groups yet)
############################
module "eks_control_plane" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.36.0"

  cluster_name    = "secure-cluster-v9"
  cluster_version = var.eks_version

  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  tags = {
    Environment = "production"
    Name        = "secure-cluster-v9"
  }
}

############################
# 4) Data Sources for Kubernetes Provider
############################
data "aws_eks_cluster" "cluster" {
  name       = module.eks_control_plane.cluster_name
  depends_on = [module.eks_control_plane]
}

data "aws_eks_cluster_auth" "cluster" {
  name       = module.eks_control_plane.cluster_name
  depends_on = [module.eks_control_plane]
}

############################
# 5) Kubernetes Provider (auth via token)
############################
provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

############################
# 6) Patch aws‑auth ConfigMap
############################
resource "kubernetes_config_map_v1" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = yamlencode([
      {
        rolearn  = aws_iam_role.eks_worker_role.arn
        username = "system:node:{{EC2PrivateDNSName}}"
        groups   = ["system:bootstrappers", "system:nodes"]
      },
      {
        rolearn  = aws_iam_role.bastion_access_role.arn
        username = "bastion-admin"
        groups   = ["system:masters"]
      },
      {
        rolearn  = "arn:aws:iam::180294207856:role/<your-github-actions-oidc-role>"
        username = "github-actions"
        groups   = ["system:masters"]
      }
    ])
  }

  depends_on = [module.eks_control_plane]
}


############################
# 7) EKS Managed Node Group
############################
resource "aws_eks_node_group" "worker_nodes" {
  cluster_name    = module.eks_control_plane.cluster_name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.eks_worker_role.arn
  subnet_ids      = module.vpc.private_subnets

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]
  version        = var.eks_version
  ami_type       = "AL2023_x86_64_STANDARD"

  depends_on = [kubernetes_config_map_v1.aws_auth]
}

############################
# 8) Bastion Security Group (rules separated)
############################
resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg-v9"
  description = "Security group for bastion host"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = "bastion-sg-v9"
  }
}

resource "aws_security_group_rule" "bastion_ssh_ingress" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.my_ip_cidr]
  security_group_id = aws_security_group.bastion_sg.id
}

resource "aws_security_group_rule" "bastion_all_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.bastion_sg.id
}

##########################
# 9) EC2 Bastion Host (in public subnet with Elastic IP)
##########################
resource "aws_instance" "bastion" {
  ami                         = var.ec2_ami_id
  instance_type               = "t3.micro"
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  key_name                    = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.bastion_instance_profile.name

  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail

    yum update -y
    yum install -y curl unzip bash-completion jq

    # Install AWS CLI v2
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    ./aws/install

    # Install kubectl matching cluster version
    curl -LO "https://dl.k8s.io/release/v${var.eks_version}/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/

    # Generate kubeconfig
    mkdir -p /home/ec2-user/.kube
    chown ec2-user:ec2-user /home/ec2-user/.kube

    CLUSTER_NAME="secure-cluster-v9"
    REGION="${var.aws_region}"
    ENDPOINT=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query "cluster.endpoint" --output text)
    CERT=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query "cluster.certificateAuthority.data" --output text)

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
    Name = "eks-bastion-v9"
  }
}

# Allocate stable Elastic IP for the bastion
resource "aws_eip" "bastion_eip" {
  instance = aws_instance.bastion.id
  vpc      = true
  depends_on = [aws_instance.bastion]
  tags = {
    Name = "bastion-eip-v9"
  }
}

############################
# 10) Outputs
############################
output "bastion_eip" {
  description = "Elastic IP of the bastion host"
  value       = aws_eip.bastion_eip.public_ip
}

output "eks_cluster_name" {
  value = module.eks_control_plane.cluster_name
}

output "kubeconfig_certificate_authority_data" {
  value = data.aws_eks_cluster.cluster.certificate_authority[0].data
}

output "cluster_endpoint" {
  value = data.aws_eks_cluster.cluster.endpoint
}

output "vpc_id" {
  value = module.vpc.vpc_id
}
