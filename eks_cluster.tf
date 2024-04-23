resource "aws_cloudwatch_log_group" "example" {
  name              = "/aws/eks/${local.cluster_name}/cluster"
  retention_in_days = 7
  skip_destroy      = false

  tags = {
    Name    = "/aws/eks/${local.cluster_name}/cluster"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

data "aws_iam_policy_document" "eks-cluster" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
    sid = "EKSClusterAssumeRole"
  }
}

resource "aws_iam_role" "eks-cluster" {
  name                  = "${local.cluster_name}-cluster"
  assume_role_policy    = data.aws_iam_policy_document.eks-cluster.json
  force_detach_policies = true
  max_session_duration  = 3600

  inline_policy {
    name = "${local.cluster_name}-cluster"
    policy = jsonencode(
      {
        Statement = [
          {
            Action = [
              "logs:CreateLogGroup",
            ]
            Effect   = "Deny"
            Resource = "*"
          },
        ]
        Version = "2012-10-17"
      }
    )
  }

  tags = {
    Name    = "tf-${var.use_case}-iam-role-eks-cluster-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

data "aws_iam_policy_document" "kms-encryption-key" {
  statement {
    actions = [
      "kms:CancelKeyDeletion",
      "kms:Create*",
      "kms:Delete*",
      "kms:Describe*",
      "kms:Disable*",
      "kms:Enable*",
      "kms:Get*",
      "kms:List*",
      "kms:Put*",
      "kms:Revoke*",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:Update*",
    ]
    resources = ["*"]
    sid       = "KeyAdministration"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/tf-dev-administrator-role"]
    }
  }

  statement {
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    sid       = "KeyUsage"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.eks-cluster.arn]
    }
  }
}

resource "aws_kms_key" "kms-encryption-key" {
  description         = "${local.cluster_name} cluster encryption key"
  enable_key_rotation = true
  is_enabled          = true

  policy = data.aws_iam_policy_document.kms-encryption-key.json

  tags = {
    Name    = "tf-${var.use_case}-kms-encryption-key-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_kms_alias" "example" {
  name          = "alias/eks/${local.cluster_name}"
  target_key_id = aws_kms_key.kms-encryption-key.id
}

resource "aws_iam_policy" "cluster_encryption" {
  name_prefix = "${local.cluster_name}-cluster-ClusterEncryption"
  description = "Cluster encryption policy to allow cluster role to utilize CMK provided"
  path        = "/"
  policy = jsonencode({
    Statement : [
      {
        Action : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ListGrants",
          "kms:DescribeKey"
        ],
        Effect : "Allow",
        Resource : aws_kms_key.kms-encryption-key.arn
      }
    ],
    Version : "2012-10-17"
  })

  tags = {
    Name    = "tf-${var.use_case}-iam-policy-cluster-encryption-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_iam_role_policy_attachment" "cluster_encryption" {
  policy_arn = aws_iam_policy.cluster_encryption.arn
  role       = aws_iam_role.eks-cluster.name
}

data "aws_iam_policy" "eks-cluster-policy" {
  name = "AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks-cluster-policy" {
  policy_arn = data.aws_iam_policy.eks-cluster-policy.arn
  role       = aws_iam_role.eks-cluster.name
}

data "aws_iam_policy" "eks-cluster-resource-controller" {
  name = "AmazonEKSVPCResourceController"
}

resource "aws_iam_role_policy_attachment" "eks-cluster-resource-controller" {
  policy_arn = data.aws_iam_policy.eks-cluster-resource-controller.arn
  role       = aws_iam_role.eks-cluster.name
}

resource "aws_security_group" "eks-cluster" {
  name                   = "${local.cluster_name}-cluster"
  description            = "EKS cluster security group"
  revoke_rules_on_delete = false
  vpc_id                 = aws_vpc.example.id

  tags = {
    Name    = "tf-${var.use_case}-sg-eks-cluster-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_security_group" "eks-node" {
  description            = "EKS node shared security group"
  name                   = "${local.cluster_name}-node"
  revoke_rules_on_delete = false
  vpc_id                 = aws_vpc.example.id

  tags = {
    Name                                          = "${local.cluster_name}-node",
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
    Owner                                         = "John Ajera"
    UseCase                                       = var.use_case
  }
}

resource "aws_security_group_rule" "eks-cluster-api" {
  description              = "Node groups to cluster API"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-cluster.id
  source_security_group_id = aws_security_group.eks-node.id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-egress" {
  description = "Allow all egress"
  from_port   = 0
  cidr_blocks = [
    "0.0.0.0/0",
  ]
  prefix_list_ids   = []
  protocol          = "-1"
  security_group_id = aws_security_group.eks-node.id
  to_port           = 0
  type              = "egress"
}

resource "aws_security_group_rule" "eks-node-api" {
  description              = "Cluster API to node groups"
  from_port                = 443
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-node.id
  source_security_group_id = aws_security_group.eks-cluster.id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-4443-tcp" {
  description              = "Cluster API to node 4443/tcp webhook"
  from_port                = 4443
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-node.id
  source_security_group_id = aws_security_group.eks-cluster.id
  to_port                  = 4443
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-6443-tcp" {
  description              = "Cluster API to node 6443/tcp webhook"
  from_port                = 6443
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-node.id
  source_security_group_id = aws_security_group.eks-cluster.id
  to_port                  = 6443
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-8443-tcp" {
  description              = "Cluster API to node 8443/tcp webhook"
  from_port                = 8443
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-node.id
  source_security_group_id = aws_security_group.eks-cluster.id
  to_port                  = 8443
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-9443-tcp" {
  description              = "Cluster API to node 9443/tcp webhook"
  from_port                = 9443
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-node.id
  source_security_group_id = aws_security_group.eks-cluster.id
  to_port                  = 9443
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-kubelets" {
  description              = "Cluster API to node kubelets"
  from_port                = 10250
  prefix_list_ids          = []
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks-node.id
  source_security_group_id = aws_security_group.eks-cluster.id
  to_port                  = 10250
  type                     = "ingress"
}

resource "aws_security_group_rule" "eks-node-ephemeral" {
  description       = "Node to node ingress on ephemeral ports"
  from_port         = 1025
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.eks-node.id
  self              = true
  to_port           = 65535
  type              = "ingress"
}

resource "aws_security_group_rule" "eks-node-coredns-tcp" {
  description       = "Node to node CoreDNS TCP"
  from_port         = 53
  prefix_list_ids   = []
  protocol          = "tcp"
  security_group_id = aws_security_group.eks-node.id
  self              = true
  to_port           = 53
  type              = "ingress"
}

resource "aws_security_group_rule" "eks-node-coredns-udp" {
  description       = "Node to node CoreDNS UDP"
  from_port         = 53
  prefix_list_ids   = []
  protocol          = "udp"
  security_group_id = aws_security_group.eks-node.id
  self              = true
  to_port           = 53
  type              = "ingress"
}

resource "aws_eks_cluster" "example" {
  name     = local.cluster_name
  role_arn = aws_iam_role.eks-cluster.arn
  enabled_cluster_log_types = [
    "audit", "api", "authenticator"
  ]

  encryption_config {
    resources = [
      "secrets"
    ]

    provider {
      key_arn = aws_kms_key.kms-encryption-key.arn
    }
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.20.0.0/16"
  }

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = true

    public_access_cidrs = [
      "0.0.0.0/0"
    ]

    security_group_ids = [
      aws_security_group.eks-cluster.id
    ]

    subnet_ids = concat(
      [for s in aws_subnet.private : s.id]
    )
  }

  tags = {
    Name    = "tf-${var.use_case}-eks-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks-cluster-policy,
    aws_iam_role_policy_attachment.cluster_encryption,
    aws_security_group_rule.eks-cluster-api,
    aws_security_group_rule.eks-node-egress,
    aws_security_group_rule.eks-node-api,
    aws_security_group_rule.eks-node-4443-tcp,
    aws_security_group_rule.eks-node-6443-tcp,
    aws_security_group_rule.eks-node-8443-tcp,
    aws_security_group_rule.eks-node-9443-tcp,
    aws_security_group_rule.eks-node-kubelets,
    aws_security_group_rule.eks-node-ephemeral,
    aws_security_group_rule.eks-node-coredns-tcp,
    aws_security_group_rule.eks-node-coredns-udp,
    aws_cloudwatch_log_group.example
  ]
}

resource "time_sleep" "example" {
  create_duration = "30s"
  triggers = {
    cluster_certificate_authority_data = try(aws_eks_cluster.example.certificate_authority[0].data, {})
    cluster_endpoint                   = aws_eks_cluster.example.endpoint
    cluster_name                       = aws_eks_cluster.example.name
    cluster_service_cidr               = try(aws_eks_cluster.example.kubernetes_network_config[0].service_ipv4_cidr, {})
    cluster_version                    = aws_eks_cluster.example.version
  }
}

data "tls_certificate" "example" {
  url = aws_eks_cluster.example.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "example" {

  client_id_list = [
    "sts.amazonaws.com",
  ]

  thumbprint_list = [for cert in data.tls_certificate.example.certificates : cert.sha1_fingerprint]

  url = aws_eks_cluster.example.identity[0].oidc[0].issuer

  tags = {
    "Name" : "${local.cluster_name}-irsa"
  }
}

resource "aws_iam_role" "eks-nodes-1" {
  name_prefix = "node-group-1-eks-node-group-"
  description = "EKS managed node group IAM role"

  assume_role_policy = jsonencode(
    {
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
          Sid = "EKSNodeAssumeRole"
        },
      ]
      Version = "2012-10-17"
    }
  )

  force_detach_policies = true
  max_session_duration  = 3600

  tags = {
    Name    = "tf-${var.use_case}-iam-role-eks-node-1-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

data "aws_iam_policy" "eks-nodes-1-ec2-container-registry" {
  name = "AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "eks-nodes-1-ec2-container-registry" {
  policy_arn = data.aws_iam_policy.eks-nodes-1-ec2-container-registry.arn
  role       = aws_iam_role.eks-nodes-1.name
}

data "aws_iam_policy" "eks-nodes-1-eks-worker-node" {
  name = "AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks-nodes-1-eks-worker-node" {
  policy_arn = data.aws_iam_policy.eks-nodes-1-eks-worker-node.arn
  role       = aws_iam_role.eks-nodes-1.name
}

data "aws_iam_policy" "eks-nodes-1-cni" {
  name = "AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks-nodes-1-cni" {
  policy_arn = data.aws_iam_policy.eks-nodes-1-cni.arn
  role       = aws_iam_role.eks-nodes-1.name
}

resource "aws_launch_template" "eks-nodes-1" {
  name_prefix            = "one-"
  description            = "Custom launch template for node-group-1 EKS managed node group"
  update_default_version = true
  vpc_security_group_ids = [
    aws_security_group.eks-node.id
  ]

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      "Name" = "node-group-1"
    }
  }

  tag_specifications {
    resource_type = "network-interface"
    tags = {
      "Name" = "node-group-1"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      "Name" = "node-group-1"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.example,
    aws_eks_cluster.example,
    aws_iam_role_policy_attachment.eks-nodes-1-ec2-container-registry,
    aws_iam_role_policy_attachment.eks-nodes-1-eks-worker-node,
    aws_security_group.eks-cluster,
    aws_subnet.private,
    aws_vpc.example
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name    = "tf-${var.use_case}-lt-eks-node-1-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_eks_node_group" "eks-nodes-1" {
  cluster_name = aws_eks_cluster.example.name
  ami_type     = "AL2_x86_64"

  instance_types = [
    "t3.small",
  ]

  node_group_name_prefix = "node-group-1-"
  node_role_arn          = aws_iam_role.eks-nodes-1.arn

  subnet_ids = concat(
    [for s in aws_subnet.private : s.id]
  )

  launch_template {
    id      = aws_launch_template.eks-nodes-1.id
    version = aws_launch_template.eks-nodes-1.latest_version
  }

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  update_config {
    max_unavailable_percentage = 33
  }

  tags = {
    Name    = "tf-${var.use_case}-eks-node-group-1-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }

  depends_on = [
    time_sleep.example
  ]
}

resource "aws_iam_role" "eks-nodes-2" {
  name_prefix = "node-group-2-eks-node-group-"
  description = "EKS managed node group IAM role"

  assume_role_policy = jsonencode(
    {
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
          Sid = "EKSNodeAssumeRole"
        },
      ]
      Version = "2012-10-17"
    }
  )

  force_detach_policies = true
  max_session_duration  = 3600

  tags = {
    Name    = "tf-${var.use_case}-iam-role-eks-node-2-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

data "aws_iam_policy" "eks-nodes-2-ec2-container-registry" {
  name = "AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "eks-nodes-2-ec2-container-registry" {
  policy_arn = data.aws_iam_policy.eks-nodes-2-ec2-container-registry.arn
  role       = aws_iam_role.eks-nodes-2.name
}

data "aws_iam_policy" "eks-nodes-2-eks-worker-node" {
  name = "AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks-nodes-2-eks-worker-node" {
  policy_arn = data.aws_iam_policy.eks-nodes-2-eks-worker-node.arn
  role       = aws_iam_role.eks-nodes-2.name
}

data "aws_iam_policy" "eks-nodes-2-cni" {
  name = "AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks-nodes-2-cni" {
  policy_arn = data.aws_iam_policy.eks-nodes-2-cni.arn
  role       = aws_iam_role.eks-nodes-2.name
}

resource "aws_launch_template" "eks-nodes-2" {
  name_prefix            = "two-"
  description            = "Custom launch template for node-group-2 EKS managed node group"
  update_default_version = true
  vpc_security_group_ids = [
    aws_security_group.eks-node.id
  ]

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      "Name" = "node-group-2"
    }
  }

  tag_specifications {
    resource_type = "network-interface"
    tags = {
      "Name" = "node-group-2"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      "Name" = "node-group-2"
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name    = "tf-${var.use_case}-lt-eks-node-2-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks-nodes-2-eks-worker-node,
    aws_iam_role_policy_attachment.eks-nodes-2-ec2-container-registry,
    aws_security_group.eks-cluster,
    aws_subnet.private,
    aws_vpc.example
  ]
}

resource "aws_eks_node_group" "eks-nodes-2" {
  cluster_name = aws_eks_cluster.example.name
  ami_type     = "AL2_x86_64"

  instance_types = [
    "t3.small",
  ]

  node_group_name_prefix = "node-group-2-"
  node_role_arn          = aws_iam_role.eks-nodes-2.arn

  subnet_ids = concat(
    [for s in aws_subnet.private : s.id]
  )

  launch_template {
    id      = aws_launch_template.eks-nodes-2.id
    version = aws_launch_template.eks-nodes-2.latest_version
  }

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  timeouts {}

  update_config {
    max_unavailable_percentage = 33
  }

  tags = {
    Name    = "tf-${var.use_case}-eks-node-group-2-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }

  depends_on = [
    time_sleep.example
  ]
}

data "aws_eks_addon_version" "latest" {
  addon_name         = "aws-ebs-csi-driver"
  kubernetes_version = aws_eks_cluster.example.version
  most_recent        = true
}

resource "aws_eks_addon" "ebs-csi" {
  addon_name    = data.aws_eks_addon_version.latest.addon_name
  addon_version = data.aws_eks_addon_version.latest.version
  cluster_name  = aws_eks_cluster.example.name

  service_account_role_arn = aws_iam_role.eks-cluster.arn

  tags = {
    "eks_addon" = "ebs-csi"
    "terraform" = "true"
  }

  depends_on = [
    aws_eks_node_group.eks-nodes-1,
    aws_eks_node_group.eks-nodes-2
  ]
}
