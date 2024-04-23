resource "aws_vpc" "example" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"

  tags = {
    Name    = "tf-${var.use_case}-vpc-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_subnet" "private" {
  count                   = length(var.vpc_network.private_subnets)
  vpc_id                  = aws_vpc.example.id
  cidr_block              = var.vpc_network.private_subnets[count.index]
  availability_zone       = element(data.aws_availability_zones.available.names, count.index)
  map_public_ip_on_launch = false

  tags = {
    Name                                          = "tf-${var.use_case}-subnet-private-${element(data.aws_availability_zones.available.names, count.index)}"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
    Owner                                         = "John Ajera"
    UseCase                                       = var.use_case
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.vpc_network.public_subnets)
  vpc_id                  = aws_vpc.example.id
  cidr_block              = var.vpc_network.public_subnets[count.index]
  availability_zone       = element(data.aws_availability_zones.available.names, count.index)
  map_public_ip_on_launch = false

  tags = {
    "Name" : "tf-${var.use_case}-subnet-public-${element(data.aws_availability_zones.available.names, count.index)}"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
    Owner                                         = "John Ajera"
    UseCase                                       = var.use_case
  }
}

resource "aws_default_network_acl" "example" {
  default_network_acl_id = aws_vpc.example.default_network_acl_id

  subnet_ids = concat(
    [for s in aws_subnet.private : s.id],
    [for s in aws_subnet.public : s.id]
  )

  egress {
    action          = "allow"
    from_port       = 0
    ipv6_cidr_block = "::/0"
    protocol        = "-1"
    rule_no         = 101
    to_port         = 0
  }
  egress {
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    protocol   = "-1"
    rule_no    = 100
    to_port    = 0
  }

  ingress {
    action          = "allow"
    from_port       = 0
    ipv6_cidr_block = "::/0"
    protocol        = "-1"
    rule_no         = 101
    to_port         = 0
  }
  ingress {
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    protocol   = "-1"
    rule_no    = 100
    to_port    = 0
  }

  tags = {
    Name    = "tf-${var.use_case}-default-nacl-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_default_route_table" "example" {
  provider = aws

  default_route_table_id = aws_vpc.example.default_route_table_id

  propagating_vgws = []
  route            = []

  timeouts {
    create = "5m"
    update = "5m"
  }

  tags = {
    Name    = "tf-${var.use_case}-default-route-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_internet_gateway" "example" {
  vpc_id = aws_vpc.example.id

  tags = {
    Name    = "tf-${var.use_case}-igw-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_eip" "nat-2" {
  domain = "vpc"

  tags = {
    Name    = "tf-${var.use_case}-eip-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }

  depends_on = [
    aws_vpc.example,
    aws_internet_gateway.example
  ]
}

resource "aws_nat_gateway" "example" {
  allocation_id     = aws_eip.nat-2.id
  connectivity_type = "public"
  subnet_id         = aws_subnet.public[0].id

  tags = {
    Name    = "tf-${var.use_case}-ng-example-${random_string.suffix.result}-${aws_subnet.public[0].availability_zone}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.example.id

  tags = {
    Name    = "tf-${var.use_case}-rt-private-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.example.id

  tags = {
    Name    = "tf-${var.use_case}-rt-public-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}

resource "aws_route" "private_nat_gateway-2" {
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.example.id
  route_table_id         = aws_route_table.private.id

  timeouts {
    create = "5m"
  }
}

resource "aws_route" "public_internet_gateway-2" {
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.example.id
  route_table_id         = aws_route_table.public.id

  timeouts {
    create = "5m"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(var.vpc_network.private_subnets)
  route_table_id = aws_route_table.private.id
  subnet_id      = aws_subnet.private[count.index].id
}

resource "aws_route_table_association" "public" {
  count          = length(var.vpc_network.public_subnets)
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public[count.index].id
}

resource "aws_default_security_group" "example" {
  revoke_rules_on_delete = true
  vpc_id                 = aws_vpc.example.id

  tags = {
    Name    = "tf-${var.use_case}-dsg-example-${random_string.suffix.result}"
    Owner   = "John Ajera"
    UseCase = var.use_case
  }
}
