terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.22"
    }
    ns1 = {
      source  = "ns1-terraform/ns1"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

locals {
  vpc_cidr              = "172.16.254.0/23"
  domain                = "netbox-ecs.pcigdc.com"
  netbox_docker_version = "v3.6.4-2.7.0"
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.1"

  name                = "netbox"
  cidr                = local.vpc_cidr
  azs                 = slice(data.aws_availability_zones.available.names, 0, 2)
  private_subnets     = [cidrsubnet(local.vpc_cidr, 3, 0), cidrsubnet(local.vpc_cidr, 3, 1)]
  public_subnets      = [cidrsubnet(local.vpc_cidr, 3, 2), cidrsubnet(local.vpc_cidr, 3, 3)]
  elasticache_subnets = [cidrsubnet(local.vpc_cidr, 3, 4), cidrsubnet(local.vpc_cidr, 3, 5)]
  database_subnets    = [cidrsubnet(local.vpc_cidr, 3, 6), cidrsubnet(local.vpc_cidr, 3, 7)]

  single_nat_gateway = true

  default_security_group_ingress = [
    {
      self = true
    },
  ]
  default_security_group_egress = [
    {
      self = true
    },
  ]
}

module "db_password" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 1.1"

  name_prefix = "netbox-db-password-"

  create_random_password           = true
  random_password_override_special = ""

  block_public_policy     = true
  recovery_window_in_days = 7
}

data "aws_secretsmanager_secret_version" "db_password" {
  secret_id  = module.db_password.secret_id
  version_id = module.db_password.secret_version_id
}

module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.2"

  identifier = "netbox"

  engine            = "postgres"
  family            = "postgres15"
  instance_class    = "db.t4g.micro"
  storage_type      = "gp3"
  allocated_storage = 20

  availability_zone  = module.vpc.azs[0]
  maintenance_window = "Mon:00:00-Mon:01:00"

  username                            = "netbox"
  password                            = data.aws_secretsmanager_secret_version.db_password.secret_string
  db_name                             = "netbox"
  manage_master_user_password         = false
  iam_database_authentication_enabled = false

  skip_final_snapshot    = true
  create_db_option_group = false

  parameters = [
    {
      name  = "rds.force_ssl"
      value = "0" # Netbox in App mode can't access /root/.postgresql/postgresql.crt so it disables SSL
    },
  ]

  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [module.vpc.default_security_group_id]
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "netbox"
  engine               = "redis"
  node_type            = "cache.t4g.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"

  availability_zone  = module.vpc.azs[0]
  maintenance_window = "Mon:00:00-Mon:01:00"

  subnet_group_name  = module.vpc.elasticache_subnet_group_name
  security_group_ids = [module.vpc.default_security_group_id]
}

data "ns1_zone" "pcigdc_com" {
  zone = "pcigdc.com"
}

module "ssl_cert" {
  source  = "terraform-aws-modules/acm/aws"
  version = "~> 5.0"

  domain_name = local.domain
  zone_id     = data.ns1_zone.pcigdc_com.zone

  create_route53_records  = false
  validation_method       = "DNS"
  validation_record_fqdns = ns1_record.ssl_cert_validation[*].domain
}

resource "ns1_record" "ssl_cert_validation" {
  count = length(module.ssl_cert.distinct_domain_names)

  use_client_subnet = false

  zone   = data.ns1_zone.pcigdc_com.zone
  domain = trimsuffix(module.ssl_cert.validation_domains[count.index]["resource_record_name"], ".")
  type   = module.ssl_cert.validation_domains[count.index]["resource_record_type"]
  ttl    = 60

  answers {
    answer = module.ssl_cert.validation_domains[count.index]["resource_record_value"]
  }
}

module "lb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 9.0"

  name    = "netbox"
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  security_groups = [module.vpc.default_security_group_id]
  security_group_ingress_rules = {
    "allow-http/tcp" = {
      ip_protocol = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
      from_port   = 80
      to_port     = 80
    }
    "allow-https/tcp" = {
      ip_protocol = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
      from_port   = 443
      to_port     = 443
    }
  }

  listeners = {
    http-https-redirect = {
      port     = 80
      protocol = "HTTP"

      redirect = {
        port        = 443
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    https = {
      port            = 443
      protocol        = "HTTPS"
      certificate_arn = module.ssl_cert.acm_certificate_arn

      forward = {
        target_group_key = "instance"
      }
    }
  }

  target_groups = {
    instance = {
      create_attachment = false
      target_type       = "ip"
      backend_protocol  = "HTTP"
      backend_port      = 80
    }
  }
}

module "secret_key" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 1.1"

  name_prefix = "netbox-secret-key-"

  create_random_password           = true
  random_password_override_special = "!@#$%^&*(-_=+)"
  random_password_length           = 50

  block_public_policy     = true
  recovery_window_in_days = 7
}

module "ecs_cluster" {
  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "~> 5.2"

  cluster_name = "netbox"

  cloudwatch_log_group_retention_in_days = 1
}

module "app" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.2"

  cluster_arn = module.ecs_cluster.arn
  name        = "netbox"

  runtime_platform = {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  assign_public_ip   = true
  enable_autoscaling = false
  security_group_ids = [
    module.vpc.default_security_group_id,
  ]
  security_group_rules = {
    "allow-internet" = { # to fetch image
      type        = "egress"
      protocol    = "all"
      cidr_blocks = ["0.0.0.0/0"]
      from_port   = 0
      to_port     = 0
    }
  }
  subnet_ids = [module.vpc.public_subnets[0]]
  container_definitions = {
    netbox = {
      readonly_root_filesystem = false
      essential                = true
      image                    = "docker.io/netboxcommunity/netbox:${local.netbox_docker_version}"
      port_mappings = [
        { name = "http", containerPort = 8080, protocol = "tcp" },
      ]
      environment = [
        { name = "DB_HOST", value = module.db.db_instance_address },
        { name = "DB_USER", value = "netbox" },
        { name = "DB_NAME", value = "netbox" },
        { name = "REDIS_HOST", value = aws_elasticache_cluster.redis.cache_nodes[0].address },
      ]
      secrets = [
        { name = "DB_PASSWORD", valueFrom = module.db_password.secret_arn },
        { name = "SECRET_KEY", valueFrom = module.secret_key.secret_arn },
      ]
    }
  }
  load_balancer = {
    service = {
      container_name   = "netbox"
      container_port   = 8080
      target_group_arn = module.lb.target_groups["instance"].arn
    }
  }
}

resource "ns1_record" "cname" {
  use_client_subnet = false

  zone   = data.ns1_zone.pcigdc_com.zone
  domain = local.domain
  type   = "CNAME"
  ttl    = 60

  answers {
    answer = module.lb.dns_name
  }
}
