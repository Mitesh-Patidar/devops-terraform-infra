terraform {
  required_version = ">= 1.0.0"
}

provider "aws" {
  region = "ap-south-1"
}

resource "aws_vpc" "bastion-vpc" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Bastion-VPC"
  }
}

resource "aws_internet_gateway" "bastion_igw" {
  vpc_id = aws_vpc.bastion-vpc.id

  tags = {
    Name = "Bastion-IGW"
  }
}

resource "aws_subnet" "bastion_public_subnet" {
  vpc_id                  = aws_vpc.bastion-vpc.id
  cidr_block              = "192.168.1.0/24"
  availability_zone       = "ap-south-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Bastion-Public-Subnet"
  }
}

resource "aws_route_table" "bastion_public_rt" {
  vpc_id = aws_vpc.bastion-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.bastion_igw.id
  }

  tags = {
    Name = "Bastion-Public-rt"
  }
}

resource "aws_route_table_association" "bastion_public_rta" {
  subnet_id      = aws_subnet.bastion_public_subnet.id
  route_table_id = aws_route_table.bastion_public_rt.id
}

resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg"
  description = "Allow ssh access"
  vpc_id      = aws_vpc.bastion-vpc.id

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["49.36.109.65/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Bastion-SG"
  }
}

resource "aws_instance" "bastion_ec2" {
  ami                    = "ami-0f58b397bc5c1f2e8"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.bastion_public_subnet.id
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  key_name               = "bastion-key"

  tags = {
    Name = "Bastion-Host"
  }
}


resource "aws_vpc" "app_vpc" {
  cidr_block           = "172.32.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "App-VPC"
  }
}

resource "aws_subnet" "app_public_subnet" {
  vpc_id                  = aws_vpc.app_vpc.id
  cidr_block              = "172.32.1.0/24"
  availability_zone       = "ap-south-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "App-Public-subnet"
  }
}

resource "aws_subnet" "app_private_subnet_a" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "172.32.2.0/24"
  availability_zone = "ap-south-1a"

  tags = {
    Name = "App-Private_subnet-A"
  }
}

resource "aws_subnet" "app_private_subnet_b" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "172.32.3.0/24"
  availability_zone = "ap-south-1b"

  tags = {
    Name = "App-private-subnet-b"
  }
}

resource "aws_internet_gateway" "app_igw" {
  vpc_id = aws_vpc.app_vpc.id

  tags = {
    Name = "App-IGW"
  }
}

resource "aws_route_table" "app_public_rt" {
  vpc_id = aws_vpc.app_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.app_igw.id
  }

  tags = {
    Name = "Public-app-rt"
  }
}

resource "aws_route_table_association" "app_public_rta" {
  subnet_id      = aws_subnet.app_public_subnet.id
  route_table_id = aws_route_table.app_public_rt.id
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.app_public_subnet.id

  tags = {
    Name = "NAT-gateway"
  }
}

resource "aws_route_table" "app_private_rt" {
  vpc_id = aws_vpc.app_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }

  tags = {
    Name = "App-Private-rt"
  }
}

resource "aws_route_table_association" "app_private_rta_a" {
  subnet_id      = aws_subnet.app_private_subnet_a.id
  route_table_id = aws_route_table.app_private_rt.id
}

resource "aws_route_table_association" "app_private_rta" {
  subnet_id      = aws_subnet.app_private_subnet_b.id
  route_table_id = aws_route_table.app_private_rt.id
}

resource "aws_ec2_transit_gateway" "tgw" {
  description = "TGW connecting Bastion and App VPCs"

  tags = {
    Name = "Main-Transit-Gateway"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "bastion_attachment" {
  subnet_ids         = [aws_subnet.bastion_public_subnet.id]
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  vpc_id             = aws_vpc.bastion-vpc.id

  tags = {
    Name = "Bastion-TGW-attachment"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "app_attachment" {
  subnet_ids = [
    aws_subnet.app_private_subnet_a.id,
    aws_subnet.app_private_subnet_b.id
  ]
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  vpc_id             = aws_vpc.app_vpc.id

  tags = {
    Name = "App-TGW-Attachment"
  }
}

resource "aws_security_group" "app_sg" {
 name = "app-web-sg"
 vpc_id = aws_vpc.app_vpc.id
 description = "allow traffic for webservers"

  ingress {
    description = "Allow HTTP from Anywhere"
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
     description = "Allow SSH only from Bastion Host"
     from_port = 22
     to_port = 22
     protocol = "tcp"
     cidr_blocks = [aws_subnet.bastion_public_subnet.cidr_block]
  }
  
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "App-Web-SG"
  }
}

resource "aws_launch_template" "web_lt" {
  name_prefix = "web-launch-template-"
  image_id = "ami-0f58b397bc5c1f2e8"
  instance_type = "t2.micro"
  key_name = "bastion-key"
  
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data = base64encode(<<EOF
#!/bin/bash
sudo apt update -y
sudo apt install apache2 -y
echo "Hello from Terraform App Server" > /var/www/html/index.html
sudo systemctl enable apache2
sudo systemctl start apache2
EOF
  )

  iam_instance_profile {
      name = aws_iam_instance_profile.ec2_instance_profile.name
  }

  tag_specifications {
     resource_type = "instance"
     
     tags = {
        Name = "App-web-server"
      }
   }
}

resource "aws_autoscaling_group" "web_asg" {
  desired_capacity = 2
  max_size = 4
  min_size = 2
  vpc_zone_identifier = [
       aws_subnet.app_private_subnet_a.id,
       aws_subnet.app_private_subnet_b.id
   ]
   launch_template {
        id = aws_launch_template.web_lt.id
        version = "$Latest"
    }
   
   target_group_arns = [aws_lb_target_group.web_tg.arn]

   tag {
       key = "Name"
       value = "App-ASG-instance"
       propagate_at_launch = true
     }
}

resource "aws_lb_target_group" "web_tg" {
  name ="web-target-group"
  port = 80
  protocol = "HTTP"
  vpc_id = aws_vpc.app_vpc.id

  health_check {
     path = "/"
     interval = 30
     healthy_threshold = 2
     unhealthy_threshold = 3
     matcher = "200"
   }
}

resource "aws_lb" "web_alb" {
  name = "web-application-lb"
  load_balancer_type = "application"
  security_groups = [aws_security_group.app_sg.id]
  subnets = [aws_subnet.app_public_subnet.id,
             aws_subnet.app_public_subnet_b.id
   ]

  tags = {
    Name = "Web-ALB"
  }
}

resource "aws_lb_listener" "web_listner" {
  load_balancer_arn = aws_lb.web_alb.arn
  port = 80
  protocol ="HTTP"
  
  default_action {
     type = "forward"
     target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

resource "aws_subnet" "app_public_subnet_b" {
  vpc_id = aws_vpc.app_vpc.id
  cidr_block = "172.32.4.0/24"
  availability_zone = "ap-south-1b"
  map_public_ip_on_launch = true
  
  tags = {
     Namw = "Public-subnet-1b"
  }
}

resource "aws_route_table_association" "app_public_rta_b" {
  route_table_id = aws_route_table.app_public_rt.id
  subnet_id = aws_subnet.app_public_subnet_b.id
}

resource "aws_s3_bucket" "app_config_bucket" {
  bucket = "app-config-bucket-mitesh-patidar-ship"

  tags = {
    Name = "app-config-bucket"
  }
}

resource "aws_iam_role" "ec2_instance_role" {
  name = "ec2-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "s3_read_policy" {
  name = "s3-read-access-policy"
  description = " allow read access to app config bucket"
  
  policy = jsonencode({
     Version = "2012-10-17"
     Statement = [{
         Effect = "Allow"
         Action = ["s3:GetObject", "s3:ListBucket"]
         Resource = [
            aws_s3_bucket.app_config_bucket.arn,
            "${aws_s3_bucket.app_config_bucket.arn}/*"
         ]
       }]
     })
}

resource "aws_iam_role_policy_attachment" "attach_s3_policy" {
  role = aws_iam_role.ec2_instance_role.name
  policy_arn = aws_iam_policy.s3_read_policy.arn
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile"
  role = aws_iam_role.ec2_instance_role.name
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 30

  tags = {
    Name = "VPC-FlowLogs-Group"
  }
}

resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "vpc_flow_logs_policy" {
i  name        = "vpc-flow-logs-policy"
  description = "Allow VPC Flow Logs to write to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_vpc_flow_policy" {
  role       = aws_iam_role.vpc_flow_logs_role.name
  policy_arn = aws_iam_policy.vpc_flow_logs_policy.arn
}

resource "aws_flow_log" "app_vpc_flow_logs" {
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow_logs.name
  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.app_vpc.id

  tags = {
    Name = "App-VPC-FlowLogs"
  }
}

 
     
