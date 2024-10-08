import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class ec2(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.security_groups = self.get_security_groups()
        self.network_acls = self.get_network_acls()
        self.network_interfaces = self.get_network_interfaces()
        self.instance_reservations = self.get_instance_reservations()
        self.volumes = self.get_volumes()
        self.snapshots = self.get_snapshots()
        self.vpcs = self.get_vpcs()
        self.vpc_endpoints = self.get_vpc_endpoints()
        self.images = self.get_images()
        self.subnets = self.get_subnets()
        self.transit_gateways = self.get_transit_gateways()
        self.transit_gateway_attachments = self.get_transit_gateway_attachments()
        self.transit_gateway_route_tables = self.get_transit_gateway_route_tables()

    def run(self):
        findings = []
        findings += [ self.ec2_1() ]
        findings += [ self.ec2_2() ]
        findings += [ self.ec2_3() ]
        findings += [ self.ec2_4() ]
        findings += [ self.ec2_5() ]
        findings += [ self.ec2_6() ]
        findings += [ self.ec2_7() ]
        findings += [ self.ec2_8() ]
        findings += [ self.ec2_9() ]
        findings += [ self.ec2_10() ]
        findings += [ self.ec2_11() ]
        findings += [ self.ec2_12() ]
        findings += [ self.ec2_13() ]
        findings += [ self.ec2_14() ]
        findings += [ self.ec2_15() ]
        findings += [ self.ec2_16() ]
        findings += [ self.ec2_17() ]
        findings += [ self.ec2_18() ]
        findings += [ self.ec2_19() ]
        findings += [ self.ec2_20() ]
        findings += [ self.ec2_21() ]
        findings += [ self.ec2_22() ]
        findings += [ self.ec2_23() ]
        findings += [ self.ec2_24() ]
        findings += [ self.ec2_25() ]
        findings += [ self.ec2_26() ]
        findings += [ self.ec2_27() ]
        findings += [ self.ec2_28() ]
        findings += [ self.ec2_29() ]
        findings += [ self.ec2_30() ]
        findings += [ self.ec2_31() ]
        findings += [ self.ec2_32() ]
        findings += [ self.ec2_33() ]
        findings += [ self.ec2_34() ]
        findings += [ self.ec2_35() ]
        findings += [ self.ec2_36() ]
        findings += [ self.ec2_37() ]
        findings += [ self.ec2_38() ]
        findings += [ self.ec2_39() ]
        findings += [ self.ec2_40() ]
        findings += [ self.ec2_41() ]
        findings += [ self.ec2_42() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.ec2_2() ]
        findings += [ self.ec2_4() ]
        findings += [ self.ec2_5() ]
        findings += [ self.ec2_6() ]
        findings += [ self.ec2_7() ]
        findings += [ self.ec2_10() ]
        findings += [ self.ec2_16() ]
        findings += [ self.ec2_17() ]
        findings += [ self.ec2_18() ]
        findings += [ self.ec2_19() ]
        findings += [ self.ec2_21() ]
        findings += [ self.ec2_25() ]
        findings += [ self.ec2_26() ]
        findings += [ self.ec2_28() ]
        findings += [ self.ec2_30() ]
        findings += [ self.ec2_31() ]
        findings += [ self.ec2_32() ]
        findings += [ self.ec2_33() ]
        findings += [ self.ec2_34() ]
        findings += [ self.ec2_35() ]
        return findings

    def get_security_groups(self):
        security_groups = {}
        logging.info("getting security groups")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                security_groups[region] = client.describe_security_groups()["SecurityGroups"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting security groups - %s" % e.response["Error"]["Code"])
        return security_groups
    
    def get_network_acls(self):
        network_acls = {}
        logging.info("getting network acls")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                network_acls[region] = client.describe_network_acls()["NetworkAcls"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting network acls - %s" % e.response["Error"]["Code"])
        return network_acls
    
    def get_network_interfaces(self):
        network_interfaces = {}
        logging.info("getting network interfaces")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                network_interfaces[region] = client.describe_network_interfaces()["NetworkInterfaces"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting network interfaces - %s" % e.response["Error"]["Code"])
        return network_interfaces
    
    def get_instance_reservations(self):
        reservations = {}
        logging.info("getting instance reservations")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                reservations[region] = client.describe_instances()["Reservations"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting instance reservations - %s" % e.response["Error"]["Code"])
        return reservations

    def get_volumes(self):
        volumes = {}
        logging.info("getting ebs volumes")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                volumes[region] = client.describe_volumes()["Volumes"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting ebs volumes - %s" % e.response["Error"]["Code"])
        return volumes
    
    def get_snapshots(self):
        snapshots = {}
        logging.info("getting ebs snapshots")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                snapshots[region] = client.describe_snapshots(OwnerIds=["self"])["Snapshots"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting ebs snapshots - %s" % e.response["Error"]["Code"])
        return snapshots
    
    def get_vpcs(self):
        vpcs = {}
        logging.info("getting vpcs")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                vpcs[region] = client.describe_vpcs()["Vpcs"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting vpcs - %s" % e.response["Error"]["Code"])
        return vpcs
    
    def get_vpc_endpoints(self):
        vpc_endpoints = {}
        logging.info("getting vpc endpoints")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                vpc_endpoints[region] = client.describe_vpc_endpoints()["VpcEndpoints"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting vpc endpoints - %s" % e.response["Error"]["Code"])
        return vpc_endpoints
    

    def get_images(self):
        images = {}
        logging.info("getting ami images")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                images[region] = client.describe_images(Owners=["self"])["Images"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting images - %s" % e.response["Error"]["Code"])
        return images

    def get_subnets(self):
        subnets = {}
        logging.info("getting subnets")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                subnets[region] = client.describe_subnets()["Subnets"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting subnets - %s" % e.response["Error"]["Code"])
        return subnets

    def get_transit_gateways(self):
        transit_gateways = {}
        logging.info("getting transit gateways")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                transit_gateways[region] = client.describe_transit_gateways()["TransitGateways"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting transit gateways - %s" % e.response["Error"]["Code"])
        return transit_gateways

    def get_transit_gateway_attachments(self):
        transit_gateway_attachments = {}
        logging.info("getting transit gateway attachments")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                transit_gateway_attachments[region] = client.describe_transit_gateway_attachments()["TransitGatewayAttachments"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting transit gateway attachments - %s" % e.response["Error"]["Code"])
        return transit_gateway_attachments

    def get_transit_gateway_route_tables(self):
        transit_gateway_route_tables = {}
        logging.info("getting transit gateway route tables")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                transit_gateway_route_tables[region] = client.describe_transit_gateway_route_tables()["TransitGatewayRouteTables"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting transit gateway route tables - %s" % e.response["Error"]["Code"])
        return transit_gateway_route_tables

    def ec2_1(self):
        # Ensure IAM instance roles are used for AWS resource access from instances

        results = {
            "id" : "ec2_1",
            "ref" : "",
            "compliance" : "",
            "level" : "",
            "service" : "ec2",
            "name" : "Ensure IAM instance roles are used for AWS resource access from instances",
            "affected": [],
            "analysis" : "",
            "description" : "AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls or by assigning the instance to a role which has an appropriate permissions policy for the required access. AWS Access means accessing the APIs of AWS in order to access AWS resources or manage AWS account resources. AWS IAM roles reduce the risks associated with sharing and rotating credentials that can be used outside of AWS itself. If credentials are compromised, they can be used from outside of the AWS account they give access to. In contrast, in order to leverage role permissions an attacker would need to gain and maintain access to a specific instance to use the privileges associated with it. Additionally, if credentials are encoded into compiled applications or other hard to change mechanisms, then they are even more unlikely to be properly rotated due to service disruption risks. As time goes on, credentials that cannot be rotated are more likely to be known by an increasing number of individuals who no longer work for the organization owning the credentials",
            "remediation" : "Discontinue the use of hard coded access keys for EC2 instance and use IAM Roles via Instance Profiles instead. IAM roles can only be associated at the launch of an instance. To remediate an instance to add it to a role you must create a new instance.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "running":
                        instance_id = instance["InstanceId"]
                        ec2 = self.session.resource('ec2', region_name=region)
                        ec2_instance = ec2.Instance(id=instance_id)
                        if not ec2_instance.iam_instance_profile:
                            results["affected"].append("{}({})".format(instance_id, region))

        if results["affected"]:
            results["analysis"] = "The affected instances are currently running do not have an instance profile attached"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing instances found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def ec2_2(self):
        # Ensure EBS volume encryption is enabled in all regions

        results = {
            "id" : "ec2_2",
            "ref" : "2.2.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure EBS Volume Encryption is Enabled in all Regions (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported. Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.",
            "remediation" : "Ensure EBS default volume encryption is enabled in all regions",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                if client.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] == False:
                    results["affected"].append(region)
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting encryption informaiton - %s" % e.response["Error"]["Code"])
        
        if results["affected"]:
            results["pass_fail"] = "FAIL"
            if set(results["affected"]) == set(self.regions):
                results["analysis"] = "Default Encryption is not enabled in any region"
            else:
                results["analysis"] = "The affected EC2 regions do not encrypt EBS volumes by default"
        else:
            results["analysis"] = "Default EBS Volume encryption is enabled in all regions"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def ec2_3(self):
        # Ensure VPC flow logging is enabled in all VPCs (Automated)

        results = {
            "id" : "ec2_3",
            "ref" : "",
            "compliance" : "",
            "level" : "",
            "service" : "ec2",
            "name" : "Ensure VPC flow logging is enabled in all VPCs",
            "affected": [],
            "analysis" : "",
            "description" : "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet Rejects for VPCs. VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.",
            "remediation" : "Enable VPC Flow Logs on all VPCs",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                flow_logs = client.describe_flow_logs()["FlowLogs"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting flow logs - %s" % e.response["Error"]["Code"])
            else:
                if not flow_logs:
                    results["affected"].append(region)
            
        if results["affected"]:
            results["pass_fail"] = "FAIL"

            if set(results["affected"]) == set(self.regions):
                results["analysis"] = "VPC Flow logging is not enabled in any region"
            else:
                results["analysis"] = "the affected regions do not have any VPC Flow Logs enabled."
        else:
            results["analysis"] = "Flow Logs are enabled on all VPCs"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_4(self):
        # Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        results = {
            "id" : "ec2_4",
            "ref" : "5.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389. Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, network_acls in self.network_acls.items():
            for acl in network_acls:
                network_acl_id = acl["NetworkAclId"]
                entries = acl["Entries"]
                for entry in entries:
                    if entry["Egress"] == False:
                        if entry["RuleAction"] == "allow":
                            try:
                                cidr_block = entry["CidrBlock"]
                            except KeyError:
                                cidr_block = False
                            try:
                                ipv6cidr_block = entry["Ipv6CidrBlock"]
                            except KeyError:
                                ipv6cidr_block = False
                            
                            if cidr_block == "0.0.0.0/0" or ipv6cidr_block == "::/0":
                                try:
                                    from_port = entry["PortRange"]["From"]
                                    to_port = entry["PortRange"]["To"]
                                except KeyError:
                                    # NACLs with no port range defined allow all ports
                                    results["affected"].append("{}({})".format(network_acl_id, region))
                                else:
                                    if from_port in (22, 3389) or 22 in range(from_port, to_port) or 3389 in range(from_port, to_port):
                                        results["affected"].append("{}({})".format(network_acl_id, region))

        if results["affected"]:
            results["analysis"] = "the affected Network ACLs allow admin ingress traffic from 0.0.0.0/0."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No NACLs that allow remote server administration ingress traffic from 0.0.0.0/0 found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def ec2_5(self):
        # Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        results = {
            "id" : "ec2_5",
            "ref" : "5.2",
            "compliance" : "cis",
            "level" : 1, 
            "service" : "ec2",
            "name" : "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389 . Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # get unused security groups

        unused_groups = []

        for region, groups in self.security_groups.items():

            attached_security_group_ids = []
            network_interfaces = self.network_interfaces[region]
            for interface in network_interfaces:
                for group in interface["Groups"]:
                    attached_security_group_ids.append(group["GroupId"])

            for group in groups:
                if group["GroupName"] != "default":
                    if group["GroupId"] not in attached_security_group_ids:
                        unused_groups.append(group["GroupId"])
            
        for region, groups in self.security_groups.items():
            for group in groups:
                group_id = group["GroupId"]
                ip_permissions = group["IpPermissions"]
                for ip_permission in ip_permissions:

                    # ipv4
                    if "IpRanges" in ip_permission:
                        for ip_range in ip_permission["IpRanges"]:
                            if ip_range["CidrIp"] == "0.0.0.0/0":
                                try:
                                    from_port = ip_permission["FromPort"]
                                    to_port = ip_permission["ToPort"]
                                except KeyError:
                                    # if no port range is defined, all ports are allowed
                                    if group_id not in unused_groups:
                                        results["affected"].append("{}({})".format(group_id, region))
                                else:
                                    if from_port == 22 or from_port == 3389 or 22 in range(from_port, to_port) or 3389 in range(from_port, to_port):            
                                        if group_id not in unused_groups:
                                            results["affected"].append("{}({})".format(group_id, region))

        if results["affected"]:
            results["analysis"] = "the affected security groups allow admin ingress traffic from 0.0.0.0/0."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No security groups that allow remote server administration ingress traffic from 0.0.0.0/0 found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    
    def ec2_6(self):
        # Ensure the default security group of every VPC restricts all traffic (Automated)

        results = {
            "id" : "ec2_6",
            "ref" : "5.4",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure the default security group of every VPC restricts all traffic (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group when you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic. The default VPC in every region should have its default security group updated to comply. Any newly created VPCs will automatically contain a default security group that will need remediation to comply with this recommendation. NOTE: When implementing this recommendation, VPC flow logging is invaluable in determining the least privilege port access required by systems to work properly because it can log all packet acceptances and rejections occurring under the current security groups. This dramatically reduces the primary barrier to least privilege engineering - discovering the minimum ports required by systems in the environment. Even if the VPC flow logging recommendation in this benchmark is not adopted as a permanent security measure, it should be used during any period of discovery and engineering for least privileged security groups. Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources.",
            "remediation" : "Configure default security groups in all VPCs to be default deny and restrict all traffic",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, groups in self.security_groups.items():
            for group in groups:
                group_id = group["GroupId"]
                if group["GroupName"] == "default":
                    if group["IpPermissions"]:
                        results["affected"].append("{}({})".format(group_id, region))
                    
        if results["affected"]:
            results["analysis"] = "The affected default security groups have inbound rules configured."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Default security groups restrict all traffic"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def ec2_7(self):
        # Ensure routing tables for VPC peering are "least access"

        results = {
            "id" : "ec2_7",
            "ref" : "5.5",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure routing tables for VPC peering are least access (CIS)(Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "Once a VPC peering connection is established, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection. Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.",
            "remediation" : "Configure routing tables for VPC perring following the principle of least access",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                route_tables = client.describe_route_tables()["RouteTables"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting route tables - %s" % e.response["Error"]["Code"])
            else:
                for route_table in route_tables:
                    for route in route_table["Routes"]:
                        if "VpcPeeringConnectionId" in route:
                            results["affected"].append("{}({})".format(route["VpcPeeringConnectionId"], region))
                    
        if results["affected"]:
            results["analysis"] = "VPC peering in use - check affected routing tables for least access"
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "VPC Peering not in use"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results



    def ec2_8(self):
        # Unused Security Groups

        results = {
            "id" : "ec2_8",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Unused Security Groups",
            "affected": [],
            "analysis" : "",
            "description" : "The affected security groups have not been applied to any instances and therefore not in use. To maintain the hygiene of the environment, make maintenance and auditing easier and reduce the risk of security groups erroneously being used and inadvertently granting more access than required, all old unused security groups should be removed.",
            "remediation" : "Ensure all security groups that are temporary and not being used are deleted when no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, groups in self.security_groups.items():

            attached_security_group_ids = []
            network_interfaces = self.network_interfaces[region]
            for interface in network_interfaces:
                for group in interface["Groups"]:
                    attached_security_group_ids.append(group["GroupId"])

            for group in groups:
                if group["GroupName"] != "default":
                    if group["GroupId"] not in attached_security_group_ids:
                        results["affected"].append("{}({})".format(group["GroupId"], region))


        ### more elegant but slower way ###
        #    
        #for region, groups in self.security_groups.items():
        #    client = self.session.client('ec2', region_name=region)
        #    for group in groups:
        #        if group["GroupName"] != "default":
        #            group_id = group["GroupId"]
        #            network_interfaces = client.describe_network_interfaces(Filters=[{ "Name": "group-id", "Values" : [group_id] }])["NetworkInterfaces"]
        #            if not network_interfaces:
        #                results["affected"] += ["{}({})".format(group_id, region)]

        if results["affected"]:
            results["analysis"] = "The affected security groups are not attached to any resources and therefore are not being used"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused security groups found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results
    
    def ec2_9(self):
        # Unused elastic IPs

        results = {
            "id" : "ec2_9",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Unused Elastic IPs",
            "affected": [],
            "analysis" : "",
            "description" : "Although not a security risk, Amazon Web Services enforce a small hourly charge if an Elastic IP (EIP) address within your account is not associated with a running EC2 instance or an Elastic Network Interface (ENI). To ensure account hygiene and saves costs on your month bill it is recommended to release any elastic IPs that are no longer required.",
            "remediation" : "To release an Elastic IP address using the console: 1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/. 2. In the navigation pane, choose Elastic IPs. 3. Select the Elastic IP address, choose Actions, and then select Release addresses. Choose Release when prompted. More information: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            try:
                addresses = client.describe_addresses()["Addresses"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting public ips - %s" % e.response["Error"]["Code"])
            else:
                results["affected"] += ["{}({})".format(address["PublicIp"], region) for address in addresses if "AssociationId" not in address]             
            
        if results["affected"]:
            results["analysis"] = "the affected elastic IPs are not associated with any network interfaces and are therefore not being used"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused elastic IPs found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results
    
    
    def ec2_10(self):
        # Public EBS snapshots

        results = {
            "id" : "ec2_10",
            "ref" : "2.2.2",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure there are no Public EBS Snapshots (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "EBS Snapshots that are public are accessible by all AWS principals, and therefore anyone with an AWS account. To reduce the risk of sensitive data being exposed to unauthorised bearers only share EBS snapshots with trusted accounts.",
            "remediation" : "Remove public access from your EBS snapshots and only share them with trusted accounts.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, snapshots in self.snapshots.items():
            client = self.session.client('ec2', region_name=region)
            for snapshot in snapshots:
                snapshot_id = snapshot["SnapshotId"]
                try: # slow, but cant think of a better way
                    permissions = client.describe_snapshot_attribute(SnapshotId=snapshot_id, Attribute="createVolumePermission")["CreateVolumePermissions"]
                except boto3.exceptions.botocore.exceptions.ClientError:
                    pass
                else:
                    for permission in permissions:
                        try:
                            if permission["Group"] == "all":
                                results["affected"].append("{}({})".format(snapshot_id, region))
                        except KeyError:
                            pass

        if results["affected"]:
            results["analysis"] = "The affected EBS snapshots are public"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No Public EBS Snapshots found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def ec2_11(self):
        # Public AMI images

        results = {
            "id" : "ec2_11",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Ensure there are no Public EC2 AMIs",
            "affected": [],
            "analysis" : "",
            "description" : "The reviewed AWS account contains an AWS AMI that is publicly accessible. When you make your AMIs publicly accessible, these become available in the Community AMIs where everyone with an AWS account can use them to launch EC2 instances. AMIs can contain snapshots of your applications (including their data), therefore exposing your snapshots in this manner is not advised. Ensure that your AWS AMIs are not publicly shared with the other AWS accounts in order to avoid exposing sensitive data. If required, you can share your images with specific AWS accounts without making them public",
            "remediation" : "Remove public access from your EC2 AMIs and only share them with trusted accounts.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, images in self.images.items():
            results["affected"] += [ "{}({})".format(image["ImageId"], region) for image in images if image["Public"] == True ]

        if results["affected"]:
            results["analysis"] = "the affected EC2 AMIs are public."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No Public AMIs found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results



    def ec2_12(self):
        # Ensure no security groups allow ingress from 0.0.0.0/0 to database ports

        results = {
            "id" : "ec2_11",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Ensure no security groups allow ingress from 0.0.0.0/0 to database ports",
            "affected": [],
            "analysis" : "",
            "description" : "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no Security Groups allows unrestricted ingress access to database ports, such as MySQL to port 3306, PostgreSQL to port 5432 and MSSQL to port 1433. Public access to remote database ports increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow direct database traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # get unused security groups
        unused_groups = []

        for region, groups in self.security_groups.items():

            attached_security_group_ids = []
            network_interfaces = self.network_interfaces[region]
            for interface in network_interfaces:
                for group in interface["Groups"]:
                    attached_security_group_ids.append(group["GroupId"])

            for group in groups:
                if group["GroupName"] != "default":
                    if group["GroupId"] not in attached_security_group_ids:
                        unused_groups.append(group["GroupId"])
            
        for region, groups in self.security_groups.items():
            for group in groups:
                group_id = group["GroupId"]
                ip_permissions = group["IpPermissions"]
                for ip_permission in ip_permissions:

                    # ipv4
                    if "IpRanges" in ip_permission:
                        for ip_range in ip_permission["IpRanges"]:
                            if ip_range["CidrIp"] == "0.0.0.0/0":
                                try:
                                    from_port = ip_permission["FromPort"]
                                    to_port = ip_permission["ToPort"]
                                except KeyError:
                                    # if no port range is defined, all ports are allowed
                                    if group_id not in unused_groups:
                                        results["affected"].append("{}({})".format(group_id, region))
                                else:
                                    if from_port == 3306 or from_port == 5432 or from_port == 1433 or 3306 in range(from_port, to_port) or 5432 in range(from_port, to_port) or 1433 in range(from_port, to_port):
                                        if group_id not in unused_groups:
                                            results["affected"].append("{}({})".format(group_id, region))
                    # ipv6
                    if "Ipv6Ranges" in ip_permission:
                        for ip_range in ip_permission["Ipv6Ranges"]:
                            if ip_range["CidrIpv6"] == "::/0":
                                try:
                                    from_port = ip_permission["FromPort"]
                                    to_port = ip_permission["ToPort"]
                                except KeyError:
                                    # if no port range is defined, all ports are allowed
                                    if group_id not in unused_groups:
                                        results["affected"].append("{}({})".format(group_id, region))
                                else:
                                    if from_port == 3306 or from_port == 5432 or from_port == 1433 or 3306 in range(from_port, to_port) or 5432 in range(from_port, to_port) or 1433 in range(from_port, to_port):
                                        if group_id not in unused_groups:
                                            results["affected"].append("{}({})".format(group_id, region))

        if results["affected"]:
            results["analysis"] = "The affected security groups are considered to be overly permissive and allow database ingress traffic from 0.0.0.0/0."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No security groups that allow database ingress traffic from 0.0.0.0/0 found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_13(self):
        # Ensure no Network ACLs allow ingress from 0.0.0.0/0 to database ports 

        results = {
            "id" : "ec2_13",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to database ports",
            "affected": [],
            "analysis" : "",
            "description" : "The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to database ports, such as MySQL to port 3306, PostgreSQL to port 5432 and MSSQL to port 1433. Public access to databse ports increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow database traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, network_acls in self.network_acls.items():
            for acl in network_acls:
                network_acl_id = acl["NetworkAclId"]
                entries = acl["Entries"]
                for entry in entries:
                    if entry["Egress"] == False:
                        if entry["RuleAction"] == "allow":
                            try:
                                cidr_block = entry["CidrBlock"]
                            except KeyError:
                                cidr_block = False
                            try:
                                ipv6cidr_block = entry["Ipv6CidrBlock"]
                            except KeyError:
                                ipv6cidr_block = False
                            
                            if cidr_block == "0.0.0.0/0" or ipv6cidr_block == "::/0":
                                try:
                                    from_port = entry["PortRange"]["From"]
                                    to_port = entry["PortRange"]["To"]
                                except KeyError:
                                    # NACLs with no port range defined allow all ports
                                    results["affected"].append("{}({})".format(network_acl_id, region))
                                else:
                                    if from_port in (3306, 5432, 1433) or 3306 in range(from_port, to_port) or 5432 in range(from_port, to_port) or 1433 in range(from_port, to_port):
                                        results["affected"].append("{}({})".format(network_acl_id, region))

        if results["affected"]:
            results["analysis"] = "The affected Network ACLs allow database ingress traffic from 0.0.0.0/0."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No NACLs that allow remote database ingress traffic from 0.0.0.0/0 found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def ec2_14(self):
        # Ensure default Network ACLs are not defualt Allow

        results = {
            "id" : "ec2_14",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Ensure default Network ACLs are not default allow",
            "affected": [],
            "analysis" : "",
            "description" : "Network Access Control Lists (NACLs) are stateless firewalls that allow you to control traffic flow in and out of your VPCs at the subnet layer. By default, NACLs are configured to allow all inbound and outbound traffic. NACLs provide a first line of defence against malicious network traffic and can provide defence in depth when used alongside strict security groups. Configuring NACLs can minimise the risk of a misconfigured security group or weak default security group exposing sensitive or vulnerable services to the internet and can provide a separation of responsibilities between developers and architecture teams. All Network Access Control Lists within the tested account are currently configured to allow all inbound and outbound traffic on all ports.",
            "remediation" : "Configure all NACLs applying the principle of least privilege and only allows the traffic required for the application or service to function. NOTE: Because NACLs are stateless return traffic on ephemeral unprivileged ports will need to be accounted for. More Information http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, network_acls in self.network_acls.items():
            for acl in network_acls:
                if acl["IsDefault"] == True:
                    network_acl_id = acl["NetworkAclId"]
                    entries = acl["Entries"]
                    for entry in entries:
                        if entry["Egress"] == False: # only ingress rules are checked
                            if entry["RuleAction"] == "allow":
                                try:
                                    cidr_block = entry["CidrBlock"]
                                except KeyError:
                                    cidr_block = False
                                try:
                                    ipv6cidr_block = entry["Ipv6CidrBlock"]
                                except KeyError:
                                    ipv6cidr_block = False
                                
                                if cidr_block == "0.0.0.0/0" or ipv6cidr_block == "::/0":
                                    if "PortRange" not in entry:
                                        # no ports defined = allow all ports
                                        results["affected"].append("{}({})".format(network_acl_id, region))

        if results["affected"]:
            results["analysis"] = "The affected default Network ACLs allow all traffic."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No default Network ACLs that allow all traffic where found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_15(self):
        # Ensure custom Network ACLs are not default Allow

        results = {
            "id" : "ec2_15",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Ensure custom Network ACLs do not allow all traffic",
            "affected": [],
            "analysis" : "",
            "description" : "Network Access Control Lists (NACLs) are stateless firewalls that allow you to control traffic flow in and out of your VPCs at the subnet layer. By default, NACLs are configured to allow all inbound and outbound traffic. NACLs provide a first line of defence against malicious network traffic and can provide defence in depth when used alongside strict security groups. Configuring NACLs can minimise the risk of a misconfigured security group or weak default security group exposing sensitive or vulnerable services to the internet and can provide a separation of responsibilities between developers and architecture teams. All Network Access Control Lists within the tested account are currently configured to allow all inbound and outbound traffic on all ports.",
            "remediation" : "Configure all NACLs applying the principle of least privilege and only allows the traffic required for the application or service to function. NOTE: Because NACLs are stateless return traffic on ephemeral unprivileged ports will need to be accounted for. More Information http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        custom_nacls = []
            
        for region, network_acls in self.network_acls.items():
            for acl in network_acls:
                if acl["IsDefault"] == False:
                    network_acl_id = acl["NetworkAclId"]
                    entries = acl["Entries"]
                    custom_nacls += [network_acl_id]
                    for entry in entries:
                        if entry["Egress"] == False: # only ingress rules are checked
                            if entry["RuleAction"] == "allow":
                                try:
                                    cidr_block = entry["CidrBlock"]
                                except KeyError:
                                    cidr_block = False
                                try:
                                    ipv6cidr_block = entry["Ipv6CidrBlock"]
                                except KeyError:
                                    ipv6cidr_block = False
                                
                                if cidr_block == "0.0.0.0/0" or ipv6cidr_block == "::/0":
                                    if "PortRange" not in entry:
                                        # no ports defined = allow all ports
                                        results["affected"].append("{}({})".format(network_acl_id, region))

        
        if results["affected"]:
            results["analysis"] = "The affected custom Network ACLs allow all traffic."
            results["pass_fail"] = "FAIL"
        else:
            results["pass_fail"] = "PASS"        
            results["affected"].append(self.account_id)
            if not custom_nacls:
                results["analysis"] = "No Custom Network ACLs found."
            else:
                results["analysis"] = "No custom Network ACLs that allow all traffic where found."


        return results
    
    def ec2_16(self):
        # unused network interfaces

        results = {
            "id" : "ec2_16",
            "ref" : "2.10",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Unused Network Interfaces (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The affected Network Interfaces, are not attached to any instances and therefore are not being used. To maintain the hygiene of the environment, make maintenance and auditing easier and reduce cost, all old and temporary network interfaces should be removed.",
            "remediation" : "remove network interfaces that are not in use and no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, interfaces in self.network_interfaces.items():
            for interface in interfaces:
                if interface["Status"] == "available":
                    results["affected"].append("{}({})".format(interface["NetworkInterfaceId"], region))
        
        if results["affected"]:
            results["analysis"] = "The affected network interfaces are not being used."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused Network Interfaces found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def ec2_17(self):
        # Ensure running instances are not more than 180 days old

        results = {
            "id" : "ec2_17",
            "ref" : "2.5",
            "compliance" : "cis_compute",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure running instances are not more than 180 days old (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review contains running EC2 instances that were launched more than 180 days ago. One of the biggest benefits of cloud based infrastructure is to have mutable and short lived infrastructure that can scale and shrink with demand. Instances should be reprovisioned and rebooted periodically to ensure software and hardware resources are up to date and subject to the latest security patches. Additionally, long lived instances may no longer be adequately sized or no longer required, consuming resources and generating a cost to the company.",
            "remediation" : "Review the list of instances and ensure they subject to a regular patching policy and lifecycle management.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
       
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "running":
                        year, month, day = str(instance["LaunchTime"]).split(" ")[0].split("-") #convert datetime to string so it can be converted to date and compare with time delta
                        launch_date = date(int(year), int(month), int(day)) # extract date, ignore time
                        if launch_date < (date.today() - timedelta(days=180)):
                            results["affected"].append("{}({})".format(instance["InstanceId"], region))

        if results["affected"]:
            results["analysis"] = "The affected instances are more than 365 days old."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No instances older than 365 days found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def ec2_18(self):
        # Ensure EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required

        results = {
            "id" : "ec2_18",
            "ref" : "2.8",
            "compliance" : "cis_compute",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review contains EC2 instances that do not enforce the use of IMDSv2.\nTo help protect against Server Side Request Forgery (SSRF) and related vulnerabilities, which could be leveraged by an attacker to query the metadata service to steal the AWS API credentials associated with the instance profile for the running EC2 instance, AWS introduced IMDSv2 which now protects all requests with additional session authentication.",
            "remediation" : "Configure IMDSv2 on all affected EC2 instances. See the following link for more information on how to transition to version 2 of the metadata service.\nMore Information\nhttps://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/configuring-instance-metadata-service.html",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
       
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["MetadataOptions"]["HttpEndpoint"] == "enabled":
                        if instance["MetadataOptions"]["HttpTokens"] != "required":
                            results["affected"].append("{}({})".format(instance["InstanceId"], region))

        if results["affected"]:
            results["analysis"] = "The affected instances are running and do not have IMDSv2 enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing instances found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_19(self):
        # EC2 Instances Not Managed By AWS Systems Manager

        results = {
            "id" : "ec2_19",
            "ref" : "2.9",
            "compliance" : "cis_compute",
            "level" : 2,
            "service" : "ec2",
            "name" : "EC2 Instances Not Managed By AWS Systems Manager (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review contains running EC2 instances that are not managed by AWS Systems Manager. Systems Manager simplifies resource and application management, shortens the time to detect and resolve operational problems, and makes it easier to operate and manage your infrastructure at scale.\nAWS Systems Manager helps maintain security and compliance by scanning your instances against your patch, configuration, and custom policies. You can define patch baselines, maintain up-to-date anti-virus definitions, and enforce firewall policies. You can also remotely manage your servers at scale without manually logging in to each server. Systems Manager also provides a centralized store to manage your configuration data, whether it's plain text, such as database strings, or secrets, such as passwords. This allows you to separate your secrets and configuration data from code.",
            "remediation" : "It is recommended to configure all EC2 instances to be monitored by Systems Manager by installing and registering the SSM agent on the affected hosts.\nMore Information\nhttps://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
       
        for region, reservations in self.instance_reservations.items():
            client = self.session.client('ssm', region_name=region)
            try:
                managed_instances = [ instance["InstanceId"] for instance in client.describe_instance_information()["InstanceInformationList"] ]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting instance information - %s" % e.response["Error"]["Code"])
            else:
                for reservation in reservations:
                    for instance in reservation["Instances"]:
                        if instance["InstanceId"] not in managed_instances:
                            results["affected"].append("{}({})".format(instance["InstanceId"], region))

        if results["affected"]:
            results["analysis"] = "The affected instances are running and not managed by Systems Manager."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing instances found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


    def ec2_20(self):
        # Unencrypted EBS Volumes

        results = {
            "id" : "ec2_20",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Unencrypted EBS Volumes",
            "affected": [],
            "analysis" : "",
            "description" : "To ensure the privacy of any data stored and processed by your EC2 instances it is recommended to enable encryption on EBS volumes. When you create an encrypted EBS volume and attach it to a supported instance type, the following types of data are encrypted:\n\n- Data at rest inside the volume\n- All data moving between the volume and the instance\n- All snapshots created from the volume\n- All volumes created from those snapshots ",
            "remediation" : "There is no direct way to encrypt an existing unencrypted volume, or to remove encryption from an encrypted volume. However, you can migrate data between encrypted and unencrypted volumes. You can also apply a new encryption status while copying a snapshot:\nMore information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, volumes in self.volumes.items():
            results["affected"] += [ "{}({})".format(volume["VolumeId"], region) for volume in volumes if volume["Encrypted"] == False ]
        
        if results["affected"]:
            results["analysis"] = "The affected EBS Volumes are not encrypted."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All EBS Volumes are encrypted."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        
        return results
    
    def ec2_21(self):
        # Unencrypted EBS Snapshots

        results = {
            "id" : "ec2_21",
            "ref" : "2.2.3",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Unencrypted EBS Snapshots (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "To ensure the privacy of any data stored and processed by your EC2 instances it is recommended to enable encryption on EBS volumes. When you create an encrypted EBS volume and attach it to a supported instance type, the following types of data are encrypted:\n\n- Data at rest inside the volume\n- All data moving between the volume and the instance\n- All snapshots created from the volume\n- All volumes created from those snapshots ",
            "remediation" : "There is no direct way to encrypt an existing unencrypted volume, or to remove encryption from an encrypted volume. However, you can migrate data between encrypted and unencrypted volumes. You can also apply a new encryption status while copying a snapshot:\nMore information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, snapshots in self.snapshots.items():
            results["affected"] += [ "{}({})".format(snapshot["SnapshotId"], region) for snapshot in snapshots if snapshot["Encrypted"] == False ]
        
        if results["affected"]:
            results["analysis"] = "The affected Snapshots are not encrypted."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All EBS Snapshots are encrypted."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results
    
    def ec2_22(self):
        # Snapshots older than 30 days

        results = {
            "id" : "ec2_22",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Snapshots Older Than 30 days",
            "affected": [],
            "analysis" : "",
            "description" : "With an active EBS backup strategy that takes volume snapshots daily or weekly, your data can grow rapidly and add unexpected charges to your bill. Since AWS EBS volumes snapshots are incremental, deleting previous (older) snapshots do not affect the ability to restore the volume data from later snapshots which allows you keep just the necessary backup data and lower your AWS monthly costs.",
            "remediation" : "Delete snapshots that are older than 30 days and consider implementing snapshot lifecycle management in AWS DLM",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, snapshots in self.snapshots.items():
            for snapshot in snapshots:
                year, month, day = str(snapshot["StartTime"]).split(" ")[0].split("-") #convert datetime to string so it can be converted to date and compare with time delta
                start_date = date(int(year), int(month), int(day)) # extract date, ignore time
                if start_date < (date.today() - timedelta(days=30)):
                    results["affected"].append("{}({})".format(snapshot["SnapshotId"], region))
        
        if results["affected"]:
            results["analysis"] = "The affected snapshots are older than 30 days."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No EBS snapshots older than 30 days found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results
    
    def ec2_23(self):
        # default VPCs in use

        results = {
            "id" : "ec2_23",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Default VPCs in use",
            "affected": [],
            "analysis" : "",
            "description" : "Default VPCs created by AWS can be considered overly permissive and it is recommended to create your own VPCs instead. Default VPCs include an internet gateway, default security groups and default allow all NACLs which could result in accidental exposure of EC2 instances and data to the internet.",
            "remediation" : "Create your own VPCs as required applying the principle of least privilege to network access controls",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    for vpc in self.vpcs[region]:
                        try:
                            if vpc["VpcId"] == instance["VpcId"]:
                                if vpc["IsDefault"] == True:
                                    results["affected"].append("{}({})".format(vpc["VpcId"], region))
                        except KeyError: # instance has no VpcID
                            pass
        
        if results["affected"]:
            results["analysis"] = "The affected VPCs are in use and default."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No Default VPCs in use"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results

    def ec2_24(self):
        # Overly permissive VPC endpoint policy

        results = {
            "id" : "ec2_24",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Overly Permissive VPC Endpoint Policy",
            "affected": [],
            "analysis" : "",
            "description" : "VPC endpoint policies within the AWS accounts were configured with permissive default policies which could be exploited by a malicious user to exfiltrate data from the AWS environment.\nVPC endpoint policies are an AWS networking feature which provide private connections between resources within a VPC to supported AWS services using the backbone network and private APIs of each service. This configuration ensures that resources within a VPC do not require an Internet connection or VPN to communicate with other AWS services, directly supporting the implementation of secure isolated networks which do not require the use of potentially insecure public infrastructure. As an example, using a VPC endpoint, a service on an EC2 instance can make a request to the private API endpoint of an S3 bucket to download required objects, if a VPC endpoint has not been created for the S3 service, traffic will instead require a route via an internet gateway or similar device to the public, internet facing S3 API endpoint.\nSeveral VPC endpoint service types include the ability to configure endpoint policies to restrict the communications of resources with the associated AWS services. If no endpoint policy is defined when the endpoint is created, AWS will automatically attach a default policy which provides full, unrestricted access to the associated service. However as the default policy provides full access to the service, a malicious actor with access to the VPC could leverage the configuration to extract data from the AWS environment to write data to an attacker controlled service.\nFor example, an S3 VPC endpoint with the default full access policy would provide full access to the private S3 APIs which could be used to extract sensitive information to an S3 bucket within an attacker controlled AWS account. This could be achieved several ways but a common method would be If a malicious user had access to an EC2 instance within the VPC, they could upload AWS access keys with write permission to an S3 bucket within their own account and use these permissions to exfiltrate data to their S3 bucket via the endpoint. Similar methods could be achieved via other endpoints and services, such as by exfiltrating secrets from AWS Secrets Manager to an attacker controlled resource.",
            "remediation" : 'It is recommended that VPC endpoints are created for each supported service within each VPC to limit the requirement for internet connectivity. However a custom policy should be created in line with the principal of least privilege for all supported VPC endpoints in use within the AWS environment. These policies should ensure that network connections to AWS services is only accessible to those resources within the internal AWS environment. Care should be taken to restrict resources by name or ARN and minimise the use of wildcards which may provide unintended access to services.\nAdditionally there are several types of VPC endpoints available including Interface endpoints which are a type of network interface providing access to the PrivateLink network for access to services. These Interface endpoints also support the use of security groups to restrict traffic, however it is recommended that these security groups are used in tandem with VPC endpoint policies as a defence-in-depth approach to implementing fine grained access controls. Other VPC endpoint types such as Gateway endpoints which act as route tables do not support the use of security groups and as such a restrictive endpoint policy should be implemented to restrict traffic to external resources.\nAn example policy for the S3 service is provided below:\n{\n    "Statement": [\n        {\n            "Action": "S3:*",\n            "Effect": "Allow",\n            "Resource": [\n                "*:*:*:*:xxxxxxxxxxxx:*",\n                "*:*:*:*:yyyyyyyyyyyy:*"\n            ],\n            "Principal": "*",\n            "Condition": {\n                "StringEquals": {\n                    "aws:PrincipalOrgID": "o-zzzzzzzzzz"\n                }\n            }       \n}   \n]\,}\nThis example policy ensures that resources in the isolated network can only use the VPC endpoint for S3 if they try to interact with S3 buckets controlled by specific accounts (xxxxxxxxxxxx and yyyyyyyyyyyy) and only if the principal is from your Org (o-zzzzzzzzzz) so an attacker wouldn\'t be able to use their own access keys.\n',
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score" : "4.9",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        affected_statements = {}

        for region, endpoints in self.vpc_endpoints.items():
            for endpoint in endpoints:
                # Policy document is returned as a string and not a dict for some unknown reason.
                try:
                    statements = json.loads(endpoint["PolicyDocument"])["Statement"]
                except KeyError:
                    logging.error("Error getting vpc endpoint policies")
                else:
                    for statement in statements:
                        try:
                            if statement["Effect"] == "Allow":
                                if statement["Action"] == "*":
                                    if statement["Resource"] == "*":
                                        if statement["Principal"] == "*":
                                            results["affected"].append("{}({})".format(endpoint["VpcEndpointId"], region))
                                            affected_statements[endpoint["VpcEndpointId"]] = statement
                        except KeyError: # catch statements that dont have "Action" and are using "NotAction" instead
                            pass

        if results["affected"]:
            results["analysis"] = affected_statements
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        
        return results
        

    def ec2_25(self):
        # Ensure no security groups allow ingress from ::/0 to remote server administration ports (Automated)

        results = {
            "id" : "ec2_25",
            "ref" : "5.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure no security groups allow ingress from ::/0 to remote server administration ports (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389 . Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IPv6 addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # get unused security groups
        unused_groups = []

        for region, groups in self.security_groups.items():

            attached_security_group_ids = []
            network_interfaces = self.network_interfaces[region]
            for interface in network_interfaces:
                for group in interface["Groups"]:
                    attached_security_group_ids.append(group["GroupId"])

            for group in groups:
                if group["GroupName"] != "default":
                    if group["GroupId"] not in attached_security_group_ids:
                        unused_groups.append(group["GroupId"])
            
        for region, groups in self.security_groups.items():
            for group in groups:
                group_id = group["GroupId"]
                ip_permissions = group["IpPermissions"]
                for ip_permission in ip_permissions:
                    # ipv6
                    if "Ipv6Ranges" in ip_permission:
                        for ip_range in ip_permission["Ipv6Ranges"]:
                            if ip_range["CidrIpv6"] == "::/0":
                                try:
                                    from_port = ip_permission["FromPort"]
                                    to_port = ip_permission["ToPort"]
                                except KeyError:
                                    # if no port range is defined, all ports are allowed
                                    if group_id not in unused_groups:
                                        results["affected"].append("{}({})".format(group_id, region))
                                else:
                                    if from_port == 22 or from_port == 3389 or 22 in range(from_port, to_port) or 3389 in range(from_port, to_port):            
                                        if group_id not in unused_groups:
                                            results["affected"] += ["{}({})".format(group_id, region)]

        if results["affected"]:
            results["analysis"] = "the affected security groups allow admin ingress traffic from 0.0.0.0/0."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No security groups that allow remote server administration ingress traffic from 0.0.0.0/0 found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def ec2_26(self):
        # EC2 instance user data

        results = {
            "id" : "ec2_26",
            "ref" : "2.13",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data (CIS)(Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "User Data can be specified when launching an ec2 instance. Examples include specifying parameters for configuring the instance or including a simple script. The user data is not protected by authentication or cryptographic methods. Therefore, sensitive data, such as passwords or long-lived encryption keys should not be stored as user data.",
            "remediation" : "From the Console\n1. Login to AWS Console using https://console.aws.amazon.com\n2. Click All services and click EC2 under Compute.\n3. Click on Instances.\n4. If the instance is currently running, stop the instance first.\nNote: ensure there is no negative impact from stopping the instance prior to stopping\nthe instance.\n5. For each instance, click Actions -> Instance Settings -> Edit user data\n6. For each instance, edit the user data to ensure there are no secrets or sensitive data stored. A Secret Management solution such as AWS Secrets Manager can be used here as a more secure mechanism of storing necessary sensitive data.\n7. Repeat this remediation for all the other AWS regions.\nNote: If the ec2 instances are created via automation or infrastructure-as-code, edit the user data in those pipelines and code.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        user_data = {}

        for region, reservations in self.instance_reservations.items():

            client = self.session.client('ec2', region_name=region)
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]
                    try:
                        user_data[instance_id] = client.describe_instance_attribute(Attribute="userData", InstanceId=instance_id)["UserData"]
                    except boto3.exceptions.botocore.exceptions.ClientError as e:
                        logging.error("Error getting instance metadata - %s" % e.response["Error"]["Code"])
                    else:
                        if user_data[instance_id]:
                            results["affected"].append(instance_id)

        if results["affected"]:
            results["analysis"] = user_data
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "No user data found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results   

    def ec2_27(self):
        # Ensure all security groups rules have a description

        results = {
            "id" : "ec2_27",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "Ensure All Security Group Rules Have A Description",
            "affected": [],
            "analysis" : "",
            "description" : "The affected Security Groups contain rules which do not have a corresponding description. Setting a description on all rules improves readbility, helps ensure maintainability of the account and will help minimise mistakes when configuring or updating rules. ",
            "remediation" : "Ensure all rules have a suitable description.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        affected_groups = []
            
        for region, groups in self.security_groups.items():
            for group in groups:
                group_id = group["GroupId"]
                for permissions in group["IpPermissions"]:
                    for ip_range in permissions["IpRanges"]:
                        if "Description" not in ip_range: 
                            affected_groups.append("{}({})".format(group_id, region))

                    for ipv6_range in permissions["Ipv6Ranges"]:
                        if "Description" not in ip_range: 
                            affected_groups.append("{}({})".format(group_id, region))

                for permissions in group["IpPermissionsEgress"]:
                    for ip_range in permissions["IpRanges"]:
                        if "Description" not in ip_range: 
                            affected_groups.append("{}({})".format(group_id, region))

                    for ipv6_range in permissions["Ipv6Ranges"]:
                        if "Description" not in ip_range: 
                            affected_groups.append("{}({})".format(group_id, region))

        results["affected"] = list(set(affected_groups))
                    
        if results["affected"]:
            results["analysis"] = "The affected security groups contains rules without a description"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Default security groups restrict all traffic"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_28(self):
        # EC2 Instances without detailed monitoring enabled

        results = {
            "id" : "ec2_28",
            "ref" : "2.6",
            "compliance" : "cis_compute",
            "level" : 2,
            "service" : "ec2",
            "name" : "EC2 Instances Without Detailed Monitoring Enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enabling detailed monitoring provides enhanced monitoring and granular insights into EC2 instance metrics. Not having detailed monitoring enabled may limit the ability to troubleshoot performance and security related issues effectively. Data is available in 1-minute periods. For the instances where you've enabled detailed monitoring, you can also get aggregated data across groups of similar instances. You are charged per metric that is sent to CloudWatch. You are not charged for data storage. Due to this added cost it is recommended that you only enable this on critical instances.",
            "remediation" : "Enable detailed monitoring for appropriate instances.\nNOTE: Additional costs are incurred when detailed monitoring is enabled.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["Monitoring"]["State"] != "enabled":
                        results["affected"].append("{}({})".format(instance["ImageId"], region))

        if results["affected"]:
            results["analysis"] = "The affected instances do not have detailed monitoring enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing instances found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_29(self):
        # EC2 Instances with a public IP address

        results = {
            "id" : "ec2_29",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ec2",
            "name" : "EC2 Instances with a Public IP Address",
            "affected": [],
            "analysis" : [],
            "description" : "Affected Instances have a Public IP Address Attached",
            "remediation" : "Review Public IPs to ensure an appropriate Security Group has been applied applying the principle of least privilege.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    try:
                        if instance["PublicIpAddress"]:
                            results["analysis"].append("{}({})({})".format(instance["ImageId"], region, instance["PublicIpAddress"]))
                            results["affected"].append("{}({})".format(instance["ImageId"], region))
                    except KeyError:
                        pass

        if results["affected"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "No Public IPs found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_30(self):
        # Stopped Instances

        results = {
            "id" : "ec2_30",
            "ref" : "2.11",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Stopped EC2 Instances (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The affected EC2 Instances are currently in a stopped state. To maintain account hygiene and reduce potential storage and Elastic IP costs is recommended to terminate all stopped instances that are no longer required. the CIS benchmark recommends that all instances stopped for 90 days are deleted.",
            "remediation" : "Terminate the affected instances if no longer requried.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        analysis = []

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "stopped":
                        results["affected"].append("{} ({})".format(instance["InstanceId"], region))
#                        year, month, day = str(instance["LaunchTime"]).split(" ")[0].split("-") #convert datetime to string so it can be converted to date and compare with time delta
#                        launch_date = date(int(year), int(month), int(day)) # extract date, ignore time
                        analysis.append("{} ({}) - Launch Date: {}".format(instance["InstanceId"], region, instance["LaunchTime"]))

        if results["affected"]:
            results["analysis"] = analysis
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No stopped instances found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_31(self):
        # Ensure Consistent Naming Convention is used for Organizational AMI (CIS)

        results = {
            "id" : "ec2_31",
            "ref" : "2.1.1",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure Consistent Naming Convention is used for Organizational AMI (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The naming convention for AMI (Amazon Machine Images) should be documented and followed for any AMI's created. The majority of AWS resources can be named and tagged. Most organizations have already created standardize naming conventions, and have existing rules in effect. They simply need to extend that for all AWS cloud resources to include Amazon Machine Images (AMI)",
            "remediation" : "If the AMI Name for an AMI doesn't follow Organization policy Perform the following to copy and rename the AMI: From the Console:\n1. Login to the EC2 console at https://console.aws.amazon.com/ec2/.\n2. In the left pane click Images, click AMIs.\n3. Select the AMI that does not comply to the naming policy.\n4. Click on Actions.\n5. Click on Copy AMI",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, images in self.images.items():
            for image in images:
                results["affected"].append(image["Name"])

        if results["affected"]:
            results["analysis"] = "The affected images were found in your account, review them to ensure a consistent naming convention is in use"
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "No AMI images found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_32(self):
        # Ensure Images (AMI's) are encrypted (CIS)

        results = {
            "id" : "ec2_32",
            "ref" : "2.1.2",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure Images (AMI's) are encrypted (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Amazon Machine Images should utilize EBS Encrypted snapshots AMIs backed by EBS snapshots should use EBS encryption. Snapshot volumes can be encrypted and attached to an AMI.",
            "remediation" : "Perform the following to encrypt AMI EBS Snapshots: From the Console:\n1. Login to the EC2 console at https://console.aws.amazon.com/ec2/.\n2. In the left pane click on AMIs.\n3. Select the AMI that does not comply to the encryption policy.\n4. Click on Actions.\n5. Click on Copy AMI.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        analysis = {}

        for region, images in self.images.items():
            for image in images:
                analysis[image["Name"]] = []
                for mapping in image["BlockDeviceMappings"]:
                    try:
                        if mapping["Ebs"]["Encrypted"] == False:
                            results["affected"].append(image["Name"])
                            analysis[image["Name"]].append(mapping["Ebs"]["SnapshotId"])
                    except KeyError:
                        pass

        if results["affected"]:
            results["analysis"] = analysis
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unencrpyted AMI image snapshots found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_33(self):
        # Ensure unused EBS volumes are removed (CIS)

        results = {
            "id" : "ec2_33",
            "ref" : "2.2.4",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure unused EBS volumes are removed (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Identify any unused Elastic Block Store (EBS) volumes in your AWS account and remove them. Any Elastic Block Store volume created in your AWS account contains data, regardless of being used or not. If you have EBS volumes (other than root volumes) that are unattached to an EC2 instance they should be removed to prevent unauthorized access or data leak to any sensitive data on these volumes. Once a EBS volume is deleted, the data will be lost. If this is data that you need to archive, create an encrypted EBS snapshot before deleting them.",
            "remediation" : "From Console:\n1. Login to the EC2 console using https://console.aws.amazon.com/ec2/\n2. Under Elastic Block Store, click Volumes.\n3. Find the State column\n4. Sort by Available\n5. Select the Volume that you want to delete.\n6. Click Actions, Delete volume, Yes, Delete\nNote: EBS volumes can be in different regions. Make sure to review all the regions being utilized.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, volumes in self.volumes.items():
            for volume in volumes:
                if volume["State"] == "available":
                    results["affected"].append(volume["VolumeId"])

        if results["affected"]:
            results["analysis"] = "The affected volumes are not attached"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused volumes found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_34(self):
        # Ensure Default EC2 Security groups are not being used (CIS)

        results = {
            "id" : "ec2_34",
            "ref" : "2.7",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure Default EC2 Security groups are not being used (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "When an EC2 instance is launched a specified custom security group should be assigned to the instance. When an EC2 Instance is launched the default security group is automatically assigned. In error a lot of instances are launched in this way, and if the default security group is configured to allow unrestricted access, it will increase the attack footprint allowing the opportunity for malicious activity.",
            "remediation" : "From the Console:\n1. Login to EC2 using https://console.aws.amazon.com/ec2/\n2. On the left Click Network & Security, click Security Groups.\n3. Select Security Groups\n4. Click on the default Security Group you want to review.\n5. Click Actions, View details.\n6. Select the Inbound rules tab\n7. Click on Edit inbound rules\n8. Click on Delete for all the rules listed\n9. Once there are no rules listed click on 'Save rules`\n10. Repeat steps no. 3 – 8 for any other default security groups listed.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    for group in instance["SecurityGroups"]:
                        if group["GroupName"] == "default":
                            results["affected"].append(instance["InstanceId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected EC2 instances have default security groups attached"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Default security groups are not in use"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_35(self):
        # Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination (CIS)

        results = {
            "id" : "ec2_35",
            "ref" : "2.12",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "This rule ensures that Amazon Elastic Block Store volumes that are attached to Amazon Elastic Compute Cloud (Amazon EC2) instances are marked for deletion when an instance is terminated. If an Amazon EBS volume isn’t deleted when the instance that it’s attached to is terminated, it may violate the concept of least functionality.",
            "remediation" : 'From the CLI\n1. Run the modify-instance-attribute command using the list of instances collected in the audit.\n<code>aws ec2 modify-instance-attribute --instance-id i-123456abcdefghi0 --block-device-mappings "[{\"DeviceName\":\"/dev/sda\",\"Ebs\":{\"DeleteOnTermination\":true}}]"</code>\n2. Repeat steps no. 1 with the other instances discovered in all AWS regions.',
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    for mapping in instance["BlockDeviceMappings"]:
                        if mapping["Ebs"]["DeleteOnTermination"] == False:
                            results["affected"].append(instance["InstanceId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected EC2 instances have EBS volumes attached that do not have delete on termination enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No EBS volumes without Delete on termination enabled found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_36(self):
        # Amazon EC2 subnets should not automatically assign public IP addresses

        results = {
            "id" : "ec2_36",
            "ref" : "ec2.15",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Amazon EC2 subnets should not automatically assign public IP addresses",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether the assignment of public IPs in Amazon Virtual Private Cloud (Amazon VPC) subnets have MapPublicIpOnLaunch set to FALSE. The control passes if the flag is set to FALSE. All subnets have an attribute that determines whether a network interface created in the subnet automatically receives a public IPv4 address. Instances that are launched into subnets that have this attribute enabled have a public IP address assigned to their primary network interface",
            "remediation" : "To configure a subnet to not assign public IP addresses, see Modify the public IPv4 addressing attribute for your subnet in the Amazon VPC User Guide. Clear the check box for Enable auto-assign public IPv4 address.\nMore Information\nhttps://docs.aws.amazon.com/vpc/latest/userguide/modify-subnets.html#subnet-public-ip",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, subnets in self.subnets.items():
            for subnet in subnets:
                if subnet["MapPublicIpOnLaunch"]:
                    results["affected"].append(subnet["SubnetId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected subnets are configured to assign a public IP on launch."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_37(self):
        # Unused Network Access Control Lists should be removed

        results = {
            "id" : "ec2_37",
            "ref" : "ec2.16",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Unused Network Access Control Lists should be removed",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether there are any unused network access control lists (network ACLs) in your virtual private cloud (VPC). The control fails if the network ACL isn't associated with a subnet. The control doesn't generate findings for an unused default network ACL. The control checks the item configuration of the resource AWS::EC2::NetworkAcl and determines the relationships of the network ACL. If the only relationship is the VPC of the network ACL, the control fails. If other relationships are listed, then the control passes.",
            "remediation" : "For instructions on deleting an unused network ACL, see Deleting a network ACL in the Amazon VPC User Guide. You can't delete the default network ACL or an ACL that is associated with subnets.\nMore Information\nhttps://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#DeleteNetworkACL",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, acls in self.network_acls.items():
            for acl in acls:
                if not acl["Associations"]:
                    results["affected"].append(acl["NetworkAclId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected subnets are not associated with any subnets and are therefore not in use"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_38(self):
        # Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests

        results = {
            "id" : "ec2_38",
            "ref" : "ec2.23",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if EC2 transit gateways are automatically accepting shared VPC attachments. This control fails for a transit gateway that automatically accepts shared VPC attachment requests. Turning on AutoAcceptSharedAttachments configures a transit gateway to automatically accept any cross-account VPC attachment requests without verifying the request or the account the attachment is originating from. To follow the best practices of authorization and authentication, we recommended turning off this feature to ensure that only authorized VPC attachment requests are accepted.",
            "remediation" : "To modify a transit gateway, see Modify a transit gateway in the Amazon VPC Developer Guide.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, gateways in self.transit_gateways.items():
            for gateway in gateways:
                if gateway["AutoAcceptSharedAttachments"] == "enable":
                    results["affected"].append(gateway["TransitGatewayId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected EC2 Transit Gateways are currently configured to allow auto accepts VPC attachment requests"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_39(self):
        # Amazon EC2 paravirtual instance types should not be used

        results = {
            "id" : "ec2_39",
            "ref" : "ec2.24",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Amazon EC2 paravirtual instance types should not be used",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether the virtualization type of an EC2 instance is paravirtual. The control fails if the virtualizationType of the EC2 instance is set to paravirtual. Linux Amazon Machine Images (AMIs) use one of two types of virtualization: paravirtual (PV) or hardware virtual machine (HVM). The main differences between PV and HVM AMIs are the way in which they boot and whether they can take advantage of special hardware extensions (CPU, network, and storage) for better performance. Historically, PV guests had better performance than HVM guests in many cases, but because of enhancements in HVM virtualization and the availability of PV drivers for HVM AMIs, this is no longer true. For more information, see Linux AMI virtualization types in the Amazon EC2 User Guide.",
            "remediation" : "To update an EC2 instance to a new instance type, see Change the instance type in the Amazon EC2 User Guide.\nMore Information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-resize.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["VirtualizationType"] == "paravirtual":
                        results["affected"].append(instance["InstanceId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected instances are using the paravirtual instance type"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_40(self):
        # EC2 transit gateway attachments should be tagged

        results = {
            "id" : "ec2_40",
            "ref" : "ec2.33",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "EC2 transit gateway attachments should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 transit gateway attachment has tags. The control fails if the transit gateway attachment doesn’t have any tag keys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the transit gateway attachment isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to an EC2 transit gateway attachment, see Tag your Amazon EC2 resources in the Amazon EC2 User Guide.\nMore Information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#Using_Tags_Console",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, gateway_attachments in self.transit_gateway_attachments.items():
            for attachment in gateway_attachments:
                if not attachment["Tags"]:
                    results["affected"].append(attachment["TransitGatewayAttachmentId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected transit gateway attachment id does not have any tags attached"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_41(self):
        # EC2 transit gateway route tables should be tagged

        results = {
            "id" : "ec2_41",
            "ref" : "ec2.34",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "EC2 transit gateway route tables should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 transit gateway route table has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the transit gateway route table doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the transit gateway route table isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to an EC2 transit gateway route table, see Tag your Amazon EC2 resources in the Amazon EC2 User Guide.\nMore Information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#Using_Tags_Console",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, gateway_route_tables in self.transit_gateway_route_tables.items():
            for table in gateway_route_tables:
                if not table["Tags"]:
                    results["affected"].append(table["TransitGatewayRouteTableId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected transit gateway attachment id does not have any tags attached"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ec2_42(self):
        # EC2 network interfaces should be tagged

        results = {
            "id" : "ec2_41",
            "ref" : "ec2.35",
            "compliance" : "FSBP",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "EC2 network interfaces should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon EC2 transit gateway route table has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the transit gateway route table doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the transit gateway route table isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to an EC2 transit gateway route table, see Tag your Amazon EC2 resources in the Amazon EC2 User Guide.\nMore Information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#Using_Tags_Console",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
            
        for region, network_interfaces in self.network_interfaces.items():
            for interface in network_interfaces:
                if not interface["TagSet"]:
                    results["affected"].append(interface["NetworkInterfaceId"])
                    
        if results["affected"]:
            results["analysis"] = "The affected interfaces do not have any tags attached"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
