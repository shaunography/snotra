import boto3

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
        return findings

    def get_security_groups(self):
        security_groups = {}
        print("getting security groups")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            security_groups[region] = client.describe_security_groups()["SecurityGroups"]
        return security_groups
    
    def get_network_acls(self):
        network_acls = {}
        print("getting network acls")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            network_acls[region] = client.describe_network_acls()["NetworkAcls"]
        return network_acls
    
    def get_network_interfaces(self):
        network_interfaces = {}
        print("getting network interfaces")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            network_interfaces[region] = client.describe_network_interfaces()["NetworkInterfaces"]
        return network_interfaces
    
    def get_instance_reservations(self):
        reservations = {}
        print("getting instance reservations")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            reservations[region] = client.describe_instances()["Reservations"]
        return reservations
    
    def get_volumes(self):
        volumes = {}
        print("getting ebs volumes")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            volumes[region] = client.describe_volumes()["Volumes"]
        return volumes
    
    def get_snapshots(self):
        snapshots = {}
        print("getting ebs snapshots")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            snapshots[region] = client.describe_snapshots()["Snapshots"]
        return snapshots
    
    def get_vpcs(self):
        vpcs = {}
        print("getting vpcs")
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            vpcs[region] = client.describe_vpcs()["Vpcs"]
        return vpcs
    
    def ec2_1(self):
        # Ensure IAM instance roles are used for AWS resource access from instances (Manual)

        results = {
            "id" : "ec2_1",
            "ref" : "1.18",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure IAM instance roles are used for AWS resource access from instances",
            "affected": "No failing instances found",
            "analysis" : "",
            "description" : "AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls or by assigning the instance to a role which has an appropriate permissions policy for the required access. AWS Access means accessing the APIs of AWS in order to access AWS resources or manage AWS account resources. AWS IAM roles reduce the risks associated with sharing and rotating credentials that can be used outside of AWS itself. If credentials are compromised, they can be used from outside of the AWS account they give access to. In contrast, in order to leverage role permissions an attacker would need to gain and maintain access to a specific instance to use the privileges associated with it. Additionally, if credentials are encoded into compiled applications or other hard to change mechanisms, then they are even more unlikely to be properly rotated due to service disruption risks. As time goes on, credentials that cannot be rotated are more likely to be known by an increasing number of individuals who no longer work for the organization owning the credentials",
            "remediation" : "",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_1")

        failing_instances = []

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "running":
                        instance_id = instance["InstanceId"]
                        ec2 = self.session.resource('ec2', region_name=region)
                        ec2_instance = ec2.Instance(id=instance_id)
                        if not ec2_instance.iam_instance_profile:
                            failing_instances += ["{}({})".format(instance_id, region)]

        if failing_instances:
            results["analysis"] = "the following running instances do not have an instance profile attached:\n{}".format(" ".join(failing_instances))
            results["affected"] = ", ".join(failing_instances)
            results["pass_fail"] = "FAIL"

        return results


    def ec2_2(self):
        # Ensure EBS volume encryption is enabled (Manual)

        results = {
            "id" : "ec2_2",
            "ref" : "2.2.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure EBS volume encryption is enabled",
            "affected": "",
            "analysis" : "Default EBS Volume encryption is enabled in all regions",
            "description" : "Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported. Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.",
            "remediation" : "Ensure EBS default volume encryption is enabled in all regions",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_2")
        
        failing_regions = []
        
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            if client.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] == False:
                failing_regions += [region]
        
        if failing_regions:
            results["pass_fail"] = "FAIL"

            if set(failing_regions) == set(self.regions):
                results["analysis"] = "Default Encryption is not enabled in any region"
                results["affected"] = ", ".join(self.regions)
            else:
                results["analysis"] = "the following EC2 regions do not encrypt EBS volumes by default:\n{}".format(" ".join(failing_regions))
                results["affected"] = ", ".join(failing_regions)
        
        return results


    def ec2_3(self):
        # Ensure VPC flow logging is enabled in all VPCs (Automated)

        results = {
            "id" : "ec2_3",
            "ref" : "3.9",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure VPC flow logging is enabled in all VPCs",
            "affected": "",
            "analysis" : "Flow Logs are enabled on all VPCs",
            "description" : "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet Rejects for VPCs. VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.",
            "remediation" : "Enable VPC Flow Logs on all VPCs",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_3")

        failing_regions = []
        
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            flow_logs = client.describe_flow_logs()["FlowLogs"]
            if not flow_logs:
                failing_regions += [region]
            
        if failing_regions:
            results["pass_fail"] = "FAIL"

            if set(failing_regions) == set(self.regions):
                results["analysis"] = "VPC Flow logging is not enabled in any region"
                results["affected"] = ", ".join(self.regions)
            else:
                results["analysis"] = "the following regions do not have any VPC FLow Logs enabled:\n{}".format(" ".join(failing_regions))
                results["affected"] = ", ".join(failing_regions)
        
        return results

    def ec2_4(self):
        # Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        results = {
            "id" : "ec2_4",
            "ref" : "5.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
            "affected": "",
            "analysis" : "No NACLs that allow remote server administration ingress traffic from 0.0.0.0/0 found",
            "description" : "The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389. Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_4")
        
        failing_nacls = []
            
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
                                    failing_nacls += ["{}({})".format(network_acl_id, region)]
                                else:
                                    if from_port in (22, 3389) or 22 in range(from_port, to_port) or 3389 in range(from_port, to_port):
                                        failing_nacls += ["{}({})".format(network_acl_id, region)]

        if failing_nacls:
            results["analysis"] = "the following Network ACLs allow admin ingress traffic from 0.0.0.0/0:\n{}".format(" ".join(set(failing_nacls)))
            results["affected"] = ", ".join(set(failing_nacls))
            results["pass_fail"] = "FAIL"

        return results


    def ec2_5(self):
        # Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        results = {
            "id" : "ec2_5",
            "ref" : "5.2",
            "compliance" : "cis",
            "level" : 1,
            "service" : "ec2",
            "name" : "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
            "affected": "",
            "analysis" : "No security groups that allow remote server administration ingress traffic from 0.0.0.0/0 found",
            "description" : "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389 . Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow RDP and SSH traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_5")

        failing_security_groups = []
            
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
                                    failing_security_groups += ["{}({})".format(group_id, region)]
                                else:
                                    if from_port == 22 or from_port == 3389 or 22 in range(from_port, to_port) or 3389 in range(from_port, to_port):            
                                        failing_security_groups += ["{}({})".format(group_id, region)]
                    # ipv6
                    if "Ipv6Ranges" in ip_permission:
                        for ip_range in ip_permission["Ipv6Ranges"]:
                            if ip_range["CidrIpv6"] == "::/0":
                                try:
                                    from_port = ip_permission["FromPort"]
                                    to_port = ip_permission["ToPort"]
                                except KeyError:
                                    # if no port range is defined, all ports are allowed
                                    failing_security_groups += ["{}({})".format(group_id, region)]
                                else:
                                    if from_port == 22 or from_port == 3389 or 22 in range(from_port, to_port) or 3389 in range(from_port, to_port):            
                                        failing_security_groups += ["{}({})".format(group_id, region)]

        if failing_security_groups:
            results["analysis"] = "the following security groups allow admin ingress traffic from 0.0.0.0/0:\n{}".format(" ".join(set(failing_security_groups)))
            results["affected"] = ", ".join(set(failing_security_groups))
            results["pass_fail"] = "FAIL"

        return results
    
    
    def ec2_6(self):
        # Ensure the default security group of every VPC restricts all traffic (Automated)

        results = {
            "id" : "ec2_6",
            "ref" : "5.3",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure the default security group of every VPC restricts all traffic",
            "affected": "",
            "analysis" : "default security groups restrict all traffic",
            "description" : "A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group when you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic. The default VPC in every region should have its default security group updated to comply. Any newly created VPCs will automatically contain a default security group that will need remediation to comply with this recommendation. NOTE: When implementing this recommendation, VPC flow logging is invaluable in determining the least privilege port access required by systems to work properly because it can log all packet acceptances and rejections occurring under the current security groups. This dramatically reduces the primary barrier to least privilege engineering - discovering the minimum ports required by systems in the environment. Even if the VPC flow logging recommendation in this benchmark is not adopted as a permanent security measure, it should be used during any period of discovery and engineering for least privileged security groups. Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources.",
            "remediation" : "Configure default security groups in all VPCs to be default deny and restrict all traffic",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_6")

        failing_security_groups = []
            
        for region, groups in self.security_groups.items():
            for group in groups:
                group_id = group["GroupId"]
                if group["GroupName"] == "default":
                    if group["IpPermissions"]:
                        failing_security_groups += ["{}({})".format(group_id, region)]
                    
        if failing_security_groups:
            results["analysis"] = "the following default security groups have inbound rules configured:\n{}".format(" ".join(failing_security_groups))
            results["affected"] = ", ".join(failing_security_groups)
            results["pass_fail"] = "FAIL"

        return results
    
    def ec2_7(self):
        # Ensure routing tables for VPC peering are "least access" (Manual)

        results = {
            "id" : "ec2_7",
            "ref" : "5.4",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure routing tables for VPC peering are least access",
            "affected": "",
            "analysis" : "VPC Peering not in use",
            "description" : "Once a VPC peering connection is established, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection. Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.",
            "remediation" : "Configure routing tables for VPC perring following the principle of least access",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_7")

        peering_connections = []
            
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            route_tables = client.describe_route_tables()["RouteTables"]
            for route_table in route_tables:
                for route in route_table["Routes"]:
                    if "VpcPeeringConnectionId" in route:
                        peering_connections += ["{}({})".format(route["VpcPeeringConnectionId"], region)]
                    
        if peering_connections:
            results["analysis"] = "VPC peering in use - check routing tables for least access:\n{}".format(" ".join(set(peering_connections)))
            results["pass_fail"] = "INFO"

        return results



    def ec2_8(self):
        # Unused Security Groups

        results = {
            "id" : "ec2_8",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure there are no unused security groups",
            "affected": "",
            "analysis" : "No unused security groups found",
            "description" : "The affected security groups have not been applied to any instances and therefore not in use. To maintain the hygiene of the environment, make maintenance and auditing easier and reduce the risk of security groups erroneously being used and inadvertently granting more access than required, all old unused security groups should be removed.",
            "remediation" : "Ensure all security groups that are temporary and not being used are deleted when no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_8")

        failing_security_groups = []
            
        for region, groups in self.security_groups.items():

            attached_security_group_ids = []
            network_interfaces = self.network_interfaces[region]
            for interface in network_interfaces:
                for group in interface["Groups"]:
                    attached_security_group_ids.append(group["GroupId"])

            for group in groups:
                if group["GroupName"] != "default":
                    if group["GroupId"] not in attached_security_group_ids:
                        failing_security_groups.append("{}({})".format(group["GroupId"], region))


        ### more elegant but slower way ###
        #failing_security_groups = []
        #    
        #for region, groups in self.security_groups.items():
        #    client = self.session.client('ec2', region_name=region)
        #    for group in groups:
        #        if group["GroupName"] != "default":
        #            group_id = group["GroupId"]
        #            network_interfaces = client.describe_network_interfaces(Filters=[{ "Name": "group-id", "Values" : [group_id] }])["NetworkInterfaces"]
        #            if not network_interfaces:
        #                failing_security_groups += ["{}({})".format(group_id, region)]

        if failing_security_groups:
            results["analysis"] = "the following security groups are not being used:\n{}".format(" ".join(failing_security_groups))
            results["affected"] = ", ".join(failing_security_groups)
            results["pass_fail"] = "FAIL"
        
        return results
    
    def ec2_9(self):
        # Unused elastic IPs

        results = {
            "id" : "ec2_9",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure there are no unused elastic IPs",
            "affected": "",
            "analysis" : "No unused elastic IPs found",
            "description" : "Although not a security risk, Amazon Web Services enforce a small hourly charge if an Elastic IP (EIP) address within your account is not associated with a running EC2 instance or an Elastic Network Interface (ENI). To ensure account hygiene and saves costs on your month bill it is recommended to release any elastic IPs that are no longer required.",
            "remediation" : "To release an Elastic IP address using the console: 1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/. 2. In the navigation pane, choose Elastic IPs. 3. Select the Elastic IP address, choose Actions, and then select Release addresses. Choose Release when prompted. More information: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_9")

        failing_addresses = []
            
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            addresses = client.describe_addresses()["Addresses"]
            failing_addresses += ["{}({})".format(address["AllocationId"], region) for address in addresses if ("NetworkInterfaceId","AssociationId") not in address]             

        if failing_addresses:
            results["analysis"] = "the following elastic IPs are not being used:\n{}".format(" ".join(failing_addresses))
            results["affected"] = ", ".join(failing_addresses)
            results["pass_fail"] = "FAIL"
        
        return results
    
    
    def ec2_10(self):
        # Public EBS snapshots

        results = {
            "id" : "ec2_10",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure there are no Public EBS Snapshots",
            "affected": "",
            "analysis" : "No Public EBS Snapshots found",
            "description" : "EBS Snapshots that are public are accessible by all AWS principals, and therefore anyone with an AWS account. To reduce the risk of sensitive data being exposed to unauthorised bearers only share EBS snapshots with trusted accounts.",
            "remediation" : "Remove public access from your EBS snapshots and only share them with trusted accounts.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_10")

        failing_snapshots = []
            
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            snapshots = client.describe_snapshots(OwnerIds=[self.account_id])["Snapshots"]
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
                                failing_snapshots += [snapshot_id]
                        except KeyError:
                            pass

        if failing_snapshots:
            results["analysis"] = "the following EBS snapshots are public:\n{}".format(" ".join(failing_snapshots))
            results["affected"] = ", ".join(failing_snapshots)
            results["pass_fail"] = "FAIL"
        
        return results

    def ec2_11(self):
        # Public AMI images

        results = {
            "id" : "ec2_11",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure there are no Public EC2 AMIs",
            "affected": "",
            "analysis" : "No Public AMIs found",
            "description" : "The reviewed AWS account contains an AWS AMI that is publicly accessible. When you make your AMIs publicly accessible, these become available in the Community AMIs where everyone with an AWS account can use them to launch EC2 instances. AMIs can contain snapshots of your applications (including their data), therefore exposing your snapshots in this manner is not advised. Ensure that your AWS AMIs are not publicly shared with the other AWS accounts in order to avoid exposing sensitive data. If required, you can share your images with specific AWS accounts without making them public",
            "remediation" : "Remove public access from your EC2 AMIs and only share them with trusted accounts.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_11")
            
        for region in self.regions:
            client = self.session.client('ec2', region_name=region)
            images = client.describe_images(Owners=["self"])["Images"]
            failing_images = [ "{}({})".format(image["ImageId"], region) for image in images if image["Public"] == True ]

        if failing_images:
            results["analysis"] = "the following EC2 AMIs are public:\n{}".format(" ".join(failing_images))
            results["affected"] = ", ".join(failing_images)
            results["pass_fail"] = "FAIL"
        
        return results



    def ec2_12(self):
        # Ensure no security groups allow ingress from 0.0.0.0/0 to database ports

        results = {
            "id" : "ec2_11",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure no security groups allow ingress from 0.0.0.0/0 to database ports",
            "affected": "",
            "analysis" : "No security groups that allow database ingress traffic from 0.0.0.0/0 found",
            "description" : "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no Security Groups allows unrestricted ingress access to database ports, such as MySQL to port 3306, PostgreSQL to port 5432 and MSSQL to port 1433. Public access to remote database ports increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow direct database traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_11")

        failing_security_groups = []
            
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
                                    failing_security_groups += ["{}({})".format(group_id, region)]
                                else:
                                    if from_port == 3306 or from_port == 5432 or from_port == 1433 or 3306 in range(from_port, to_port) or 5432 in range(from_port, to_port) or 1433 in range(from_port, to_port):
                                        failing_security_groups += ["{}({})".format(group_id, region)]
                    # ipv6
                    if "Ipv6Ranges" in ip_permission:
                        for ip_range in ip_permission["Ipv6Ranges"]:
                            if ip_range["CidrIpv6"] == "::/0":
                                try:
                                    from_port = ip_permission["FromPort"]
                                    to_port = ip_permission["ToPort"]
                                except KeyError:
                                    # if no port range is defined, all ports are allowed
                                    failing_security_groups += ["{}({})".format(group_id, region)]
                                else:
                                    if from_port == 3306 or from_port == 5432 or from_port == 1433 or 3306 in range(from_port, to_port) or 5432 in range(from_port, to_port) or 1433 in range(from_port, to_port):
                                        failing_security_groups += ["{}({})".format(group_id, region)]

        if failing_security_groups:
            results["analysis"] = "the following security groups allow database ingress traffic from 0.0.0.0/0:\n{}".format(" ".join(set(failing_security_groups)))
            results["affected"] = ", ".join(set(failing_security_groups))
            results["pass_fail"] = "FAIL"

        return results

    def ec2_13(self):
        # Ensure no Network ACLs allow ingress from 0.0.0.0/0 to database ports 

        results = {
            "id" : "ec2_13",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to database ports",
            "affected": "",
            "analysis" : "No NACLs that allow remote database ingress traffic from 0.0.0.0/0 found",
            "description" : "The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to database ports, such as MySQL to port 3306, PostgreSQL to port 5432 and MSSQL to port 1433. Public access to databse ports increases resource attack surface and unnecessarily raises the risk of resource compromise.",
            "remediation" : "Apply the principle of least privilege and only allow database traffic from a whitelist of trusted IP addresses",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_13")
        
        failing_nacls = []
            
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
                                    failing_nacls += ["{}({})".format(network_acl_id, region)]
                                else:
                                    if from_port in (3306, 5432, 1433) or 3306 in range(from_port, to_port) or 5432 in range(from_port, to_port) or 1433 in range(from_port, to_port):
                                        failing_nacls += ["{}({})".format(network_acl_id, region)]

        if failing_nacls:
            results["analysis"] = "the following Network ACLs allow database ingress traffic from 0.0.0.0/0:\,{}".format(" ".join(set(failing_nacls)))
            results["affected"] = ", ".join(set(failing_nacls))
            results["pass_fail"] = "FAIL"

        return results
    
    def ec2_14(self):
        # Ensure defualt Network ACLs are not defualt Allow

        results = {
            "id" : "ec2_14",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure default Network ACLs are not default allow",
            "affected": "",
            "analysis" : "No default Network ACLs that allow all traffic where found",
            "description" : "Network Access Control Lists (NACLs) are stateless firewalls that allow you to control traffic flow in and out of your VPCs at the subnet layer. By default, NACLs are configured to allow all inbound and outbound traffic. NACLs provide a first line of defence against malicious network traffic and can provide defence in depth when used alongside strict security groups. Configuring NACLs can minimise the risk of a misconfigured security group or weak default security group exposing sensitive or vulnerable services to the internet and can provide a separation of responsibilities between developers and architecture teams. All Network Access Control Lists within the tested account are currently configured to allow all inbound and outbound traffic on all ports.",
            "remediation" : "Configure all NACLs applying the principle of least privilege and only allows the traffic required for the application or service to function. NOTE: Because NACLs are stateless return traffic on ephemeral unprivileged ports will need to be accounted for. More Information http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_14")
        
        failing_nacls = []
            
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
                                        failing_nacls += ["{}({})".format(network_acl_id, region)]

        if failing_nacls:
            results["analysis"] = "the following default Network ACLs allow all traffic:\n{}".format(" ".join(set(failing_nacls)))
            results["affected"] = ", ".join(set(failing_nacls))
            results["pass_fail"] = "FAIL"

        return results

    def ec2_15(self):
        # Ensure custom Network ACLs are not defualt Allow

        results = {
            "id" : "ec2_15",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure custom Network ACLs do not allow all traffic",
            "affected": "",
            "analysis" : "No custom Network ACLs that allow all traffic where found",
            "description" : "Network Access Control Lists (NACLs) are stateless firewalls that allow you to control traffic flow in and out of your VPCs at the subnet layer. By default, NACLs are configured to allow all inbound and outbound traffic. NACLs provide a first line of defence against malicious network traffic and can provide defence in depth when used alongside strict security groups. Configuring NACLs can minimise the risk of a misconfigured security group or weak default security group exposing sensitive or vulnerable services to the internet and can provide a separation of responsibilities between developers and architecture teams. All Network Access Control Lists within the tested account are currently configured to allow all inbound and outbound traffic on all ports.",
            "remediation" : "Configure all NACLs applying the principle of least privilege and only allows the traffic required for the application or service to function. NOTE: Because NACLs are stateless return traffic on ephemeral unprivileged ports will need to be accounted for. More Information http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_15")
        
        failing_nacls = []
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
                                        failing_nacls += ["{}({})".format(network_acl_id, region)]

        if not custom_nacls:
            results["analysis"] = "No Custom Network ACLs found"
            results["pass_fail"] = "PASS"        
        
        if failing_nacls:
            results["analysis"] = "the following custom Network ACLs allow all traffic:\n{}".format(" ".join(set(failing_nacls)))
            results["affected"] = ", ".join(set(failing_nacls))
            results["pass_fail"] = "FAIL"

        return results
    
    def ec2_16(self):
        # unused network interfaces

        results = {
            "id" : "ec2_16",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Unused Network Interfaces",
            "affected": "",
            "analysis" : "No unused Network Interfaces found",
            "description" : "The affected Network Interfaces, are not attached to any instances and therefore are not being used. To maintain the hygiene of the environment, make maintenance and auditing easier and reduce cost, all old and temporary network interfaces should be removed.",
            "remediation" : "remove network interfaces that are not in use and no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_16")

        failing_interfaces = []

        for region, interfaces in self.network_interfaces.items():
            for interface in interfaces:
                if interface["Status"] == "available":
                    failing_interfaces.append("{}({})".format(interface["NetworkInterfaceId"], region))
        
        if failing_interfaces:
            results["analysis"] = "the following network interfacces are not being used:\n{}".format(" ".join(failing_interfaces))
            results["affected"] = ", ".join(failing_interfaces)
            results["pass_fail"] = "FAIL"

        return results


    def ec2_17(self):
        # Ensure running instances are not more than 365 days old

        results = {
            "id" : "ec2_17",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure running instances are not more than 365 days old",
            "affected": "",
            "analysis" : "No instances older than 365 days found",
            "description" : "The account under review contains running EC2 instances that were launched more than 365 days ago. One of the biggest benefits of cloud based infrastructure is to have mutable and short lived infrastructure that can scale and shrink with demand. Instances should be reprovisioned and rebooted periodically to ensure software and hardware resources are up to date and subject to the latest security patches. Additionally, long lived instances may no longer be adequately sized or no longer required, consuming resources and generating a cost to the company.",
            "remediation" : "Review the list of instances and ensure they subject to a regular patching policy and lifecycle management.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "info",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_17")

        failing_instances = []
       
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "running":
                        year, month, day = str(instance["LaunchTime"]).split(" ")[0].split("-") #convert datetime to string so it can be converted to date and compare with time delta
                        launch_date = date(int(year), int(month), int(day)) # extract date, ignore time
                        if launch_date < (date.today() - timedelta(days=365)):
                            failing_instances.append("{}({})".format(instance["InstanceId"], region))

        if failing_instances:
            results["analysis"] = "the following running instances do not have an instance profile attached:\n{}".format(" ".join(failing_instances))
            results["affected"] = ", ".join(failing_instances)
            results["pass_fail"] = "FAIL"

        return results
    
    def ec2_18(self):
        # Ensure EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required

        results = {
            "id" : "ec2_18",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Ensure EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required",
            "affected": "",
            "analysis" : "No failing instances found",
            "description" : "The account under review contains EC2 instances that do not enforce the use of IMDSv2.\nTo help protect against Server Side Request Forgery (SSRF) and related vulnerabilities, which could be leveraged by an attacker to query the metadata service to steal the AWS API credentials associated with the instance profile for the running EC2 instance, AWS introduced IMDSv2 which now protects all requests with additional session authentication.",
            "remediation" : "Configure IMDSv2 on all affected EC2 instances. See the following link for more information on how to transition to version 2 of the metadata service.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_18")

        failing_instances = []
       
        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["MetadataOptions"]["HttpEndpoint"] == "enabled":
                        if instance["MetadataOptions"]["HttpTokens"] != "required":
                            failing_instances.append("{}({})".format(instance["InstanceId"], region))

        if failing_instances:
            results["analysis"] = "the following running instances do not have IMDSv2 enabled:\n{}".format(" ".join(failing_instances))
            results["affected"] = ", ".join(failing_instances)
            results["pass_fail"] = "FAIL"

        return results

    def ec2_19(self):
        # EC2 Instances Not Managed By AWS Systems Manager

        results = {
            "id" : "ec2_19",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "EC2 Instances Not Managed By AWS Systems Manager",
            "affected": "",
            "analysis" : "No failing instances found",
            "description" : "The account under review contains running EC2 instances that are not managed by AWS Systems Manager. Systems Manager simplifies resource and application management, shortens the time to detect and resolve operational problems, and makes it easier to operate and manage your infrastructure at scale.\nAWS Systems Manager helps maintain security and compliance by scanning your instances against your patch, configuration, and custom policies. You can define patch baselines, maintain up-to-date anti-virus definitions, and enforce firewall policies. You can also remotely manage your servers at scale without manually logging in to each server. Systems Manager also provides a centralized store to manage your configuration data, whether it's plain text, such as database strings, or secrets, such as passwords. This allows you to separate your secrets and configuration data from code.",
            "remediation" : "It is recommended to configure all EC2 instances to be monitored by Systems Manager by installing and registering the SSM agent on the affected hosts.\nMore Information\nhttps://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_19")

        failing_instances = []
       
        for region, reservations in self.instance_reservations.items():
            client = self.session.client('ssm', region_name=region)
            managed_instances = [ instance["InstanceId"] for instance in client.describe_instance_information()["InstanceInformationList"] ]
            
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    if instance["InstanceId"] not in managed_instances:
                        failing_instances.append("{}({})".format(instance["InstanceId"], region))

        if failing_instances:
            results["analysis"] = "the following running instances are not managed by Systems Manager:\n{}".format(" ".join(failing_instances))
            results["affected"] = ", ".join(failing_instances)
            results["pass_fail"] = "FAIL"

        return results


    def ec2_20(self):
        # Unencrypted EBS Volumes

        results = {
            "id" : "ec2_20",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Unencrypted EBS Volumes",
            "affected": "",
            "analysis" : "All EBS Volumes are encrypted",
            "description" : "To ensure the privacy of any data stored and processed by your EC2 instances it is recommended to enable encryption on EBS volumes. When you create an encrypted EBS volume and attach it to a supported instance type, the following types of data are encrypted:\n\n- Data at rest inside the volume\n- All data moving between the volume and the instance\n- All snapshots created from the volume\n- All volumes created from those snapshots ",
            "remediation" : "There is no direct way to encrypt an existing unencrypted volume, or to remove encryption from an encrypted volume. However, you can migrate data between encrypted and unencrypted volumes. You can also apply a new encryption status while copying a snapshot:\nMore information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_20")
        
        failing_volumes = []
        
        for region, volumes in self.volumes.items():
            failing_volumes += [ "{}({})".format(volume["VolumeId"], region) for volume in volumes if volume["Encrypted"] == False ]
        
        if failing_volumes:
                results["analysis"] = "the following Volumes are not encrypted:\n{}".format(" ".join(failing_volumes))
                results["affected"] = ", ".join(failing_volumes)
                results["pass_fail"] = "FAIL"
        
        
        return results
    
    def ec2_21(self):
        # Unencrypted EBS Snapshots

        results = {
            "id" : "ec2_21",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Unencrypted EBS Snapshots",
            "affected": "",
            "analysis" : "All EBS Snapshots are encrypted",
            "description" : "To ensure the privacy of any data stored and processed by your EC2 instances it is recommended to enable encryption on EBS volumes. When you create an encrypted EBS volume and attach it to a supported instance type, the following types of data are encrypted:\n\n- Data at rest inside the volume\n- All data moving between the volume and the instance\n- All snapshots created from the volume\n- All volumes created from those snapshots ",
            "remediation" : "There is no direct way to encrypt an existing unencrypted volume, or to remove encryption from an encrypted volume. However, you can migrate data between encrypted and unencrypted volumes. You can also apply a new encryption status while copying a snapshot:\nMore information\nhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_21")
        
        failing_snapshots = []
        
        for region, snapshots in self.snapshots.items():
            failing_snapshots += [ "{}({})".format(snapshot["SnapshotId"], region) for snapshot in snapshots if snapshot["Encrypted"] == False ]
        
        if failing_snapshots:
                results["analysis"] = "the following Snapshots are not encrypted:\n{}".format(" ".join(failing_snapshots))
                results["affected"] = ", ".join(failing_snapshots)
                results["pass_fail"] = "FAIL"
        
        return results
    
    def ec2_22(self):
        # Snapshots older than 30 days

        results = {
            "id" : "ec2_22",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Snapshot older than 30 days",
            "affected": "",
            "analysis" : "All EBS Snapshots are encrypted",
            "description" : "With an active EBS backup strategy that takes volume snapshots daily or weekly, your data can grow rapidly and add unexpected charges to your bill. Since AWS EBS volumes snapshots are incremental, deleting previous (older) snapshots do not affect the ability to restore the volume data from later snapshots which allows you keep just the necessary backup data and lower your AWS monthly costs.",
            "remediation" : "Delete snapshots that are older than 30 days and consider implementing snapshot lifecycle management in AWS DLM",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_22")
        
        failing_snapshots = []
        
        for region, snapshots in self.snapshots.items():
            for snapshot in snapshots:
                year, month, day = str(snapshot["StartTime"]).split(" ")[0].split("-") #convert datetime to string so it can be converted to date and compare with time delta
                start_date = date(int(year), int(month), int(day)) # extract date, ignore time
                if start_date < (date.today() - timedelta(days=30)):
                    failing_snapshots.append("{}({})".format(snapshot["SnapshotId"], region))
        
        if failing_snapshots:
                results["analysis"] = "the following Volumes are not encrypted:\n{}".format(" ".join(failing_snapshots))
                results["affected"] = ", ".join(failing_snapshots)
                results["pass_fail"] = "FAIL"
        
        return results
    
    def ec2_23(self):
        # default VPCs in use

        results = {
            "id" : "ec2_23",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "ec2",
            "name" : "Default VPCs in use",
            "affected": "",
            "analysis" : "No Default VPCs in use",
            "description" : "Default VPCs created by AWS can be considered overly permissive and it is recomened to create you own VPCs instead. Default VPCs include an internet gateway, default security groups and default allow all NACLs which could result in accidental exposure of EC2 instances and data to the internet.",
            "remediation" : "Create you own VPCs as required applying the priciple of least privilege to network access controls",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_23")
        
        failing_vpcs = []

        for region, reservations in self.instance_reservations.items():
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    for vpc in self.vpcs[region]:
                        if vpc["VpcId"] == instance["VpcId"]:
                            if vpc["IsDefault"] == True:
                                failing_vpcs.append("{}({})".format(vpc["VpcId"], region))
        
        if failing_vpcs:
                results["analysis"] = "the following Volumes are not encrypted:\n{}".format(" ".join(failing_vpcs))
                results["affected"] = ", ".join(failing_vpcs)
                results["pass_fail"] = "FAIL"
        
        return results