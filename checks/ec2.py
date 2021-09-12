import boto3

from utils.utils import describe_regions

class ec2(object):

    def __init__(self):
        self.regions = describe_regions()

    def run(self):
        findings = []
        findings += [ self.ec2_1() ]
        findings += [ self.ec2_2() ]
        findings += [ self.ec2_3() ]
        findings += [ self.ec2_4() ]
        findings += [ self.ec2_5() ]
        findings += [ self.ec2_6() ]
        findings += [ self.ec2_7() ]
        return findings

    def ec2_1(self):
        # Ensure IAM instance roles are used for AWS resource access from instances (Manual)

        results = {
            "id" : "ec2_1",
            "ref" : "1.18",
            "compliance" : "cis",
            "level" : 2,
            "service" : "ec2",
            "name" : "Ensure IAM instance roles are used for AWS resource access from instances",
            "affected": "",
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

        for region in self.regions:
            client = boto3.client('ec2', region_name=region)
            instance_description = client.describe_instances()
            reservations = instance_description["Reservations"]
            for reservation in reservations:
                instances = reservation["Instances"]
                for instance in instances:
                    state = instance["State"]["Name"]
                    if state == "running":
                        instance_id = instance["InstanceId"]
                        ec2 = boto3.resource('ec2', region_name=region)
                        ec2_instance = ec2.Instance(id=instance_id)
                        if not ec2_instance.iam_instance_profile:
                            failing_instances += ["{}({})".format(instance_id, region)]

        if failing_instances:
            results["analysis"] = "the following running instances do not have an instance profile attached: {}".format(" ".join(failing_instances))
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
            "analysis" : "All EBS Volumes are encrypted",
            "description" : "Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported. Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.",
            "remediation" : "Ensure EBS defualt volume encryption is enabled in all regions",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: ec2_2")
        
        failing_regions = []
        
        for region in self.regions:
            client = boto3.client('ec2', region_name=region)
            if client.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] == False:
                failing_regions += [region]
        
        if failing_regions:
            results["pass_fail"] = "FAIL"

            if set(failing_regions) == set(self.regions):
                results["analysis"] = "Default Encryption is not enabled in any region"
                results["affected"] = ", ".join(self.regions)
            else:
                results["analysis"] = "the following EC2 regions do not encrypt EBS volumes by default: {}".format(" ".join(failing_regions))
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
            client = boto3.client('ec2', region_name=region)
            flow_logs = client.describe_flow_logs()["FlowLogs"]
            if not flow_logs:
                failing_regions += [region]
            

        if failing_regions:
            results["pass_fail"] = "FAIL"

            if set(failing_regions) == set(self.regions):
                results["analysis"] = "VPC Flow logging is not enabled in any region"
                results["affected"] = ", ".join(self.regions)
            else:
                results["analysis"] = "the following regions do not have any VPC FLow Logs enabled: {}".format(" ".join(failing_regions))
                results["affected"] = ", ".join(failing_regions)
        
        return results

    def ec2_4(self):
        # Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        cis_dict = {
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
            
        for region in self.regions:
            client = boto3.client('ec2', region_name=region)
            network_acls = client.describe_network_acls()["NetworkAcls"]
            for acl in network_acls:
                network_acl_id = acl["NetworkAclId"]
                entries = acl["Entries"]
                for entry in entries:
                    if entry["Egress"] == False:
                        if entry["RuleAction"] == "allow":
                            if entry["CidrBlock"] == "0.0.0.0/0":
                                failing_nacls += ["{}({})".format(network_acl_id, region)]
        if failing_nacls:
            cis_dict["analysis"] = "the following Network ACLs allow allow ingress traffic from 0.0.0.0/0: {}".format(" ".join(failing_nacls))
            cis_dict["affected"] = ", ".join(failing_nacls)
            cis_dict["pass_fail"] = "CHECK"

        return cis_dict


    def ec2_5(self):
        # Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)

        cis_dict = {
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
            
        for region in self.regions:
            client = boto3.client('ec2', region_name=region)
            security_groups = client.describe_security_groups()["SecurityGroups"]
            for group in security_groups:
                group_id = group["GroupId"]
                ip_permissions = group["IpPermissions"]
                for ip_permission in ip_permissions:
                    try:
                        if ip_permission["FromPort"] == 22 or ip_permission["FromPort"] == 3389:
                            for ip_range in ip_permission["IpRanges"]:
                                if ip_range["CidrIp"] == "0.0.0.0/0":
                                    failing_security_groups += ["{}({})".format(group_id, region)]
                    except KeyError:
                        pass

        if failing_security_groups:
            cis_dict["analysis"] = "the following security groups allow admin ingress traffic from 0.0.0.0/0: {}".format(" ".join(failing_security_groups))
            cis_dict["affected"] = ", ".join(failing_security_groups)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    
    def ec2_6(self):
        # Ensure the default security group of every VPC restricts all traffic (Automated)

        cis_dict = {
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
            
        for region in self.regions:
            client = boto3.client('ec2', region_name=region)
            security_groups = client.describe_security_groups()["SecurityGroups"]
            for group in security_groups:
                group_id = group["GroupId"]
                if group["GroupName"] == "default":
                    if group["IpPermissions"]:
                        failing_security_groups += ["{}({})".format(group_id, region)]
                    
        if failing_security_groups:
            cis_dict["analysis"] = "the following default security groups have inbound rules configured: {}".format(" ".join(failing_security_groups))
            cis_dict["affected"] = ", ".join(failing_security_groups)
            cis_dict["pass_fail"] = "FAIL"

        return cis_dict
    
    def ec2_7(self):
        # Ensure routing tables for VPC peering are "least access" (Manual)

        cis_dict = {
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
            client = boto3.client('ec2', region_name=region)
            route_tables = client.describe_route_tables()["RouteTables"]
            for route_table in route_tables:
                for route in route_table["Routes"]:
                    try:
                        vpc_peering_connection_id = route["VpcPeeringConnectionId"]
                    except KeyError:
                        pass
                    else:
                        peering_connections += ["{}({})".format(vpc_peering_connection_id, region)]
                    
        if peering_connections:
            cis_dict["analysis"] = "VPC peering in use - check routing tables for least access: {}".format(" ".join(set(peering_connections)))
            cis_dict["pass_fail"] = "INFO"

        return cis_dict