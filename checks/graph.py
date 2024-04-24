import requests
import json

import logging
import re

class graph(object):

    def __init__(self, credential, tenant):
        self.credential = credential
        self.tenant = tenant
        self.access_token = credential.get_token("https://graph.microsoft.com/.default").token
        self.headers = {"Authorization": "Bearer " + self.access_token}
        self.skus = self.get_skus()
        self.premium = self.get_premium()
        self.users = self.get_users()
        #self.user_roles = self.get_user_roles()
        self.guests = self.get_guests()
        self.roles = self.get_roles()
        self.global_admins = self.get_global_admins()
        self.conditional_access_policies = self.get_conditional_access_policies()
        self.applications = self.get_applications()
        self.service_principals = self.get_service_principals()
        self.service_principal_roles = self.get_service_principal_roles()
        self.application_administrators = self.get_application_administrators()

    def get_skus(self):
        url = "https://graph.microsoft.com/v1.0/subscribedSkus"
        logging.info(f'getting skus')
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting skus: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting skus: , access denied:')
            else:
                logging.error(f'error getting skus: { response.status_code }')
    def get_premium(self):
        for sku in self.skus:
            if re.match("AAD_PREMIUM*", sku["skuPartNumber"]):
                logging.info("azure ad premium in use")
                return True


    def get_users(self):
        url = "https://graph.microsoft.com/v1.0/users"
        users = []
        while True:
            try:
                logging.info(f'getting users')
                response = requests.get(url, headers=self.headers)
            except Exception as e:
                logging.error(f'error getting users: , error: { e }')
            else:
                if response.status_code == 200:
                    for user in response.json()["value"]:
                        users.append(user)
                    try:
                        url = response.json()["@odata.nextLink"]
                    except KeyError:
                        return users
                        break
                elif response.status_code == 403:
                    logging.error(f'error getting users: , access denied')
                else:
                    logging.error(f'error getting users: { response.status_code }')
        return users

    #def get_user_roles(self):
        #user_roles = {}
        #logging.info(f'getting user roles')
        #for user in self.users:
            #logging.info(f'getting roles for user { user["displayName"] }')
            #url = f"https://graph.microsoft.com/v1.0/users/{ user['id'] }/memberOf"
            #try:
                #response = requests.get(url, headers=self.headers)
            #except Exception as e:
                #logging.error(f'error getting role for user { user["displayName"] }: , error: { e }')
            #else:
                #if response.status_code == 200:
                    #if response.json()["value"]:
                        #user_roles[user["displayName"]] = response.json()["value"]
                #elif response.status_code == 403:
                    #logging.error(f'error getting user roles: , access denied:')
                #else:
                    #logging.error(f'error getting user roles: { response.status_code }')
#
        #return user_roles

    def get_user_roles(self, user):
        user_roles = ""
        logging.info(f'getting roles for user { user["displayName"] }')
        url = f"https://graph.microsoft.com/v1.0/users/{ user['id'] }/memberOf"
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting role for user { user["displayName"] }: , error: { e }')
        else:
            if response.status_code == 200:
                if response.json()["value"]:
                    user_roles = response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting user roles: , access denied:')
            else:
                logging.error(f'error getting user roles: { response.status_code }')
        return user_roles

    def get_guests(self):
        url = "https://graph.microsoft.com/v1.0/users/?$filter=userType eq 'Guest'"
        logging.info(f'getting users')
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting users: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting conditional access policies: , access denied: Policy.Read.All required')
            else:
                logging.error(f'error getting conditional access policies: { response.status_code }')

    def get_roles(self):
        url = "https://graph.microsoft.com/v1.0/directoryRoles"
        logging.info(f'getting roles')
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting roles: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting roles: , access denied:')
            else:
                logging.error(f'error getting roles: { response.status_code }')

    def get_global_admins(self):
        logging.info(f'getting global admins')
        for role in self.roles:
            if role["displayName"] == "Global Administrator":
                id = role["id"]
                url = f"https://graph.microsoft.com/v1.0/directoryRoles/{ id }/members"
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting roles: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting roles: , access denied:')
            else:
                logging.error(f'error getting roles: { response.status_code }')


    def get_conditional_access_policies(self):
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        logging.info(f'getting conditional access policies')
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting conditional access policies: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting conditional access policies: , access denied: Policy.Read.All required')
            else:
                logging.error(f'error getting conditional access policies: { response.status_code }')

    def get_applications(self):
        url = "https://graph.microsoft.com/v1.0/applications"
        logging.info(f'getting applications')
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting application: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting applications: , access denied:')
            else:
                logging.error(f'error getting applications: { response.status_code }')

    def get_service_principals(self):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        logging.info(f'getting service principals')
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting service principals: , error: { e }')
        else:
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 403:
                logging.error(f'error getting service principals: , access denied:')
            else:
                logging.error(f'error getting service principals: { response.status_code }')

    def get_service_principal_roles(self):
        service_principal_roles = {}
        logging.info(f'getting service principal directory roles')
        for service_principal in self.service_principals:
            url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{ service_principal['id'] }/memberOf"
            try:
                response = requests.get(url, headers=self.headers)
            except Exception as e:
                logging.error(f'error getting role for service principal { service_principal["displayName"] }: , error: { e }')
            else:
                if response.status_code == 200:
                    if response.json()["value"]:
                        service_principal_roles[service_principal["displayName"]] = response.json()["value"]
                elif response.status_code == 403:
                    logging.error(f'error getting service principal roles: , access denied:')
                else:
                    logging.error(f'error getting service principal roles: { response.status_code }')

        return service_principal_roles

    def get_application_administrators(self):
        application_administrators = []
        for role in self.roles:
            if role["displayName"] == "Cloud Application Administrator" or role["displayName"] == "Application Administrator":
                url = f"https://graph.microsoft.com/v1.0/directoryRoles/{ role['id'] }/members"
                try:
                    response = requests.get(url, headers=self.headers)
                except Exception as e:
                    logging.error(f'error getting application administrators: , error: { e }')
                else:
                    if response.status_code == 200:
                        for member in response.json()["value"]:
                            application_administrators.append(member)
                    elif response.status_code == 403:
                        logging.error(f'error getting application administrators: , access denied:')
                    else:
                        logging.error(f'error getting application administrators: { response.status_code }')

        return application_administrators

    def run(self):
        findings = []
        findings += [ self.graph_1() ]
        findings += [ self.graph_2() ]
        findings += [ self.graph_3() ]
        findings += [ self.graph_4() ]
        findings += [ self.graph_5() ]
        findings += [ self.graph_6() ]
        findings += [ self.graph_7() ]
        findings += [ self.graph_8() ]
        findings += [ self.graph_9() ]
        findings += [ self.graph_10() ]
        findings += [ self.graph_11() ]
        findings += [ self.graph_12() ]
        findings += [ self.graph_13() ]
        findings += [ self.graph_14() ]
        findings += [ self.graph_15() ]
        findings += [ self.graph_16() ]
        findings += [ self.graph_17() ]
        findings += [ self.graph_18() ]
        findings += [ self.graph_19() ]
        findings += [ self.graph_20() ]
        findings += [ self.graph_21() ]
        findings += [ self.graph_22() ]
        findings += [ self.graph_23() ]
        findings += [ self.graph_24() ]
        findings += [ self.graph_25() ]
        findings += [ self.graph_26() ]
        findings += [ self.graph_27() ]
        findings += [ self.graph_28() ]
        findings += [ self.graph_29() ]
        findings += [ self.graph_30() ]
        findings += [ self.graph_31() ]
        findings += [ self.graph_32() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.graph_1() ]
        return findings

    def graph_1(self):
        # Ensure Security Defaults is enabled on Microsoft Entra ID (CIS)

        results = {
            "id" : "graph_1",
            "ref" : "1.1.1",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure Security Defaults is enabled on Microsoft Entra ID (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Security defaults in Microsoft Entra ID make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks. \nSecurity defaults is available to everyone. The goal is to ensure that all organizations have a basic level of security enabled at no extra cost. You may turn on security defaults in the Azure portal.\nSecurity defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.\nFor example, doing the following:\n• Requiring all users and admins to register for MFA.\n• Challenging users with MFA - when necessary, based on factors such as location, device, role, and task.\n• Disabling authentication from legacy authentication clients, which can’t do MFA.\nThis recommendation should be implemented initially and then may be overridden by other service/product specific CIS Benchmarks. Administrators should also be aware that certain configurations in Microsoft Entra ID may impact other Microsoft services such as Microsoft 365.",
            "remediation" : "To enable security defaults in your directory:\n1. From Azure Home select the Portal Menu.\n2. Browse to Microsoft Entra ID > Properties\n3. Select Manage security defaults\n4. Set the Enable security defaults to Enabled\n5. Select Save",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.premium:
            url = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy/"

            try:
                response = requests.get(url, headers=self.headers)
            except Exception as e:
                logging.error(f'error getting security defaults: , error: { e }')
            else:
                if response.status_code == 200:
                    if response.json()["isEnabled"] != True:
                        results["analysis"] = "Security Defaults is disabled."
                        results["affected"].append(self.tenant)

            if results["affected"]:
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"

        return results

    def graph_2(self):
        # Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users (CIS)

        results = {
            "id" : "graph_2",
            "ref" : "1.1.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Enable multi-factor authentication for all roles, groups, and users that have write access or permissions to Azure resources. These include custom created objects or built-in roles such as;\n• Service Co-Administrators\n• Subscription Owners\n• Contributors\n\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\nUsers would require two forms of authentication before any access is granted. Additional administrative time will be required for managing dual forms of authentication when enabling multi-factor authentication.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID blade\n3. Select Users\n4. Take note of all users with the role Service Co-Administrators, Owners or\nContributors\n5. Click on the Per-User MFA button in the top row menu\n6. Check the box next to each noted user\n7. Click Enable under quick steps in the right-hand panel\n8. Click enable multi-factor auth\n9. Click close",
            "impact" : "high",
            "probability" : "high",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score" : "9.1",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.premium:
            for user in self.global_admins:
                try:
                    url = f"https://graph.microsoft.com/v1.0/users/{ user['id'] }/authentication/methods"
                    response = requests.get(url, headers=self.headers)
                except Exception as e:
                    logging.error(f'error getting security defaults: , error: { e }')
                else:
                    if response.status_code == 200:
                        enabled = False
                        authentication_methods = response.json()["value"]
                        for method in authentication_methods:
                            if method["@odata.type"] == "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#emailAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#fido2AuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#phoneAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#microsoft.graph.softwareOathAuthenticationMethod":
                                enabled = True
                        if not enabled:
                            results["affected"].append(user["userPrincipalName"])

                    if response.status_code == 404:
                        logging.error(f'{ user["mail"] } user not found')

            if results["affected"]:
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"

        return results
    def graph_3(self):
        # Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users (CIS)

        results = {
            "id" : "graph_3",
            "ref" : "1.1.3",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Enable multi-factor authentication for all non-privileged users.\nMulti-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.\n Users would require two forms of authentication before any access is granted. Also, this requires an overhead for managing dual forms of authentication.",
            "remediation" : "Follow Microsoft Azure documentation and enable multi-factor authentication in your environment.\nhttps://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa\nEnabling and configuring MFA is a multi-step process. Here are some additional resources on the process within Microsoft Entra ID:\nhttps://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa\nhttps://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-getstarted#enable-multi-factor-authentication-with-conditional-access\nhttps://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.premium:
            for user in self.users:
                try:
                    url = f"https://graph.microsoft.com/v1.0/users/{ user['id'] }/authentication/methods"
                    response = requests.get(url, headers=self.headers)
                except Exception as e:
                    logging.error(f'error getting security defaults: , error: { e }')
                else:
                    if response.status_code == 200:
                        enabled = False
                        authentication_methods = response.json()["value"]
                        for method in authentication_methods:
                            if method["@odata.type"] == "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#emailAuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#fido2AuthenticationMethod":
                                enabled = True
                            if method["@odata.type"] == "#phoneAuthenticationMethod":
                                enabled = True

                        if not enabled:
                            results["affected"].append(user["userPrincipalName"])

                    if response.status_code == 404:
                        logging.error(f'{ user["mail"] } user not found')



            if results["affected"]:
                results["pass_fail"] = "FAIL"
            else:
                results["pass_fail"] = "PASS"

        return results

    def graph_4(self):
        # Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled (CIS)(Manual)

        results = {
            "id" : "graph_4",
            "ref" : "1.1.3",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled (CIS)(Manual)",
            "affected": [],
            "analysis" : {},
            "description" : "Do not allow users to remember multi-factor authentication on devices.\nRemembering Multi-Factor Authentication (MFA) for devices and browsers allows users to have the option to bypass MFA for a set number of days after performing a successful sign-in using MFA. This can enhance usability by minimizing the number of times a user may need to perform two-step verification on the same device. However, if an account or device is compromised, remembering MFA for trusted devices may affect security. Hence, it is recommended that users not be allowed to bypass MFA.\nFor every login attempt, the user will be required to perform multi-factor authentication",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Click the Per-user MFA button on the top bar\n5. Click on service settings\n6. Uncheck the box next to Allow users to remember multi-factor authentication on devices they trust",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check -From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select Password reset\n5. Then Registration\n6. Ensure that Number of days before users are asked to re-confirm their\nauthentication information is not set to 0 "
        results["pass_fail"] = "INFO"

        return results


    def graph_5(self):
        # Lack Of Conditional Access (CIS)

        results = {
            "id" : "greph_5",
            "ref" : "1.2.1-7",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Lack Of Conditional Access (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "The account under review did not implement a comprehensive set of conditional access policies to control user authentication and resource access. Securing the identity of users, especially administrators, is fundamental to protecting your cloud environment from unauthorised access and data compromise.\nOne of the Azure key security principles states to explicitly validate trusted signals to allow or deny user access to resources, as part of a zero-trust access model. Signals to validate should include strong authentication of user accounts, behavioural analytics of user accounts, device trustworthiness, user or group membership and trusted locations etc. Additionally enforcing a time out for MFA will help ensure that sessions are not kept alive for an indefinite period of time and ensuring that browser sessions are not persistent will help in prevention of drive-by attacks in web browsers. This configuration also prevents the creation and saving of user-based session cookies which prevents an attacker from leveraging compromised sessions to access a Tenant.",
            "remediation" : "For organisations which maintain the appropriate licenses (Azure AD Premium P1 minimum), Azure Conditional Access policies should be utilised to assist a zero-trust architecture through granular access controls and organisational policies.\nConditional access policies can be based on common signals such as, user and group membership, IP location, device type and application access and can be used to block or grant access based on several options such as compliance and MFA. Organisations should review the applications and services in use within a Tenant and configure conditional access policies that define the required criteria under which users are able to access resources. \nThe following common use cases should be considered: \nRequiring multi-factor authentication for users with administrative roles. \nRequiring multi-factor authentication for all users. \nRequiring multi-factor authentication for Azure management tasks \nBlocking sign-ins for users attempting to use legacy authentication protocols. \nRequiring trusted locations for Azure AD Multi-Factor Authentication registration \nBlocking access from geographic locations that are deemed out-of-scope for your organization or application. \nDefine Trusted Locations from which access can be limited to. \nBlocking risky sign-in behaviours. \nRequiring organization-managed devices for specific applications. \nCreate a policy that specifies Sign-in frequency set to the time determined by your organization and that Persistent browser session is set to Never persistent. \nCreate a policy to block access to the Microsoft Azure Management Cloud Apps for non-administrative users. \nFurther Information \nhttps://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions \nhttps://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-cloud-apps \nhttps://www.cisecurity.org/benchmark/azure - section 1.2",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if self.premium:
            if not self.conditional_access_policies:
                results["affected"].append(self.tenant)
                results["analysis"] = "No conditional access policies in use"
            else:
                for policy in self.conditional_access_policies:
                    print(policy)
        else:
            results["analysis"] = "Azure AD Premium not in use"


        if results["affected"]:
            results["pass_fail"] = "FAIL"

        return results


    def graph_6(self):
        # Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes' (Manual)

        results = {
            "id" : "graph_6",
            "ref" : "1.3",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Require administrators or appropriately delegated users to create new tenants. It is recommended to only allow an administrator to create new tenants. This prevent users from creating new Microsoft Entra ID or Azure AD B2C tenants and ensures that only authorized users are able to do so. Enforcing this setting will ensure that only authorized users are able to create new tenants.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Select User settings\n5. Set Restrict non-admin users from creating tenants to Yes",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check\n1. From Azure Home select the Portal Menu \n2. Select Microsoft Entra ID\n3. Select Users\n4. Select User settings\n5. Ensure that Restrict non-admin users from creating tenants is set to Yes"
        results["pass_fail"] = "INFO"

        return results

    def graph_7(self):
        # Ensure Guest Users Are Reviewed on a Regular Basis (CIS)

        results = {
            "id" : "graph_7",
            "ref" : "1.4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure Guest Users Are Reviewed on a Regular Basis (CIS)",
            "affected": [],
            "analysis" : [],
            "description" : "Microsoft Entra ID is extended to include Azure AD B2B collaboration, allowing you to invite people from outside your organization to be guest users in your cloud account and sign in with their own work, school, or social identities. Guest users allow you to share your company's applications and services with users from any other organization, while maintaining control over your own corporate data. Work with external partners, large or small, even if they don't have Azure AD or an IT department. A simple invitation and redemption process lets partners use their own credentials to access your company's resources as a guest user. Guest users in every subscription should be review on a regular basis to ensure that inactive and unneeded accounts are removed.\nGuest users in the Microsoft Entra ID are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants. Guest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely, leading to a potential vulnerability. To prevent this, guest users should be reviewed on a regular basis. During this audit, guest users should also be determined to not have administrative privileges.\nBefore removing guest users, determine their use and scope. Like removing any user, there may be unforeseen consequences to systems if it is deleted.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Click on Add filter\n5. Select User type\n6. Select Guest from the Value dropdown\n7. Click Apply\n8. Delete all Guest users that are no longer required or are inactive",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if not self.guests:
            results["analysis"] = f"no guest users found"
        else:
            for user in self.guests:
                results["affected"].append(self.tenant)
                results["analysis"].append(user["userPrincipalName"])
                results["pass_fail"] = "INFO"

        return results

    def graph_8(self):
        # Ensure That 'Number of methods required to reset' is set to '2' (CIS)(Manual)

        results = {
            "id" : "graph_8",
            "ref" : "1.5",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure That 'Number of methods required to reset' is set to '2' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Ensures that two alternate forms of identification are provided before allowing a password reset.\n A Self-service Password Reset (SSPR) through Azure Multi-factor Authentication (MFA) ensures the user's identity is confirmed using two separate methods of identification. With multiple methods set, an attacker would have to compromise both methods before they could maliciously reset a user's password.\n There may be administrative overhead, as users who lose access to their secondary authentication methods will need an administrator with permissions to remove it. There will also need to be organization-wide security policies and training to teach administrators to verify the identity of the requesting user so that social engineering can not render this setting useless.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select Password reset\n5. Then Authentication methods\n6. Set the Number of methods required to reset to 2",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check\nFrom Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select Password reset\n5. Then Authentication methods\n6. Ensure that Number of methods required to reset is set to 2"
        results["pass_fail"] = "INFO"

        return results

    def graph_9(self):
        # Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization (CIS)(Manual)

        results = {
            "id" : "graph_9",
            "ref" : "1.6",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization (CIS)(MANUAL)",
            "affected": [],
            "analysis" : [],
            "description" : "Microsoft Azure provides a Global Banned Password policy that applies to Azure administrative and normal user accounts. This is not applied to user accounts that are synced from an on-premise Active Directory unless Microsoft Entra ID Connect is used and you enable EnforceCloudPasswordPolicyForPasswordSyncedUsers. Please see the list in default values on the specifics of this policy. To further password security, it is recommended to further define a custom banned password policy.\nEnabling this gives your organization further customization on what secure passwords are allowed. Setting a bad password list enables your organization to fine-tune its password policy further, depending on your needs. Removing easy-to-guess passwords increases the security of access to your Azure resources.\nIncreasing needed password complexity might increase overhead on administration of user accounts. Licensing requirement for Global Banned Password List and Custom Banned Password list requires Microsoft Entra ID P1 or P2. On-premises Active Directory Domain Services users that are not synchronized to Microsoft Entra ID also benefit from Microsoft Entra ID Password Protection based on existing licensing for synchronized users.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Security.\n4. Under Manage, select Authentication Methods.\n5. Select Password Protection.\n6. Set the Enforce custom list option to Yes.\n7. Double click the custom banned password list to add a string",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check -  From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID.\n3. Select 'Security'.\n4. Under Manage, select Authentication Methods.\n5. Select Password Protection.\n6. Ensure Enforce custom list is set to Yes.\n7. Scroll through the list to view the enforced passwords"
        results["pass_fail"] = "INFO"

        return results

    def graph_10(self):
        # Ensure That 'Number of methods required to reset' is set to '2' (CIS)(Manual)

        results = {
            "id" : "graph_10",
            "ref" : "1.7",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Ensure that the number of days before users are asked to re-confirm their authentication information is not set to 0.\nThis setting is necessary if you have setup 'Require users to register when signing in option'. If authentication re-confirmation is disabled, registered users will never be prompted to re-confirm their existing authentication information. If the authentication information for a user changes, such as a phone number or email, then the password reset information for that user reverts to the previously registered authentication information.\nUsers will be prompted for their multifactor authentication at the duration set here.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select Password reset\n5. Then Registration\n6. Set the Number of days before users are asked to re-confirm their authentication information to your organization-defined frequency.\nDefault Value:\nBy default, the Number of days before users are asked to re-confirm their authentication information is set to '180 days'.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check -From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select Password reset\n5. Then Registration\n6. Ensure that Number of days before users are asked to re-confirm their\nauthentication information is not set to 0 "
        results["pass_fail"] = "INFO"

        return results

    def graph_11(self):
        # Ensure that 'Notify users on password resets?' is set to 'Yes' (CIS)(Manual)

        results = {
            "id" : "graph_11",
            "ref" : "1.8",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Notify users on password resets?' is set to 'Yes' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Ensure that users are notified on their primary and secondary emails on password resets.User notification on password reset is a proactive way of confirming password reset activity. It helps the user to recognize unauthorized password reset activities.\nUsers will receive emails alerting them to password changes to both their primary and secondary emails.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Select Password reset\n5. Under Manage, select Notifications\n6. Set Notify users on password resets? to Yes",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Go to Password reset\n5. Under Manage, select Notifications\n6. Ensure that Notify users on password resets? is set to Yes"
        results["pass_fail"] = "INFO"

        return results

    def graph_12(self):
        # Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes' (CIS)(Manual)

        results = {
            "id" : "graph_12",
            "ref" : "1.9",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Ensure that all Global Administrators are notified if any other administrator resets their password. \nGlobal Administrator accounts are sensitive. Any password reset activity notification, when sent to all Global Administrators, ensures that all Global administrators can passively confirm if such a reset is a common pattern within their group. For example, if all Global Administrators change their password every 30 days, any password reset activity before that may require administrator(s) to evaluate any unusual activity and confirm its origin. \nAll Global Administrators will receive a notification from Azure every time a password is reset. This is useful for auditing procedures to confirm that there are no out of the ordinary password resets for Global Administrators. There is additional overhead, however, in the time required for Global Administrators to audit the notifications. This setting is only useful if all Global Administrators pay attention to the notifications, and audit each one.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Select Password reset\n5. Under Manage, select Notifications\n6. Set Notify all admins when other admins reset their password? to Yes",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal \n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Select Password reset\n5. Under Manage, select Notifications\n6. Ensure that notify all admins when other admins reset their password? is set to Yes"
        results["pass_fail"] = "INFO"

        return results

    def graph_13(self):
        # Ensure `User consent for applications` is set to `Do not allow user consent` (CIS)(Manual)

        results = {
            "id" : "graph_13",
            "ref" : "1.10",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure `User consent for applications` is set to `Do not allow user consent` (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Require administrators to provide consent for applications before use.\nIf Microsoft Entra ID is running as an identity provider for third-party applications, permissions and consent should be limited to administrators or pre-approved. Malicious applications may attempt to exfiltrate data or abuse privileged user accounts. \nEnforcing this setting may create additional requests that administrators need to review.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Enterprise Applications\n4. Select Consent and permissions\n5. Select User consent settings\n6. Set User consent for applications to Do not allow user consent\n7. Click save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Enterprise Applications\n4. Select Consent and permissions\n5. Select User consent settings\n6. Ensure User consent for applications is set to Do not allow user consent"
        results["pass_fail"] = "INFO"

        return results

    def graph_14(self):
        # Ensure `User consent for applications` is set to `Do not allow user consent` (CIS)(Manual)

        results = {
            "id" : "graph_14",
            "ref" : "1.11",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure ‘User consent for applications’ Is Set To ‘Allow for Verified Publishers’ (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Allow users to provide consent for selected permissions when a request is coming from a verified publisher. \nIf Microsoft Entra ID is running as an identity provider for third-party applications, permissions and consent should be limited to administrators or pre-approved. Malicious applications may attempt to exfiltrate data or abuse privileged user accounts.\nEnforcing this setting may create additional requests that administrators need to review.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Enterprise Applications\n4. Select Consent and permissions\n5. Select User consent settings\n6. Under User consent for applications, select Allow user consent for apps from verified publishers, for selected permissions\n7. Select Save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Enterprise Applications\n4. Select Consent and permissions\n5. Select User consent settings\n6. Under User consent for applications, ensure Allow user consent for apps\nfrom verified publishers, for selected permissions is selected"
        results["pass_fail"] = "INFO"

        return results

    def graph_15(self):
        # Ensure `User consent for applications` is set to `Do not allow user consent` (CIS)(Manual)

        results = {
            "id" : "graph_15",
            "ref" : "1.12",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Users can add gallery apps to My Apps' is set to 'No' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Require administrators to provide consent for the apps before use. \nUnless Microsoft Entra ID is running as an identity provider for third-party applications, do not allow users to use their identity outside of your cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.\nImpact:\n Can cause additional requests to administrators that need to be fulfilled quite often",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Enterprise applications\n4. Select User settings\n5. Set Users can add gallery apps to My Apps to No",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Enterprise applications\n4. Select User settings\n5. Ensure that Users can add gallery apps to My Apps is set to No"
        results["pass_fail"] = "INFO"

        return results

    def graph_16(self):
        # Ensure That ‘Users Can Register Applications’ Is Set to ‘No’ (CIS)(Manual)

        results = {
            "id" : "graph_16",
            "ref" : "1.13",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure That ‘Users Can Register Applications’ Is Set to ‘No’ (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Require administrators or appropriately delegated users to register third-party applications. \nIt is recommended to only allow an administrator to register custom-developed applications. This ensures that the application undergoes a formal security review and approval process prior to exposing Microsoft Entra ID data. Certain users like developers or other high-request users may also be delegated permissions to prevent them from waiting on an administrative user. Your organization should review your policies and decide your needs. \nEnforcing this setting will create additional requests for approval that will need to be addressed by an administrator. If permissions are delegated, a user may approve a malevolent third party application, potentially giving it access to your data.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Select User settings\n5. Set Users can register applications to No",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Users\n4. Select User settings\n5. Ensure that Users can register applications is set to No"
        results["pass_fail"] = "INFO"

        return results

    def graph_17(self):
        # Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects' (CIS)(Manual)

        results = {
            "id" : "graph_17",
            "ref" : "1.14",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Limiting guest access ensures that guest accounts do not have permission for certain directory tasks, such as enumerating users, groups or other directory resources, and cannot be assigned to administrative roles in your directory. Guest access has three levels of restriction.\n1. Guest users have the same access as members (most inclusive),\n2. Guest users have limited access to properties and memberships of directory objects (default value),\n3. Guest user access is restricted to properties and memberships of their own directory objects (most restrictive).\nThe recommended option is the 3rd, most restrictive: 'Guest user access is restricted to their own directory object'.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then External Identities\n4. Select External collaboration settings\n5. Under Guest user access, change Guest user access restrictions to be Guest\nuser access is restricted to properties and memberships of their own directory objects",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "Manual Check From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then External Identities\n4. Select External collaboration settings\n5. Under Guest user access, ensure that Guest user access restrictions is set to Guest user access is restricted to properties and memberships of their own directory objects"
        results["pass_fail"] = "INFO"

        return results

    def graph_18(self):
        # Ensure that 'Guest invite restrictions' is set to "Only users assigned to specific admin roles can invite guest users" (CIS)

        results = {
            "id" : "graph_18",
            "ref" : "1.15",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users' (CIS)",
            "affected": [],
            "analysis" : [],
            "description" : "Restrict invitations to users with specific administrative roles only. Restricting invitations to users with specific administrator roles ensures that only authorized accounts have access to cloud resources. This helps to maintain 'Need to Know' permissions and prevents inadvertent access to data. By default the setting Guest invite restrictions is set to Anyone in the organization can invite guest users including guests and non-admins. This would allow anyone within the organization to invite guests and non-admins to the tenant, posing a security risk. \nWith the option of Only users assigned to specific admin roles can invite guest users selected, users with specific admin roles will be in charge of sending invitations to the external users, requiring additional overhead by them to manage user accounts. This will mean coordinating with other departments as they are onboarding new users.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then External Identities\n4. Select External collaboration settings\n5. Under Guest invite settings, for Guest invite restrictions, ensure that Only users assigned to specific admin roles can invite guest users is selected",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then External Identities\n4. External collaboration settings\n5. Under Guest invite settings, for Guest invite restrictions, ensure that that Only users assigned to specific admin roles can invite guest users is selected"
        results["pass_fail"] = "INFO"

        return results

    def graph_19(self):
        # Ensure that 'Guest invite restrictions' is set to "Only users assigned to specific admin roles can invite guest users" (CIS)

        results = {
            "id" : "graph_19",
            "ref" : "1.16",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Restrict access to the Microsoft Entra ID administration center to administrators only. NOTE: This only affects access to the Entra ID administrator's web portal. This setting does not prohibit privileged users from using other methods such as Rest API or Powershell to obtain sensitive information from Microsoft Entra ID. \nThe Microsoft Entra ID administrative center has sensitive data and permission settings. All non-administrators should be prohibited from accessing any Microsoft Entra ID data in the administration center to avoid exposure. \nAll administrative tasks will need to be done by Administrators, causing additional overhead in management of users and resources.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select User settings\n5. Set Restrict access to Microsoft Entra admin center to Yes",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Users\n4. Select User settings\n5. Ensure that Restrict access to Microsoft Entra admin center is set to Yes"
        results["pass_fail"] = "INFO"

        return results

    def graph_20(self):
        # Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes' (CIS)(Manual)

        results = {
            "id" : "graph_20",
            "ref" : "1.17",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Restrict access to group web interface in the Access Panel portal. \nSelf-service group management enables users to create and manage security groups or Office 365 groups in Microsoft Entra ID. Unless a business requires this day-to-day delegation for some users, self-service group management should be disabled. Any user can access the Access Panel, where they can reset their passwords, view their information, etc. By default, users are also allowed to access the Group feature, which shows groups, members, related resources (SharePoint URL, Group email address, Yammer URL, and Teams URL). By setting this feature to 'Yes', users will no longer have access to the web interface, but still have access to the data using the API. This is useful to prevent non-technical users from enumerating groups-related information, but technical users will still be able to access this information using APIs. \nSetting to Yes could create administrative overhead by customers seeking certain group memberships that will have to be manually managed by administrators with appropriate permissions.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Groups\n4. Select General under Settings\n5. Ensure that Restrict user ability to access groups features in My Groups is set to Yes",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Groups\n4. Select General under Settings\n5. Ensure that Restrict user ability to access groups features in My Groups\nis set to Yes"
        results["pass_fail"] = "INFO"

        return results

    def graph_21(self):
        # Ensure that 'Guest invite restrictions' is set to "Only users assigned to specific admin roles can invite guest users" (CIS)

        results = {
            "id" : "graph_21",
            "ref" : "1.18",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Restrict security group creation to administrators only. \nWhen creating security groups is enabled, all users in the directory are allowed to create new security groups and add members to those groups. Unless a business requires this day-to-day delegation, security group creation should be restricted to administrators only. \nEnabling this setting could create a number of requests that would need to be managed by an administrator.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Groups\n4. Select General under Setting\n5. Set Users can create security groups in Azure portals, API or PowerShell to No",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Groups\n4. Select General under Settings\n5. Ensure that Users can create security groups in Azure portals, API or PowerShell is set to No"
        results["pass_fail"] = "INFO"

        return results

    def graph_22(self):
        # Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No' (CIS)(Manual)

        results = {
            "id" : "graph_22",
            "ref" : "1.19",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Restrict security group management to administrators only. \nRestricting security group management to administrators only prohibits users from making changes to security groups. This ensures that security groups are appropriately managed and their management is not delegated to non-administrators. \nGroup Membership for user accounts will need to be handled by Admins and cause administrative overhead.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Groups\n4. Select General in settings\n5. Set Owners can manage group membership requests in the Access Panel to No",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Groups\n4. Select General in settings\n5. Ensure that Owners can manage group membership requests in the Access Panel is set to No"
        results["pass_fail"] = "INFO"

        return results

    def graph_23(self):
        # Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No' (CIS)(Manual)

        results = {
            "id" : "graph_23",
            "ref" : "1.20",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Restricting Microsoft 365 group creation to administrators only ensures that creation of Microsoft 365 groups is controlled by the administrator. Appropriate groups should be created and managed by the administrator and group creation rights should not be delegated to any other user.\nEnabling this setting could create a number of requests that would need to be managed by an administrator.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Groups\n4. Select General in settings\n5. Set Users can create Microsoft 365 groups in Azure portals, API or PowerShell to No",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Then Groups\n4. Select General in setting\n5. Ensure that Users can create Microsoft 365 groups in Azure portals, API or PowerShell is set to No"
        results["pass_fail"] = "INFO"

        return results

    def graph_24(self):
        # Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No' (CIS)(Manual)

        results = {
            "id" : "graph_24",
            "ref" : "1.21",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure that 'Require Multi-Factor Authentication to register or join devices with Microsoft Entra ID' is set to 'Yes' (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Joining or registering devices to Microsoft Entra ID should require Multi-factor authentication.\nMulti-factor authentication is recommended when adding devices to Microsoft Entra ID. When set to Yes, users who are adding devices from the internet must first use the second method of authentication before their device is successfully added to the directory. This ensures that rogue devices are not added to the domain using a compromised user account. Note: Some Microsoft documentation suggests to use conditional access policies for joining a domain from certain whitelisted networks or devices. Even with these in place, using Multi-Factor Authentication is still recommended, as it creates a process for review before joining the domain.\nA slight impact of additional overhead, as Administrators will now have to approve every access to the domain.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Devices\n4. Select Device settings\n5. Set Require Multi-Factor Authentication to register or join devices with Microsoft Entra to Yes",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Select Microsoft Entra ID\n3. Select Devices\n4. Select Device settings\n5. Ensure that Require Multi-Factor Authentication to register or join devices with Microsoft Entra is set to Yes"
        results["pass_fail"] = "INFO"

        return results

    def graph_25(self):
        # Ensure That No Custom Subscription Administrator Roles Exist (CIS)(Manual)

        results = {
            "id" : "graph_25",
            "ref" : "1.22",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure That No Custom Subscription Administrator Roles Exist (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access. \nClassic subscription admin roles offer basic access management and include Account Administrator, Service Administrator, and Co-Administrators. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select Access control (IAM).\n4. Select Roles.\n5. Click Type and select CustomRole from the drop down menu.\n6. Check the box next to each role which grants subscription administrator privileges.\n7. Select Remove.\n8. Select Yes.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Subscriptions.\n3. Select Access control (IAM).\n4. Select Roles.\n5. Click Type and select CustomRole from the drop down menu.\n6. Select View next to a role.\n7. Select JSON.\n8. Check for assignableScopes set to the subscription, and actions set to *.\n9. Repeat steps 6-8 for each custom role"
        results["pass_fail"] = "INFO"

        return results

    def graph_26(self):
        # Ensure a Custom Role is Assigned Permissions for Administering Resource Locks (CIS)(Manual)

        results = {
            "id" : "graph_26",
            "ref" : "1.23",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure a Custom Role is Assigned Permissions for Administering Resource Locks (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Resource locking is a powerful protection mechanism that can prevent inadvertent modification/deletion of resources within Azure subscriptions/Resource Groups and is a recommended NIST configuration.\nGiven the resource lock functionality is outside of standard Role Based Access Control(RBAC), it would be prudent to create a resource lock administrator role to prevent inadvertent unlocking of resources.\nBy adding this role, specific permissions may be granted for managing just resource locks rather than needing to provide the wide Owner or User Access Administrator role, reducing the risk of the user being able to do unintentional damage.",
            "remediation" : "From Azure Portal\n1. In the Azure portal, open a subscription or resource group where you want the custom role to be assigned.\n2. Select Access control (IAM).\n3. Click Add.\n4. Select Add custom role.\n5. In the Custom Role Name field enter Resource Lock Administrator.\n6. In the Description field enter Can Administer Resource Locks.\n7. For Baseline permissions select Start from scratch\n8. Select next.\n9. In the Permissions tab select Add permissions.\n10. In the Search for a permission box, type in Microsoft.Authorization/locks to search for permissions.\n11. Select the check box next to the permission Microsoft.Authorization/locks.\n12. Select Add.\n13. Select Review + create.\n14. Select Create.\n15. Assign the newly created role to the appropriate user.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. In the Azure portal, open a subscription or resource group where you want to view assigned roles.\n2. Select Access control (IAM)\n3. Select Roles\n4. Search for the custom role named <role_name> Ex. from remediation Resource Lock Administrator\n5. Ensure that the role is assigned to the appropriate users."
        results["pass_fail"] = "INFO"

        return results

    def graph_27(self):
        # Ensure That `Subscription leaving Microsoft Entra ID directory` and `Subscription entering Microsoft Entra ID directory` Is Set To ‘Permit No One’ (CIS)(Manual)

        results = {
            "id" : "graph_27",
            "ref" : "1.24",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "graph",
            "name" : "Ensure That `Subscription leaving Microsoft Entra ID directory` and `Subscription entering Microsoft Entra ID directory` Is Set To ‘Permit No One’ (CIS)(Manual)",
            "affected": [],
            "analysis" : [],
            "description" : "Users who are set as subscription owners are able to make administrative changes to the subscriptions and move them into and out of Microsoft Entra ID.\nPermissions to move subscriptions in and out of Microsoft Entra ID directory must only be given to appropriate administrative personnel. A subscription that is moved into an Microsoft Entra ID directory may be within a folder to which other users have elevated permissions. This prevents loss of data or unapproved changes of the objects within by potential bad actors.\nSubscriptions will need to have these settings turned off to be moved.",
            "remediation" : "From Azure Portal\n1. From the Azure Portal Home select the portal menu\n2. Select Subscriptions\n3. In the Advanced options drop-down menu, select Manage Policies\n4. Under Subscription leaving Microsoft Entra ID directory and Subscription entering Microsoft Entra ID directory select Permit no one",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["affected"].append(self.tenant)
        results["analysis"] = "From Azure Portal\n1. From the Azure Portal Home select the portal menu\n2. Select Subscriptions\n3. In the Advanced options drop-down menu, select Manage Policies\n4. Ensure Subscription leaving Microsoft Entra ID directory and Subscription entering Microsoft Entra ID directory are set to Permit no one"
        results["pass_fail"] = "INFO"

        return results

    def graph_28(self):
        # Ensure fewer than 5 users have global administrator assignment (CIS)

        results = {
            "id" : "graph_28",
            "ref" : "1.25",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "graph",
            "name" : "Ensure fewer than 5 users have global administrator assignment (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "This recommendation aims to maintain a balance between security and operational efficiency by ensuring that a minimum of 2 and a maximum of 4 users are assigned the Global Administrator role in Microsoft Entra ID. Having at least two Global Administrators ensures redundancy, while limiting the number to four reduces the risk of excessive privileged access.\nThe Global Administrator role has extensive privileges across all services in Microsoft Entra ID. The Global Administrator role should never be used in regular daily activities; administrators should have a regular user account for daily activities, and a separate account for administrative responsibilities. Limiting the number of Global Administrators helps mitigate the risk of unauthorized access, reduces the potential impact of human error, and aligns with the principle of least privilege to reduce the attack surface of an Azure tenant. Conversely, having at least two Global Administrators ensures that administrative functions can be performed without interruption in case of unavailability of a single admin.\nImplementing this recommendation may require changes in administrative workflows or the redistribution of roles and responsibilities. Adequate training and awareness should be provided to all Global Administrators.",
            "remediation" : "If more 4 users are assigned:\n1. Remove Global Administrator role for users which do not or no longer require the role.\n2. Assign Global Administrator role via PIM which can be activated when required.\n3. Assign more granular roles to users to conduct their duties.\nIf only one user is assigned:\n1. Provide the Global Administrator role to a trusted user or create a break glass admin account.",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "7.3",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if len(self.global_admins) > 4:
            results["affected"].append(self.tenant)
            results["analysis"] = f"there are currently { len(self.global_admins) } global admins in the tenancy"
            results["pass_fail"] = "FAIL"
        else:
            results["pass_fail"] = "PASS"
            results["analysis"] = f"there are only { len(self.global_admins) } global admins in the tenancy"

        return results

    def graph_29(self):
        # Ensure 'Self service password reset enabled' is set to 'All'

        results = {
            "id" : "graph_29",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "graph",
            "name" : "Ensure 'Self service password reset enabled' is set to 'All'",
            "affected": [],
            "analysis" : {},
            "description" : "Enabling self-service password reset allows users to reset their own passwords in Azure AD. When users sign in to Microsoft 365 or Azure, they will be prompted to enter additional contact information that will help them reset their password in the future. If combined registration is enabled additional information, outside of multi-factor, will not be needed. Users will no longer need to engage the helpdesk for password resets, and the password reset mechanism will automatically block common, easily guessable passwords.",
            "remediation" : "To enable self-service password reset:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Protection > Password reset select Properties.\n3. Set Self service password reset enabled to All",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        logging.info(f'getting authenticaton flows')
        url = f"https://graph.microsoft.com/v1.0/policies/authenticationFlowsPolicy"
        try:
            response = requests.get(url, headers=self.headers)
        except Exception as e:
            logging.error(f'error getting authentication flows: , error: { e }')
        else:
            if response.status_code == 200:

                if response.json()["selfServiceSignUp"]["isEnabled"] == False:
                    results["affected"].append(self.tenant)
                    results["analysis"] = "Self-Service Password Reset is not enabled"
                    results["pass_fail"] = "FAIL"
                else:
                    results["pass_fail"] = "PASS"
                    results["analysis"] = "Self-Service Password Reset is enabled"

            elif response.status_code == 403:
                logging.error(f'error getting authentication flows: , access denied:')
            else:
                logging.error(f'error getting authentication flows')

        return results

    def graph_30(self):
        # Shadow Admin via Highly Privileged Service Principal (via role assignment)

        results = {
            "id" : "graph_30",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "graph",
            "name" : "Shadow Admin via Highly Privileged Service Principal (via Role Assignment)",
            "affected": [],
            "analysis" : [],
            "description" : "The account under review contains an app registration/service principal that is highly privileged and if under the control of a malicious user would convey administrator level privileges within the account. This means users with roles that enable them to configure applications, Cloud Application Administrator and Application Administrator for example,  are in effect shadow administrators as they can add a new client secret to application and leverage the role and or Graph API permissions given to the service principle to perform actions in the account.  \nAdditionally a  user account or group was found to be a member of the application administrator role which if abused could result in the user obtaining privileged access in AzureAD. Microsoft Azure AD provides a large number of roles which can be used to delegate permissions out to users and ostensibly follow the principle of least privilege, however, with complexity it is also possible to grant users roles which provide more privileges then desired.  \nWhen registering a new application in your tenancy, follow the standard security advice of granting least privilege, or granting only the permissions required to perform a task. Determine what resources need to do and then craft policies that allow them to perform only those tasks. Start with a minimum set of permissions and grant additional permissions as necessary. Doing so is more secure than starting with permissions that are too lenient and then trying to tighten them later.  \nGranting the wrong Azure AD roles to a user or application can result in an attack path to global admin. For example, the Privileged Authentication Administrator role is like granting the user Global admin permissions, since an attacker with this role can reset the password of any Global Admin, modify the MFA settings and take over the account. Additionally, the Privileged Role Administrator role grants the entity holding it the permission to add additional Azure AD roles to any user, including the Global Administrator role.",
            "remediation" : "Review the affected users and service principals and remove any permissions that are not required including roles and MS Graph API permissions. If the use of service principle with administrator level privileges is required then ensure that non admin users are not given the Cloud Application Administrator, Application Administrator roles.",
            "impact" : "high",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score" : "8.1",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        privileged_principals = []
        principals_with_ga = []
        application_administrators_with_ga = []

        for service_principal, roles in self.service_principal_roles.items():
            for role in roles:
                if role['displayName'] == "Global Administrator":
                    principals_with_ga.append(service_principal)
                if "Administrator" in role['displayName']:
                    privileged_principals.append(service_principal)

        for user in self.application_administrators:
            for role in self.get_user_roles(user):
                if role['displayName'] == "Global Administrator":
                    application_administrators_with_ga.append(user)

        if principals_with_ga:
            for user in self.application_administrators:
                if user not in application_administrators_with_ga:
                   results["analysis"].append(f"The user ({ user['displayName'] }) has the application or cloud application administrator role and can elevate privileges to Global Admin via the service principals {[ i for i in principals_with_ga ]}")
                   results["affected"].append(user["displayName"])


        if privileged_principals:
            for user in self.application_administrators:
                if user not in application_administrators_with_ga:
                    for principal, roles in self.service_principal_roles.items():
                        for role in roles:
                            if role["displayName"] != "Global Administrator":
                                if role not in self.get_user_roles(user):
                                    results["analysis"].append(f"The user ({ user['displayName'] }) has the application or cloud application administrator role and can use the service principal { principal } to obtain the role { role['displayName'] }")
                                    results["affected"].append(user["displayName"])

        if results["affected"]:
            results["affected"] = list(set(results["affected"]))
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "no issues found"

        return results

    def graph_31(self):
        # service principal roles

        results = {
            "id" : "graph_31",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "graph",
            "name" : "Service Principals with Directory Roles",
            "affected": [],
            "analysis" : "",
            "description" : "The affected service principals have been assigned roles in Azure AD.",
            "remediation" : "Ensure roles are assigned following the principal of least privilege",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if self.service_principal_roles:
            results["affected"] = [ i for i in self.service_principal_roles ]
            results["analysis"] = self.service_principal_roles
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no service principals have directory roles assigned"

        return results

    def graph_32(self):
        # service principal roles

        results = {
            "id" : "graph_32",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "graph",
            "name" : "Cloud Application And Application Administrators",
            "affected": [],
            "analysis" : "",
            "description" : "Cloud Application Administrator and Application Administrator are privileged roles which allow users to create and administor enterprise applications aka service principals. This means they can in effect leverage any permissons afforded to service principals and potentially elevate privileges",
            "remediation" : "Ensure users with the cloud application and application administrator roles are not able to elevate privileges via permissions afforded to service principals",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        if self.application_administrators:
            results["affected"] = [ i["displayName"] for i in self.application_administrators ]
            results["analysis"] = self.application_administrators
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no users have the cloud application of application administrator roles assigned"

        return results
