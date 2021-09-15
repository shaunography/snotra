import boto3

from utils.utils import describe_regions

class kms(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)

    def run(self):
        findings = []
        findings += [ self.kms_1() ]
        return findings
        
    def kms_1(self):
        # Ensure rotation for customer created CMKs is enabled (Automated)

        results = {
            "id" : "kms_1",
            "ref" : "3.8",
            "compliance" : "cis",
            "level" : 2,
            "service" : "kms",
            "name" : "Ensure rotation for customer created CMKs is enabled",
            "affected": "",
            "analysis" : "rotation is enabled on all CMKs",
            "description" : "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the Customer Created customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently. It is recommended that CMK key rotation be enabled. Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.",
            "remediation" : "Enable key rotation on all customer created CMKs",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: kms_1")

        failing_keys = []
        
        for region in self.regions:
            client = self.session.client('kms', region_name=region)
            keys_list = client.list_keys()["Keys"]
            for key in keys_list:
                key_id = key["KeyId"]
                try:
                    key_rotation_Status = client.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]
                #botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the GetKeyRotationStatus operation
                except boto3.exceptions.botocore.exceptions.ClientError:
                    print("access denied - KMS KeyID:{}({})".format(key_id, region))
                    pass
                else:
                    if key_rotation_Status == False:
                        failing_keys += ["{}({})".format(key_id, region)]

        if failing_keys:
            results["analysis"] = "the following KMS keys do not have rotation enabled: {}".format(" ".join(failing_keys))
            results["affected"] = ", ".join(failing_keys)
            results["pass_fail"] = "FAIL"
        
        return results