from checks.cis import cis

class checks:

    def all(self):
        pass

    def cis(self):
        checks = [
            cis.CIS1_1,
            cis.CIS1_2,
            cis.CIS1_3,
            cis.CIS1_4,
            cis.CIS1_5,
            cis.CIS1_6,
            cis.CIS1_7,
            cis.CIS1_8,
            cis.CIS1_9,
            cis.CIS1_10,
            cis.CIS1_11,
            cis.CIS1_12,
            cis.CIS1_13,
            cis.CIS1_14,
            cis.CIS1_15,
            cis.CIS1_16,
            cis.CIS1_17,
            cis.CIS1_18
        ]
        checks_test = [
            cis.CIS1_18
        ]
        return checks

    def cis_level1(self):
        pass

    def cis_level2(self):
        pass

    def iam(self):
        pass