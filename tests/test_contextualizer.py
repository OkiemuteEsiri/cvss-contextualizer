import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cvss_contextualizer import Finding, assess_all, contextualize


def base(**kwargs):
    data = dict(finding_id="F-1", cve="CVE-2099-0001", cvss=7.5, severity="HIGH", asset="app-01", asset_criticality=3, owner="platform")
    data.update(kwargs)
    return Finding(**data)


class ContextualizerTests(unittest.TestCase):
    def test_score_is_bounded(self):
        self.assertLessEqual(contextualize(base(cvss=10, asset_criticality=5, internet_exposed=True, kev=True, exploit_maturity="weaponized")).contextual_score, 100)

    def test_kev_increases_score(self):
        self.assertGreater(contextualize(base(kev=True)).contextual_score, contextualize(base()).contextual_score)

    def test_internet_exposure_increases_score(self):
        self.assertGreater(contextualize(base(internet_exposed=True)).contextual_score, contextualize(base()).contextual_score)

    def test_controls_reduce_but_do_not_zero_risk(self):
        controlled = contextualize(base(compensating_controls=("network segmentation", "edr")))
        self.assertLess(controlled.contextual_score, contextualize(base()).contextual_score)
        self.assertGreater(controlled.contextual_score, 0)

    def test_unassigned_owner_adds_governance_risk(self):
        self.assertGreater(contextualize(base(owner="unassigned")).contextual_score, contextualize(base()).contextual_score)

    def test_invalid_cvss_rejected(self):
        with self.assertRaises(ValueError):
            base(cvss=11)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            assess_all([base(), base()])

    def test_results_sorted_highest_first(self):
        low = base(finding_id="L", cvss=3.1, severity="LOW", asset_criticality=1)
        high = base(finding_id="H", cvss=9.8, severity="CRITICAL", asset_criticality=5, kev=True)
        self.assertEqual(assess_all([low, high])[0].finding_id, "H")


if __name__ == "__main__":
    unittest.main()
