"""The onboarding gate follows configuration, not incidental binary strings."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runner_profile_probes", ROOT / "ops/validation/probes.py")
probes = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probes
spec.loader.exec_module(probes)
FIELDS = {
    "portal_endpoint": "http://portal:8090",
    "router_endpoint": "tls/zenoh.newnet.example:7447",
    "netbird_mgmt_url": "https://netbird.newnet.example",
    "netbird_token_env": "NEWNET_NB_API_TOKEN",
    "netbird_site_prefix": "NEWNET",
    "ory_auth_url": "https://auth.newnet.example",
    "ory_ssh_host": "192.0.2.20",
    "ory_ssh_user": "operator",
}

class RunnerProfile(unittest.TestCase):
    def probe(self, fields=None, rc=0, reached=True):
        fields = FIELDS if fields is None else fields
        body = "".join(f'{key} = "{value}"\n' for key, value in fields.items())
        with patch.object(probes, "_host_run", return_value=probes._Run(rc, body, "PRIVATE ERROR", reached)) as run:
            verdict = probes.onboard_runner_profile({"host": "192.0.2.30", "goatnet": "newnet"})
        self.assertNotIn("PRIVATE ERROR", verdict.evidence)
        for value in FIELDS.values():
            self.assertNotIn(value, verdict.evidence)
        return verdict, run

    def test_new_goatnet_needs_no_binary_string(self):
        verdict, run = self.probe()
        self.assertEqual(verdict.status, probes.PASS)
        cmd = run.call_args.args[1]
        self.assertIn('contexts/default/profile.toml', cmd)
        self.assertNotIn('strings', cmd)
        self.assertNotIn('portal.token', cmd)

    def test_each_missing_or_blank_setting_fails(self):
        for key in FIELDS:
            for value in (None, '', '   ', '{{ unresolved }}'):
                with self.subTest(key=key, value=value):
                    fields = dict(FIELDS)
                    if value is None:
                        del fields[key]
                    else:
                        fields[key] = value
                    result, _ = self.probe(fields)
                    self.assertEqual(result.status, probes.FAIL)
                    self.assertIn(key, result.evidence)

    def test_named_profile_must_match(self):
        self.assertEqual(self.probe(dict(FIELDS, goatnet='newnet'))[0].status, probes.PASS)
        self.assertEqual(self.probe(dict(FIELDS, goatnet='other'))[0].status, probes.FAIL)

    def test_incidental_name_or_prefixed_key_cannot_pass(self):
        self.assertEqual(self.probe({'comment': 'newnet'})[0].status, probes.FAIL)
        fields = dict(FIELDS)
        del fields['router_endpoint']
        fields['router_endpoint_backup'] = 'tls/example.test:7447'
        self.assertEqual(self.probe(fields)[0].status, probes.FAIL)

    def test_missing_profile_fails_transport_errors_unknown(self):
        self.assertEqual(self.probe(rc=42)[0].status, probes.FAIL)
        for rc in (1, 124, 125, 127, 255):
            self.assertEqual(self.probe(rc=rc, reached=rc != 255)[0].status, probes.UNKNOWN)

    def test_manifest_uses_the_configuration_probe(self):
        import yaml
        rows = yaml.safe_load((ROOT / 'ops/validation/acceptance-tests.yaml').read_text())['tests']
        row = next(r for r in rows if r['id'] == 'onboard-runner-knows-this-goatnet')
        self.assertEqual(row['probe'], 'onboard-runner-profile')
        self.assertIs(probes.REGISTRY[row['probe']], probes.onboard_runner_profile)
        self.assertEqual(row['params']['goatnet'], '{{ site_id }}')
        self.assertNotIn('strings', str(row))

if __name__ == '__main__':
    unittest.main()
