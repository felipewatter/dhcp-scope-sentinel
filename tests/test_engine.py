from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from dhcp_scope_sentinel.engine import audit, parse_contracts, _capacity
from dhcp_scope_sentinel.model import parse
from dhcp_scope_sentinel.parse import InputError
from dhcp_scope_sentinel.report import audit_report, diff_report, sarif

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / 'examples/baseline.json').read_text())
CONTRACTS = json.loads((ROOT / 'examples/contracts.json').read_text())
RISKY = json.loads((ROOT / 'examples/candidate-risky.json').read_text())


class AuditTests(unittest.TestCase):
    def findings(self, change):
        d = copy.deepcopy(BASE)
        change(d)
        return audit(parse(d))

    def rules(self, change):
        return {f.rule for f in self.findings(change)}

    def test_clean_baseline(self):
        self.assertEqual(audit(parse(BASE)), [])
        self.assertEqual(audit(parse(BASE), parse_contracts(CONTRACTS)), [])

    def test_risky_observation(self):
        codes = {f.rule for f in audit(parse(RISKY))}
        self.assertEqual(codes, {'DHCP101', 'DHCP102', 'DHCP103', 'DHCP104', 'DHCP105', 'DHCP107'})

    def test_offline_unauthorized_scope(self):
        self.assertIn('DHCP003', self.rules(lambda x: x['segments'][0]['scopes'][1].__setitem__('server', '10.20.0.99')))

    def test_pool_intersects_gateway(self):
        self.assertIn('DHCP004', self.rules(lambda x: x['segments'][0]['scopes'][0].__setitem__('pools', [['10.20.120.1','10.20.120.180']])))

    def test_pool_intersects_static_asset(self):
        self.assertIn('DHCP004', self.rules(lambda x: x['segments'][0]['scopes'][0].__setitem__('pools', [['10.20.120.5','10.20.120.180']])))

    def test_gateway_excluded(self):
        def edit(x):
            s = x['segments'][0]['scopes'][0]
            s['pools'] = [['10.20.120.1','10.20.120.180']]
            s['exclusions'].append(['10.20.120.1','10.20.120.10'])
        self.assertNotIn('DHCP004', self.rules(edit))

    def test_static_asset_excluded(self):
        def edit(x):
            s = x['segments'][0]['scopes'][0]
            s['pools'] = [['10.20.120.5','10.20.120.180']]
            s['exclusions'].append(['10.20.120.10','10.20.120.10'])
        self.assertNotIn('DHCP004', self.rules(edit))

    def test_orphan_failover_group_is_invalid(self):
        def edit(x):
            x['segments'][0]['scopes'][1].pop('failover_group')
            x['segments'][0]['scopes'][1]['pools'] = [['10.20.120.181','10.20.120.220']]
            x['segments'][0]['scopes'][1]['exclusions'] = []
            x['segments'][0]['scopes'][1]['reservations'] = []
        self.assertIn('DHCP002', self.rules(edit))

    def test_three_peers_in_one_failover_group_is_invalid(self):
        def edit(x):
            third = copy.deepcopy(x['segments'][0]['scopes'][1])
            third['id'] = 'LAB-THIRD'
            third['server'] = '10.20.0.4'
            x['segments'][0]['scopes'].append(third)
        self.assertIn('DHCP002', self.rules(edit))

    def test_mismatched_failover_pool(self):
        self.assertIn('DHCP002', self.rules(lambda x: x['segments'][0]['scopes'][1].__setitem__('pools', [['10.20.120.101','10.20.120.180']])))

    def test_mismatched_failover_exclusion(self):
        self.assertIn('DHCP002', self.rules(lambda x: x['segments'][0]['scopes'][1].__setitem__('exclusions', [])))

    def test_mismatched_failover_reservations(self):
        self.assertIn('DHCP002', self.rules(lambda x: x['segments'][0]['scopes'][1].__setitem__('reservations', [])))

    def test_same_server_failover_is_invalid(self):
        self.assertIn('DHCP002', self.rules(lambda x: x['segments'][0]['scopes'][1].__setitem__('server', '10.20.0.2')))

    def test_removed_failover_group_overlaps(self):
        self.assertIn('DHCP001', self.rules(lambda x: x['segments'][0]['scopes'][1].pop('failover_group')))

    def test_overlap_disjoint_scopes_allowed(self):
        def edit(x):
            s = x['segments'][0]['scopes'][1]
            s.pop('failover_group')
            s['pools'] = [['10.20.120.181','10.20.120.230']]
            s['exclusions'] = []
            s['reservations'] = []
        self.assertNotIn('DHCP001', self.rules(edit))

    def test_reservation_duplicate_ip(self):
        def edit(x):
            x['segments'][0]['scopes'][0]['reservations'].append({'ip': '10.20.120.150', 'client_id': 'different-client'})
        self.assertIn('DHCP005', self.rules(edit))

    def test_reservation_duplicate_client_other_ip(self):
        def edit(x):
            x['segments'][0]['scopes'][0]['reservations'].append({'ip': '10.20.120.151', 'client_id': 'training-terminal'})
        self.assertIn('DHCP005', self.rules(edit))

    def test_reservation_excluded_from_dynamic_pool(self):
        self.assertNotIn('DHCP008', self.rules(lambda x: None))

    def test_reservation_inside_pool_warning(self):
        self.assertIn('DHCP008', self.rules(lambda x: x['segments'][0]['scopes'][0].__setitem__('exclusions', [])))

    def test_unnecessary_exclusion(self):
        self.assertIn('DHCP006', self.rules(lambda x: x['segments'][0]['scopes'][0]['exclusions'].append(['10.20.120.90', '10.20.120.95'])))

    def test_self_overlapping_pool(self):
        self.assertIn('DHCP009', self.rules(lambda x: x['segments'][0]['scopes'][0]['pools'].append(['10.20.120.120', '10.20.120.140'])))

    def test_overlapping_networks_with_same_vrf(self):
        def edit(x):
            item = copy.deepcopy(x['segments'][0]); item['id'] = 'SCHOOL-LAB-2'
            item['scopes'][0]['id'] = 'SECONDARY-A'; item['scopes'][1]['id'] = 'SECONDARY-B'
            x['segments'].append(item)
        self.assertIn('DHCP007', self.rules(edit))

    def test_overlapping_networks_different_vrf_ok(self):
        def edit(x):
            item = copy.deepcopy(x['segments'][0]); item['id'] = 'SCHOOL-LAB-2'; item['vrf'] = 'ISOLATED'
            x['segments'].append(item)
        self.assertNotIn('DHCP007', self.rules(edit))

    def test_malicious_observation_gateway(self):
        self.assertIn('DHCP102', self.rules(lambda x: x['observations'][0].__setitem__('router', '10.20.120.254')))

    def test_malicious_dns(self):
        self.assertIn('DHCP107', self.rules(lambda x: x['observations'][0].__setitem__('dns_servers', ['8.8.8.8'])))

    def test_missing_relay(self):
        self.assertIn('DHCP105', self.rules(lambda x: x['observations'][0].pop('relay_id')))

    def test_untrusted_relay(self):
        self.assertIn('DHCP105', self.rules(lambda x: x['observations'][0].__setitem__('relay_id', 'untrusted')))

    def test_disabled_relay_requirement(self):
        def edit(x):
            x['segments'][0]['require_relay'] = False
            x['observations'][0].pop('relay_id')
        self.assertNotIn('DHCP105', self.rules(edit))

    def test_reserved_ip_offered_to_wrong_client(self):
        def edit(x):
            x['observations'][0]['offered_ip'] = '10.20.120.150'
            x['observations'][0]['client_id'] = 'other-client'
        codes = self.rules(edit)
        self.assertIn('DHCP108', codes)
        self.assertNotIn('DHCP103', codes)

    def test_reserved_ip_offered_to_correct_client(self):
        def edit(x):
            x['observations'][0]['offered_ip'] = '10.20.120.150'
            x['observations'][0]['client_id'] = 'training-terminal'
        self.assertNotIn('DHCP108', self.rules(edit))

    def test_offered_wrong_subnet(self):
        self.assertIn('DHCP103', self.rules(lambda x: x['observations'][0].__setitem__('offered_ip', '172.16.0.7')))

    def test_offered_reserved_address(self):
        def edit(x):
            x['observations'][0]['offered_ip'] = '10.20.120.150'
        self.assertNotIn('DHCP103', self.rules(edit))

    def test_offered_gateway(self):
        codes = self.rules(lambda x: x['observations'][0].__setitem__('offered_ip', '10.20.120.1'))
        self.assertIn('DHCP104', codes)
        self.assertIn('DHCP103', codes)

    def test_duplicate_offer_clients_is_not_claimed_as_lease_conflict(self):
        def edit(x):
            obs = dict(x['observations'][0]); obs['client_id'] = 'second-client'
            x['observations'].append(obs)
        findings = self.findings(edit)
        self.assertIn('DHCP106', {f.rule for f in findings})
        self.assertIn('not an actual lease conflict', [f.detail for f in findings if f.rule == 'DHCP106'][0])

    def test_fingerprint_is_stable_under_observation_order(self):
        def edit(x):
            obs = dict(x['observations'][0]); obs['client_id'] = 'second-client'
            x['observations'].append(obs)
        d = copy.deepcopy(BASE); edit(d)
        a = audit(parse(d))
        d['observations'].reverse()
        b = audit(parse(d))
        self.assertEqual([x.fingerprint for x in a], [x.fingerprint for x in b])

    def test_finding_changes_when_evidence_changes(self):
        a = self.findings(lambda x: x['observations'][0].__setitem__('router', '10.20.120.250'))
        b = self.findings(lambda x: x['observations'][0].__setitem__('router', '10.20.120.251'))
        self.assertNotEqual([x.fingerprint for x in a], [x.fingerprint for x in b])

    def test_nonempty_rule_titles_and_levels(self):
        findings = audit(parse(RISKY))
        for f in findings:
            self.assertGreaterEqual(len(f.to_dict()['title']), 5)
            self.assertIn(f.severity, ('critical', 'high', 'medium', 'low', 'info'))

    def test_capacity_one_address_pool(self):
        def edit(x):
            s = x['segments'][0]['scopes'][0]
            s['pools'] = [['10.20.120.120','10.20.120.120']]
            s['exclusions'] = []
            x['segments'][0]['scopes'] = [s]
        d = copy.deepcopy(BASE); edit(d)
        self.assertEqual(_capacity(parse(d).segments[0]), 1)

    def test_capacity_discounts_gateway_and_reservation(self):
        def edit(x):
            s = x['segments'][0]['scopes'][0]
            s['pools'] = [['10.20.120.1','10.20.120.10']]
            s['reservations'] = [{'ip':'10.20.120.3', 'client_id':'abc'}]
            s['exclusions'] = [['10.20.120.6','10.20.120.7']]
            x['segments'][0]['scopes'] = [s]
        d = copy.deepcopy(BASE); edit(d)
        self.assertEqual(_capacity(parse(d).segments[0]), 5)

    def test_contract_capacity(self):
        policy = {'schema_version':1,'contracts':[{'segment':'SCHOOL-LAB','min_usable_capacity':100}]}
        codes = {f.rule for f in audit(parse(BASE), parse_contracts(policy))}
        self.assertIn('DHCP202', codes)

    def test_contract_relay(self):
        d=copy.deepcopy(BASE)
        d['segments'][0]['require_relay']=False
        codes={f.rule for f in audit(parse(d),parse_contracts(CONTRACTS))}
        self.assertIn('DHCP201',codes)

    def test_contract_dns(self):
        d=copy.deepcopy(BASE)
        d['segments'][0]['dns_servers']=['8.8.8.8']
        codes={f.rule for f in audit(parse(d),parse_contracts(CONTRACTS))}
        self.assertIn('DHCP204',codes)

    def test_contract_prevents_authorized_server_bypass(self):
        d = copy.deepcopy(RISKY)
        d['segments'][0]['authorized_servers'].append('10.20.0.99')
        codes = {f.rule for f in audit(parse(d), parse_contracts(CONTRACTS))}
        self.assertNotIn('DHCP101',codes)
        self.assertIn('DHCP206',codes)

    def test_contract_prevents_gateway_rewrite(self):
        d = copy.deepcopy(BASE)
        d['segments'][0]['gateway']='10.20.120.254'
        codes = {f.rule for f in audit(parse(d), parse_contracts(CONTRACTS))}
        self.assertIn('DHCP207',codes)

    def test_contract_prevents_network_rewrite(self):
        d = copy.deepcopy(BASE)
        d['segments'][0]['network']='10.20.120.0/23'
        codes = {f.rule for f in audit(parse(d), parse_contracts(CONTRACTS))}
        self.assertIn('DHCP207',codes)

    def test_contract_prevents_relay_trust_bypass(self):
        d = copy.deepcopy(BASE)
        d['segments'][0]['trusted_relays'].append('bad-relay')
        codes = {f.rule for f in audit(parse(d), parse_contracts(CONTRACTS))}
        self.assertIn('DHCP208',codes)

    def test_contract_scope_limit(self):
        d=copy.deepcopy(BASE)
        scope=copy.deepcopy(d['segments'][0]['scopes'][0]);scope['id']='THIRD'
        scope['server']='10.20.0.2'; scope.pop('failover_group')
        scope['pools']=[['10.20.120.190','10.20.120.220']]
        d['segments'][0]['scopes'].append(scope)
        codes={f.rule for f in audit(parse(d),parse_contracts(CONTRACTS))}
        self.assertIn('DHCP203',codes)

    def test_missing_contract_segment(self):
        policy={'schema_version':1,'contracts':[{'segment':'MISSING'}]}
        self.assertIn('DHCP205',{f.rule for f in audit(parse(BASE),parse_contracts(policy))})

    def test_policy_duplicate_contract(self):
        with self.assertRaises(InputError):
            parse_contracts({'schema_version':1,'contracts':[{'segment':'A'},{'segment':'A'}]})

    def test_policy_requires_schema_1(self):
        for bad in (True, 0, '1', 2):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                parse_contracts({'schema_version':bad,'contracts':[]})

    def test_policy_rejects_negative_capacity(self):
        with self.assertRaises(InputError):
            parse_contracts({'schema_version':1,'contracts':[{'segment':'A','min_usable_capacity':-1}]})

    def test_policy_rejects_unknown_key(self):
        with self.assertRaises(InputError):
            parse_contracts({'schema_version':1,'contracts':[{'segment':'A','execute':'rm -rf /'}]})


class ReportTests(unittest.TestCase):
    def test_diff_new_and_resolved(self):
        clean = audit(parse(BASE))
        bad = audit(parse(RISKY))
        report = diff_report(clean, bad, 'before.json', 'after.json')
        self.assertEqual(len(report['introduced']), len(bad))
        self.assertEqual(report['persistent'], [])
        reverse = diff_report(bad, clean, 'after.json', 'before.json')
        self.assertEqual(len(reverse['resolved']), len(bad))

    def test_diff_persistent(self):
        bad = audit(parse(RISKY))
        report = diff_report(bad, bad, 'a.json', 'b.json')
        self.assertFalse(report['introduced'])
        self.assertEqual(len(report['persistent']), len(bad))

    def test_json_report_stable(self):
        a = audit_report(audit(parse(RISKY)), 'risk.json')
        b = audit_report(audit(parse(RISKY)), 'risk.json')
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_sarif_valid_structure(self):
        findings = audit(parse(RISKY))
        r = sarif(findings, 'input.json')
        self.assertEqual(r['version'], '2.1.0')
        self.assertEqual(len(r['runs'][0]['results']), len(findings))
        self.assertEqual(r['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'],'input.json')

    def test_sarif_dedup_rules(self):
        results = sarif(audit(parse(RISKY)), 'risk.json')['runs'][0]
        rules = [x['id'] for x in results['tool']['driver']['rules']]
        self.assertEqual(len(rules),len(set(rules)))

    def test_empty_sarif(self):
        doc=sarif([], 'input.json')
        self.assertEqual(doc['runs'][0]['results'], [])
