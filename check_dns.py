#!/usr/bin/env python2

# Copyright 2017 Pieter Lexis <pieter.lexis@powerdns.com>
# Licensed under the GPL version 2, see LICENSE for more.

from __future__ import print_function, absolute_import
import argparse
from collections import OrderedDict
import dnsviz.commands.probe
from dnsviz.analysis import TTLAgnosticOfflineDomainNameAnalysis, DNS_RAW_VERSION
import dnsviz.analysis.status as status
from dnsviz.format import latin1_binary_to_string as lb2s
from dnsviz.util import get_trusted_keys, get_default_trusted_keys
import nagiosplugin
import logging
import dns.name
import dns.rdatatype

_log = logging.getLogger('nagiosplugin')


class DNSSECContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        delegation = metric.value.get('delegation')
        dnssec = metric.value.get('dnssec')
        if delegation['status'] > status.DELEGATION_STATUS_SECURE:
            if delegation['status'] == status.DELEGATION_STATUS_BOGUS:
                return nagiosplugin.Result(nagiosplugin.Critical, 'Delegation is BOGUS', metric)
            if delegation['status'] == status.DELEGATION_STATUS_INSECURE:
                if resource.insecure_ok:
                    return nagiosplugin.Result(nagiosplugin.Ok, 'Delegation is INSECURE', metric)
            return nagiosplugin.Result(nagiosplugin.Warn, 'Delegation is {}'.format(
                status.delegation_status_mapping[delegation['status']]), metric)
        return nagiosplugin.Result(nagiosplugin.Ok, 'Delegation is SECURE', metric)


class DNS(nagiosplugin.Resource):
    def __init__(self, domain, insecure_ok=True):
        self.domain = domain
        self.insecure_ok = insecure_ok

        self.try_ipv4 = True
        self.try_ipv6 = True
        self.client_ipv4 = None
        self.client_ipv6 = None
        self.query_class_mixin = None
        self.ceiling = dns.name.root
        self.edns_diagnostics = False
        self.stop_at_explicit = {}
        self.cache_level = None
        self.rdtypes = None
        self.explicit_only = False  # set to true if rdtypes is set
        self.dlv_domain = None

    def probe(self):
        _log.debug('Starting probing for "{}"'.format(self.domain))
        a = dnsviz.commands.probe.BulkAnalyst(self.try_ipv4, self.try_ipv6, self.client_ipv4, self.client_ipv6,
                                              self.query_class_mixin, self.ceiling, self.edns_diagnostics,
                                              self.stop_at_explicit, self.cache_level, self.rdtypes,
                                              self.explicit_only, self.dlv_domain)
        names = [dns.name.from_text(self.domain)]
        name_objs = a.analyze(names)
        name_objs = [x for x in name_objs if x is not None]
        if len(name_objs) > 1:
            raise ValueError('More than one name specified?')
        name_obj = name_objs[0]
        serialized_obj = OrderedDict()
        name_obj.serialize(serialized_obj, False)
        trusted_keys = get_default_trusted_keys(name_obj.analysis_end)
        serialized_obj['_meta._dnsviz.'] = {'version': DNS_RAW_VERSION, 'names': [lb2s(n.to_text()) for n in names]}

        cache = {}

        analysis_obj = TTLAgnosticOfflineDomainNameAnalysis.deserialize(names[0], serialized_obj, cache)
        analysis_obj.populate_status(trusted_keys)

        # These errors are linked to the DS record
        delegation_status = analysis_obj.delegation_status[43]
        delegation_warnings = [x.description for x in analysis_obj.delegation_warnings[43]]
        delegation_errors = [e.description for e in analysis_obj.delegation_errors[43]]

        zone_status = analysis_obj.zone_status
        zone_warnings = [w.description for w in analysis_obj.zone_warnings]
        zone_errors = [e.description for e in analysis_obj.zone_errors]

        status = {
            'dnssec': {'status': zone_status, 'warnings': zone_warnings, 'errors': zone_errors},
            'delegation': {'status': delegation_status,
                           'warnings': delegation_warnings,
                           'errors': delegation_errors},
        }
        yield nagiosplugin.Metric('dnssec_status', status, context='dnssec')


class DNSSummary(nagiosplugin.Summary):
    def ok(self, results):
        ret = []
        for result in results:
            if result.metric.name == 'dnssec_status':
                if result.metric.name == 'dnssec_status':
                    to_add = ''
                    for t in ['dnssec', 'delegation']:
                        for m in ['errors', 'warnings']:
                            if result.metric.value.get(t, {}).get(m):
                                to_add += ', '.join(result.metric.value.get(t, {}).get(m))
                    if to_add != '':
                        ret.append('{}: {}'.format(result.hint, to_add))
                    else:
                        ret.append(result.hint)
        return '; '.join(ret)

    def problem(self, results):
        ret = []
        for result in results.most_significant:
            if result.metric.name == 'dnssec_status':
                to_add = ''
                for t in ['dnssec', 'delegation']:
                    for m in ['errors', 'warnings']:
                        if result.metric.value.get(t, {}).get(m):
                            to_add += ', '.join(result.metric.value.get(t, {}).get(m))
                if to_add != '':
                    ret.append('{}: {}'.format(result.hint, to_add))
                else:
                    ret.append(result.hint)
        return '; '.join(ret)


@nagiosplugin.guarded()
def main():
    argp = argparse.ArgumentParser()
    argp.add_argument('--domain', '-d', type=str, required=True, action='store')
    argp.add_argument('--insecure-is-ok', action='store_true', default=False)
    argp.add_argument('--verbose', '-v', action='count', default=0)
    args = argp.parse_args()
    check = nagiosplugin.Check(
        DNS(args.domain, args.insecure_is_ok),
        DNSSECContext('dnssec'),
        DNSSummary())
    check.main(args.verbose)


if __name__ == '__main__':
    main()
