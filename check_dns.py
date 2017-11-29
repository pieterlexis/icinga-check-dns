#!/usr/bin/env python2

# Copyright 2017 Pieter Lexis <pieter.lexis@powerdns.com>
# Licensed under the GPL version 2, see LICENSE for more.

from __future__ import print_function, absolute_import
import argparse
import time
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


class RRSIGContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        if metric.value['errors']:
            return nagiosplugin.Result(nagiosplugin.Critical, 'RRSIG error', metric)
        if metric.value['warnings']:
            return nagiosplugin.Result(nagiosplugin.Warn, 'RRSIG issue', metric)
        return nagiosplugin.Result(nagiosplugin.Ok, 'RRSIGs validate correctly', metric)


class RRSIGExpitationContext(nagiosplugin.Context):
    def __init__(self, name, warn_seconds, crit_seconds, fmt_metric=None, result_cls=nagiosplugin.Result):
        super(RRSIGExpitationContext, self).__init__(name, fmt_metric, result_cls)
        self.warn_seconds = warn_seconds
        self.crit_seconds = crit_seconds

    def evaluate(self, metric, resource):
        r_state = nagiosplugin.Ok
        if self.warn_seconds >= metric.value:
            r_state = nagiosplugin.Warn
        if self.crit_seconds >= metric.value:
            r_state = nagiosplugin.Critical
        return nagiosplugin.Result(r_state, 'RRSIGs expiring in {} seconds ({} hours)'.format(
            metric.value, metric.value/3600), metric)


class DNS(nagiosplugin.Resource):
    def __init__(self, domain, insecure_ok=True, rrsig_expiration_warn=72, rrsig_expiration_crit=24):
        self.domain = domain
        self.domain_native = dns.name.from_text(self.domain)
        self.insecure_ok = insecure_ok
        self.rrsig_expiration_warn = rrsig_expiration_warn
        self.rrsig_expiration_crit = rrsig_expiration_crit

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
        names = [self.domain_native]
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
        delegation_warnings = [w.description for w in analysis_obj.delegation_warnings[43]]
        delegation_errors = [e.description for e in analysis_obj.delegation_errors[43]]

        zone_status = analysis_obj.zone_status
        zone_warnings = [w.description for w in analysis_obj.zone_warnings]
        zone_errors = [e.description for e in analysis_obj.zone_errors]

        dnssec_status = {
            'dnssec': {'status': zone_status, 'warnings': zone_warnings, 'errors': zone_errors},
            'delegation': {'status': delegation_status,
                           'warnings': delegation_warnings,
                           'errors': delegation_errors},
        }
        yield nagiosplugin.Metric('dnssec_status', dnssec_status, context='dnssec')

        rrsig_errors = set()
        rrsig_warnings = set()
        rrsig_expiration = None
        now = int(time.time())
        for _, rrsigs in analysis_obj.rrsig_status.iteritems():
            for rrsig, rrsets in rrsigs.iteritems():
                for keymeta, single_rrsig_status in rrsets.iteritems():
                    if keymeta.name != self.domain_native:
                        continue
                    for w in single_rrsig_status.warnings:
                        rrsig_warnings.add('{}: {}'.format(keymeta, w.description))
                    for e in single_rrsig_status.errors:
                        rrsig_errors.add('{}: {}'.format(keymeta, e.description))
                    expire_seconds = rrsig.expiration - now
                    if rrsig_expiration is None or expire_seconds < rrsig_expiration:
                        rrsig_expiration = expire_seconds
        yield nagiosplugin.Metric('rrsig_status',
                                  {'errors': rrsig_errors,
                                   'warnings': rrsig_warnings},
                                  context='rrsig')
        yield nagiosplugin.Metric('rrsig_expiration',
                                  rrsig_expiration,
                                  context='rrsig_expiration')


class DNSSummary(nagiosplugin.Summary):
    def ok(self, results):
        ret = []
        for result in results:
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

            if result.metric.name == 'rrsig_status':
                to_add = ''
                for m in ['errors', 'warnings']:
                    if result.metric.value.get(m):
                        to_add += ', '.join(result.metric.value.get(m))
                if to_add != '':
                    ret.append('{}: {}'.format(result.hint, to_add))
                else:
                    ret.append(result.hint)

            if result.metric.name == 'rrsig_expiration':
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
            if result.metric.name == 'rrsig_status':
                to_add = ''
                for m in ['errors', 'warnings']:
                    if result.metric.value.get(m):
                        to_add += ', '.join(result.metric.value.get(m))
                if to_add != '':
                    ret.append('{}: {}'.format(result.hint, to_add))
                else:
                    ret.append(result.hint)
            if result.metric.name == 'rrsig_expiration':
                ret.append(result.hint)
        return '; '.join(ret)


@nagiosplugin.guarded()
def main():
    argp = argparse.ArgumentParser(prog='check_dns', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    argp.add_argument('--domain', '-d', type=str, required=True, action='store',
                      help='Domain to check')
    argp.add_argument('--insecure-is-ok', action='store_true', default=False,
                      help='If the delegation is insecure, do not warn')
    argp.add_argument('--expire-warn', default=72, metavar='HOURS',
                      help='Warn if RRSIG expiry is within this many hours')
    argp.add_argument('--expire-crit', default=48, metavar='HOURS',
                      help='Crit if RRSIG expiry is within this many hours')
    argp.add_argument('--verbose', '-v', action='count', default=0,
                      help='Be more verbose')
    args = argp.parse_args()

    if args.expire_crit > args.expire_warn:
        raise nagiosplugin.CheckError('RRSIG Critical value ({}) higher than Warning value ({})'.format(
            args.expire_crit, args.expire_warn
        ))
    check = nagiosplugin.Check(
        DNS(args.domain, args.insecure_is_ok),
        DNSSECContext('dnssec'),
        RRSIGContext('rrsig'),
        RRSIGExpitationContext('rrsig_expiration',
                               warn_seconds=args.expire_warn * 60 * 60,
                               crit_seconds=args.expire_crit * 60 * 60),
        DNSSummary())
    check.main(args.verbose)


if __name__ == '__main__':
    main()
