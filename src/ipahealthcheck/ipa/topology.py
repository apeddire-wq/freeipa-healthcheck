#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api

logger = logging.getLogger()


@registry
class IPATopologyDomainCheck(IPAPlugin):
    """
    Execute the equivalant of ipa topologysuffix-verify domain

    Return any errors discovered. This can include:
      * too many agreements
      * connection errors
    """
    def report_errors(self, suffix, result):
        if result['result']['in_order']:
            yield Result(self, constants.SUCCESS, suffix=suffix)
        else:
            max_agmts = result['result']['max_agmts']
            connect_errors = result['result']['connect_errors']
            max_agmts_errors = result['result']['max_agmts_errors']
            cmsg = 'Server %(srv)s can\'t contact servers: %(replicas)s'
            mmsg = 'Server "%(srv)s" has %(n)d agreements, recommended ' \
                   'max %(m)d'

            if connect_errors:
                for error in connect_errors:
                    msg = cmsg % {'srv': error[0],
                                  'replicas': ', '.join(error[1])}
                    yield Result(self, constants.ERROR,
                                 key=error[0],
                                 replicas=error[2],
                                 suffix=suffix,
                                 type='connect',
                                 msg=msg)
            if max_agmts_errors:
                for error in max_agmts_errors:
                    msg = mmsg % {'srv': error[0],
                                  'n': len(error[1]),
                                  'm': max_agmts}
                    yield Result(self, constants.ERROR,
                                 key=error[0],
                                 replicas=error[1],
                                 suffix=suffix,
                                 type='max',
                                 msg=msg)

    def run_check(self, suffix):
        try:
            result = api.Command.topologysuffix_verify(suffix)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         msg='topologysuffix-verify domain failed, %s' %
                         e)
        else:
            for r in self.report_errors(suffix, result):
                yield r

    requires = ('dirsrv',)

    @duration
    def check(self):

        for y in self.run_check(u'domain'):
            yield y
        if api.Command.ca_is_enabled()['result']:
            for y in self.run_check(u'ca'):
                yield y


@registry
class IPAReplicaCountCheck(IPAPlugin):
    """
    Report the number of IPA replicas (servers) in the deployment.

    IPA supports a maximum of 60 replicas. Report a CRITICAL error when the
    number of servers exceeds this limit. The number of CA replicas is
    reported separately because only CA replicas replicate certificate data.
    """
    requires = ('dirsrv',)

    MAX_REPLICAS = 60

    def count_check(self, key, label, count):
        if count > self.MAX_REPLICAS:
            yield Result(self, constants.CRITICAL,
                         key=key,
                         label=label,
                         count=count,
                         max=self.MAX_REPLICAS,
                         msg='The number of {label} is {count} which exceeds '
                             'the supported maximum of {max}.')
        else:
            yield Result(self, constants.SUCCESS,
                         key=key,
                         label=label,
                         count=count)

    @duration
    def check(self):
        # Total number of IPA servers (replicas)
        try:
            result = api.Command.server_find(sizelimit=0)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='ipa_replicas',
                         error=str(e),
                         msg='Unable to retrieve the list of IPA servers: '
                             '{error}')
        else:
            count = result.get('count', len(result.get('result', [])))
            for y in self.count_check('ipa_replicas', 'IPA replicas', count):
                yield y

        # CA replicas; only servers with the CA role replicate certificate
        # data so they are counted separately.
        if not api.Command.ca_is_enabled()['result']:
            return
        try:
            result = api.Command.server_role_find(
                role_servrole=u'CA server', status=u'enabled', sizelimit=0)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='ca_replicas',
                         error=str(e),
                         msg='Unable to retrieve the list of CA servers: '
                             '{error}')
        else:
            count = result.get('count', len(result.get('result', [])))
            for y in self.count_check('ca_replicas', 'CA replicas', count):
                yield y
