#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

from util import capture_results, m_api
from base import BaseTest

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.topology import IPAReplicaCountCheck


class TestReplicaCount(BaseTest):
    def run_check(self):
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAReplicaCountCheck(registry)
        return capture_results(f)

    def test_count_ok(self):
        m_api.Command.server_find.reset_mock()
        m_api.Command.server_role_find.reset_mock()
        m_api.Command.server_find.return_value = {'count': 3}
        m_api.Command.server_role_find.return_value = {'count': 2}
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        self.results = self.run_check()

        assert len(self.results) == 2
        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.topology'
            assert result.check == 'IPAReplicaCountCheck'

        assert self.results.results[0].kw.get('key') == 'ipa_replicas'
        assert self.results.results[0].kw.get('count') == 3
        assert self.results.results[1].kw.get('key') == 'ca_replicas'
        assert self.results.results[1].kw.get('count') == 2

        # The CA replicas are counted via the enabled CA server role.
        _, kwargs = m_api.Command.server_role_find.call_args
        assert kwargs.get('role_servrole') == 'CA server'
        assert kwargs.get('status') == 'enabled'

    def test_count_no_ca(self):
        m_api.Command.server_find.reset_mock()
        m_api.Command.server_role_find.reset_mock()
        m_api.Command.server_find.return_value = {'count': 5}
        m_api.Command.ca_is_enabled.return_value = {'result': False}

        self.results = self.run_check()

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.kw.get('key') == 'ipa_replicas'
        # No CA, so the CA role must not be queried.
        assert m_api.Command.server_role_find.call_count == 0

    def test_count_replicas_exceeded(self):
        m_api.Command.server_find.reset_mock()
        m_api.Command.server_role_find.reset_mock()
        m_api.Command.server_find.return_value = {'count': 61}
        m_api.Command.server_role_find.return_value = {'count': 2}
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        self.results = self.run_check()

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.kw.get('key') == 'ipa_replicas'
        assert result.kw.get('count') == 61
        assert result.kw.get('max') == 60
        assert 'exceeds the supported maximum' in result.kw.get('msg')

        assert self.results.results[1].result == constants.SUCCESS
        assert self.results.results[1].kw.get('key') == 'ca_replicas'

    def test_count_ca_exceeded(self):
        m_api.Command.server_find.reset_mock()
        m_api.Command.server_role_find.reset_mock()
        m_api.Command.server_find.return_value = {'count': 3}
        m_api.Command.server_role_find.return_value = {'count': 100}
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        self.results = self.run_check()

        assert len(self.results) == 2

        assert self.results.results[0].result == constants.SUCCESS
        assert self.results.results[0].kw.get('key') == 'ipa_replicas'

        result = self.results.results[1]
        assert result.result == constants.CRITICAL
        assert result.kw.get('key') == 'ca_replicas'
        assert result.kw.get('count') == 100

    def test_count_fallback_result_list(self):
        # Some API versions may not return 'count'; fall back to len(result).
        m_api.Command.server_find.reset_mock()
        m_api.Command.server_role_find.reset_mock()
        m_api.Command.server_find.return_value = {'result': [{}, {}, {}]}
        m_api.Command.ca_is_enabled.return_value = {'result': False}

        self.results = self.run_check()

        assert len(self.results) == 1
        assert self.results.results[0].kw.get('count') == 3
