#
# -----------------------------------------------------------------------------
#                     The CodeChecker Infrastructure
#   This file is distributed under the University of Illinois Open Source
#   License. See LICENSE.TXT for details.
# -----------------------------------------------------------------------------

import json
import os
import unittest
import logging

from codeCheckerDBAccess.ttypes import ReportFilter
from codeCheckerDBAccess.ttypes import DiffType

from test_utils.thrift_client_to_db import CCViewerHelper
from test_utils.debug_printer import print_run_results

import shared

def get_severity_level(name):
    """
    convert severity level from the name to value
    """
    return shared.ttypes.Severity._NAMES_TO_VALUES[name]

class RunResults(unittest.TestCase):

    _ccClient = None

    # selected runid for running the tests
    _runid = None

    def setUp(self):
        host = 'localhost'
        port = int(os.environ['CC_TEST_VIEWER_PORT'])
        uri = '/'
        self._testproject_data = json.loads(os.environ['CC_TEST_PROJECT_INFO'])
        self.assertIsNotNone(self._testproject_data)
        self._cc_client = CCViewerHelper(host, port, uri)

    # -----------------------------------------------------
    def test_get_diff_res_count_new(self):
        """
        count the new results with no filter
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        diff_res = self._cc_client.getDiffResultCount(base_run_id,
                                                   new_run_id,
                                                   DiffType.NEW,
                                                   [])
        self.assertEqual(diff_res, 0)

    # -----------------------------------------------------
    def test_get_diff_res_count_resolved(self):
        """
        count the resolved results with no filter
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        diff_res = self._cc_client.getDiffResultCount(base_run_id,
                                                   new_run_id,
                                                   DiffType.RESOLVED,
                                                   [])
        self.assertEqual(diff_res, 0)

    # -----------------------------------------------------
    def test_get_diff_res_count_unresolved(self):
        """
        count the unresolved results with no filter
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        base_count = self._cc_client.getRunResultCount(base_run_id, [])
        logging.debug("Base run id: %d", base_run_id)
        logging.debug("Base count: %d", base_count)

        base_run_res = self._cc_client.getAllRunResults(base_run_id, [], [])

        print_run_results(base_run_res)

        new_count = self._cc_client.getRunResultCount(new_run_id, [])
        logging.debug("New run id: %d", new_run_id)
        logging.debug("New count: %d", new_count)

        new_run_res = self._cc_client.getAllRunResults(new_run_id, [], [])

        print_run_results(new_run_res)

        diff_res = self._cc_client.getDiffResultCount(base_run_id,
                                                      new_run_id,
                                                      DiffType.UNRESOLVED,
                                                      [])
        self.assertEqual(diff_res, 23)

    # -----------------------------------------------------
    def test_get_diff_res_count_unresolved_filter(self):
        """
        This test asumes nothing has been resolved between the two checker runs
        The the same severity levels and numbers are used as in a
        simple filter test for only one run from the project config
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        # severity levels used for filtering
        filter_severity_levels = self._testproject_data['filter_severity_levels']

        for level in filter_severity_levels:
            for severity_level, test_result_count in level.iteritems():
                simple_filters = []
                sev = get_severity_level(severity_level)
                simple_filter = ReportFilter(severity=sev)
                simple_filters.append(simple_filter)

                diff_result_count = self._cc_client.getDiffResultCount(
                    base_run_id, new_run_id, DiffType.UNRESOLVED,
                    simple_filters)

                self.assertEqual(test_result_count, diff_result_count)

    # -----------------------------------------------------
    def test_get_diff_res_types_new(self):
        """
        test diff result types for new results
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        diff_res = self._cc_client.getDiffResultTypes(base_run_id,
                                                      new_run_id,
                                                      DiffType.NEW,
                                                      [])
        self.assertEqual(len(diff_res), 0)

    # -----------------------------------------------------
    def test_get_diff_res_types_resolved(self):
        """
        test diff result types for resolved results
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        diff_res = self._cc_client.getDiffResultTypes(base_run_id,
                                                      new_run_id,
                                                      DiffType.RESOLVED,
                                                      [])
        self.assertEqual(len(diff_res), 0)

    # -----------------------------------------------------
    def test_get_diff_res_types_unresolved(self):
        """
        test diff result types for unresolved results with no filter
        on the api
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        diff_res = self._cc_client.getDiffResultTypes(base_run_id,
                                                      new_run_id,
                                                      DiffType.UNRESOLVED,
                                                      [])

        diff_res_types_filter = self._testproject_data['diff_res_types_filter']

        for level in diff_res_types_filter:
            for checker_name, test_result_count in level.iteritems():
                diff_res = self._cc_client.getDiffResultTypes(base_run_id,
                                                              new_run_id,
                                                              DiffType.UNRESOLVED,
                                                              [])
                res = [r for r in diff_res if r.checkerId == checker_name]

                # there should be only one result for each checker name
                self.assertEqual(len(res), 1)
                self.assertEqual(test_result_count, res[0].count)
                self.assertEqual(checker_name, res[0].checkerId)

    # -----------------------------------------------------
    def test_get_diff_res_types_unresolved_filter(self):
        """
        test diff result types for unresolved results with
        checker name filter on the api
        """
        runs = self._cc_client.getRunData()
        self.assertIsNotNone(runs)
        self.assertNotEqual(len(runs), 0)
        self.assertGreaterEqual(len(runs), 2)

        base_run_id = runs[0].runId
        new_run_id = runs[1].runId

        diff_res_types_filter = self._testproject_data['diff_res_types_filter']

        for level in diff_res_types_filter:
            for checker_name, test_result_count in level.iteritems():
                simple_filters = []
                simple_filter = ReportFilter(checkerId=checker_name)
                simple_filters.append(simple_filter)

                diff_res = self._cc_client.getDiffResultTypes(base_run_id,
                                                              new_run_id,
                                                              DiffType.UNRESOLVED,
                                                              simple_filters)

                # there should be only one for each checker name
                self.assertEqual(len(diff_res), 1)
                self.assertEqual(test_result_count, diff_res[0].count)
                self.assertEqual(checker_name, diff_res[0].checkerId)
