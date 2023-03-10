from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.constants import severity
from w3af.core.data.dc.headers import Headers
from w3af.core.data.fuzzer.mutants.headers_mutant import HeadersMutant
from w3af.core.data.fuzzer.utils import rand_alnum
from w3af.core.data.fuzzer.mutants.querystring_mutant import QSMutant
from w3af.core.data.request.fuzzable_request import FuzzableRequest

import re
import time
import copy
import logging

logger = logging.getLogger(__name__)


class Web_Cache(AuditPlugin):
    """
    Identify the URLs for web cache poisoning

    :author: nikhil.mahajan@holmsecurity.com
    """

    CANARY = "holmsecurity.com"

    TIMEOUT_DELAY = 10

    headersToFuzz = [
        ("x-forwarded-scheme", ""),
        ("x-forwarded-host", ""),
        ("x-forwarded-proto", ""),
        ("x-http-method-override", ""),
        ("x-amz-website-redirect-location", ""),
        ("x-rewrite-url", ""),
        ("x-host", ""),
        ("user-agent", ""),
        ("handle", ""),
        ("h0st", ""),
        ("Transfer-Encoding", ""),
        ("x-original-url", ""),
        ("x-original-host", ""),
        ("x-forwarded-prefix", ""),
        ("x-amz-server-side-encryption", ""),
        ("trailer", ""),
        ("fastly-ssl", ""),
        ("fastly-host", ""),
        ("fastly-ff", ""),
        ("fastly-client-ip", ""),
        ("content-type", ""),
        ("api-version", ""),
        ("acunetix-header", ""),
        ("accept-version", ""),
    ]

    def __init__(self):
        AuditPlugin.__init__(self)

    def run(self, freq, orig_response, debug_id):
        self.debug_id = debug_id
        self.audit(freq, orig_response, debug_id)

    def audit(self, freq, orig_response, debugging_id):
        """
        Test URLs for web cache poisoning vulnerabilities

        :param freq: A FuzzableRequest
        :param orig_response: The HTTP response associated with the fuzzable request
        :param debugging_id: A unique identifier for this call to audit()
        """

        # self.headers_poisoning_check(freq, orig_response)

        # self._path_based_caching(freq, orig_response)

        self.fat_get_poisoning_check(freq, orig_response)

    def headers_poisoning_check(self, freq, orig_response):
        total_times = 10

        while total_times:
            total_times -= 1

            for injected_header in self.headersToFuzz:
                vulnerable = 0
                poison_check = 0
                total_attempts = 10
                while total_attempts:
                    total_attempts -= 1
                    self.custom_sleep(total_attempts)
                    header = Headers([injected_header])
                    freq_copy = copy.deepcopy(freq)
                    freq_copy.set_headers(headers=header)
                    freq_copy.set_force_fuzzing_headers(headers=header)

                    poisoned_mutants = create_mutants(
                        freq=freq_copy,
                        mutant_str_list=[self.CANARY],
                        orig_resp=orig_response,
                        debug_id=self.debug_id,
                    )

                    poisoned_res = None

                    for mutant in poisoned_mutants:
                        if (type(mutant) == HeadersMutant) and poisoned_res is None:
                            poisoned_res = self._uri_opener.send_mutant(
                                mutant, cache=False, grep=True, debug_id=self.debug_id, follow_redirects=False
                            )

                            if self._check_if_input_returned(self.CANARY, poisoned_res):
                                poison_check += 1

                    if (5 <= poison_check <= 10):
                        payload = [rand_alnum(10).lower()]

                        header = Headers([injected_header])
                        freq_copy = copy.deepcopy(freq)
                        freq_copy.set_headers(headers=header)
                        freq_copy.set_force_fuzzing_headers(headers=header)

                        mutants = create_mutants(
                            freq_copy,
                            mutant_str_list=payload,
                            orig_resp=orig_response,
                            debug_id=self.debug_id,
                        )

                        for mutant in mutants:
                            if (type(mutant) == HeadersMutant):
                                normal_res = self._uri_opener.send_mutant(
                                    mutant,
                                    grep=True,
                                    debug_id=self.debug_id,
                                    cache=False,
                                )
                                if self._check_if_input_returned(self.CANARY, normal_res):
                                    vulnerable += 1

                    else:
                        continue

                if 1<= vulnerable < 10:
                    total_attempts = 0
                    vulnerable = 0
                    poison_check = 0
                    total_times = 0
                    self._report_headers_poisoning_check(
                        injected_header, orig_response
                    )
                    break

    def _report_headers_poisoning_check(
        self, header, orig_response
    ):
        desc = (
            f"A unkeyed header [{header[0]}] with poisoned value {self.CANARY} is cached in response page"
        )

        v = Vuln(
            name="Web Cache Poisoning with an Unkeyed Header",
            desc=desc,
            severity=severity.HIGH,
            response_ids=orig_response.id,
            vulndb_id=" ",
            plugin_name=self.get_name(),
            debug_id=self.debug_id,
        )
        v.set_url(orig_response.get_url())

        logger.info(v.get_desc(), debug_id=self.debug_id)
        self.kb_append_uniq(self, "Unkeyed_header_cache_poisoning", v)

    def fat_get_poisoning_check(self, freq, orig_response):
        total_attempts = 10

        while total_attempts:
            print(f"total attempts :{total_attempts}")
            total_attempts -= 1
            flag = 0
            payload = [rand_alnum(10).lower()]

            if freq.get_method().upper() != "GET":
                return

            mutants = create_mutants(
                freq,
                mutant_str_list=payload,
                orig_resp=orig_response,
                debug_id=self.debug_id,
            )

            for mutant in mutants:
                poisoned_res = self._uri_opener.send_mutant(
                    mutant,
                    grep=True,
                    cache=False,
                    debug_id=self.debug_id,
                )
                # checking if the modified parameter value is reflected in the response body
                if self._check_if_input_returned(payload, poisoned_res):
                    flag = 1
                    data = mutant.get_dc()

            # If the modified parameter value is returned in the response page,
            # send 'modified_parameter=random_string' data in the original URI request and
            # examine the response to see if 'random_string' is cached in the response page.
            if flag == 1:
                total_times = 10
                vulnerable = 0
                while total_times:
                    self.custom_sleep(total_times)
                    total_times -= 1
                    freq_local = FuzzableRequest(
                        freq.get_uri(), method="GET", post_data=data)
                    datamutant = QSMutant(freq_local)

                    try:
                        print(f"total_times: {total_times}")
                        normal_res = self._uri_opener.send_mutant(
                            datamutant,
                            grep=True,
                            cache=False,
                            debug_id=self.debug_id,
                        )
                        print(f"\n\n{normal_res.get_body()}\n")
                    except (RuntimeError, BaseException):
                        pass

                    print(f"sending data :{data}, paylaod checking :{payload[0]}")

                    if (self._check_if_input_returned(payload, normal_res)):
                            vulnerable += 1
                            print(f"vulnerable :{vulnerable}")
                        
                if 1 <= vulnerable < 10:
                    vulnerable = 0
                    self._report_fat_get_poisoning_check(
                        payload, orig_response, data)
                    break

            

    def _report_fat_get_poisoning_check(
        self, payload, orig_response, data
    ):
        desc = (
            f"Web Cache Poisoning [fat-get] has been found by sending a data [{data}] in request, "
            f"Resulting in response caching {payload[0]}"
        )

        v = Vuln(
            name="Web Cache Poisoning [fat-get]",
            desc=desc,
            severity=severity.HIGH,
            response_ids=orig_response.id,
            vulndb_id=" ",
            plugin_name=self.get_name(),
            debug_id=self.debug_id,
        )
        v.set_url(orig_response.get_url())

        logger.info(v.get_desc(), debug_id=self.debug_id)
        self.kb_append_uniq(self, "fat_get_based_cache_poisoning", v)

    def _path_based_caching(self, freq, orig_response):
        flag = 0
        payload = [rand_alnum(10).lower()]

        if freq.get_method().upper() != "GET":
            return

        mutants = create_mutants(
            freq,
            mutant_str_list=payload,
            orig_resp=orig_response,
            debug_id=self.debug_id,
        )

        for mutant in mutants:
            poisoned_res = self._uri_opener.send_mutant(
                mutant,
                grep=True,
                cache=False,
                debug_id=self.debug_id,
            )

            if self._check_if_input_returned(payload, poisoned_res):
                flag = 1

        try:
            normal_res = self._uri_opener.GET(
                freq.get_uri(),
                cache=False,
                grep=True,
                timeout=10,
                debug_id=self.debug_id,
            )
        except (RuntimeError, BaseException):
            pass

        if (flag == 1 and self._check_if_input_returned(payload, normal_res)):
            self._report_path_based_poisoning_check(
                payload, orig_response)

    def _report_path_based_poisoning_check(
        self, payload, orig_response
    ):
        desc = (
            f"Web Cache Poisoning [path based] has been found by setting parameter {payload[0]} in request, "
            f"Resulting in response caching {payload[0]}.\n"
            f"Normal response after sending the request caching same parameter {payload[0]} indicates it has been cached."
        )

        v = Vuln(
            name="Web Cache Poisoning [path based]",
            desc=desc,
            severity=severity.HIGH,
            response_ids=orig_response.id,
            vulndb_id=" ",
            plugin_name=self.get_name(),
            debug_id=self.debug_id,
        )
        v.set_url(orig_response.get_url())

        logger.info(v.get_desc(), debug_id=self.debug_id)
        self.kb_append_uniq(self, "path_based_cache_poisoning", v)

    def _check_if_input_returned(self, payload, response):
        """
        return true if the regex is able to find payload or the query parameter in the response body.
        """
        if re.search(r"\b{}\b".format(payload[0]), response.get_body()):
            return True

        return False

    def custom_sleep(self, sec):
        time.sleep(sec)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin will check for web cache poisoning vulnerabilities.
        """
