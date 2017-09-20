import base64
from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import AnalysisPermanentError, AnalysisResult, AnalysisTemporaryError, BinaryAnalysisProvider
from cbint.utils.feed import generate_feed
import logging
import os
from rest_api import VMRayRESTAPI, VMRayRESTAPIError
import time


LOGGER = logging.getLogger(__name__)
DEF_VTI_SCORE_THRESHOLD = 50
DEF_MAX_ANALYSIS_WAIT_TIME = 60 * 60
DEF_RETRY_WAIT_TIME = 120
DEF_LOOP_WAIT_TIME = 5


class VMRayProvider(BinaryAnalysisProvider):
    def __init__(
            self,
            name,
            vmray_server,
            vmray_api_key,
            verify_ssl=False,
            vti_score_threshold=DEF_VTI_SCORE_THRESHOLD,
            max_analysis_wait_time=DEF_MAX_ANALYSIS_WAIT_TIME,
            retry_wait_time=DEF_RETRY_WAIT_TIME,
            loop_wait_time=DEF_LOOP_WAIT_TIME,
        ):
        super(VMRayProvider, self).__init__(name)

        LOGGER.debug("Creating new VMRay provider for server \"%s\" (verify_ssl=%s)", vmray_server, verify_ssl)
        self.rest_api = VMRayRESTAPI(vmray_server, vmray_api_key, verify_ssl)
        self.vti_score_threshold = vti_score_threshold
        self.max_analysis_wait_time = max_analysis_wait_time
        self.retry_wait_time = retry_wait_time
        self.loop_wait_time = loop_wait_time

    def create_result(self, sample_id, submission_id=None):
        """Create Carbon Black result for the given sample"""

        try:
            sample = self.rest_api.call("GET", "/rest/sample/%u" % (sample_id))
            if submission_id is not None:
                LOGGER.debug("Creating result for sample with ID %u (submission_id=%s)", sample_id, submission_id)
                submission = self.rest_api.call("GET", "/rest/submission/%u" % (submission_id))
                if "submission_finished" in submission:
                    # new way
                    if submission["submission_finished"]:
                        analyses = self.rest_api.call("GET", "/rest/analysis/submission/%u" % (submission_id))
                    else:
                        raise AnalysisTemporaryError(message="API error: Submission ID %u not finished yet" % (submission_id), retry_in=self.retry_wait_time)

                else:
                    # deprecated old way
                    # get analyses
                    analyses = self.rest_api.call("GET", "/rest/analysis/sample/%u" % (sample_id))
                    # filter by submission_id
                    analyses = [analysis for analysis in analyses if analysis["analysis_submission_id"] == submission_id]
            else:
                LOGGER.debug("Creating result for sample with ID %u", sample_id)
                # get all analyses
                analyses = self.rest_api.call("GET", "/rest/analysis/sample/%u" % (sample_id))
        except BaseException as exc:
            LOGGER.debug("Error getting sample and analyses info for sample ID %s", sample_id, exc_info=True)
            raise AnalysisTemporaryError(message="API error: %s" % (str(exc)))

        # check if any error occurred
        for analysis in analyses:
            if analysis["analysis_result_code"] != 1:
                LOGGER.warning("Analysis with ID %u of sample with ID %u failed with error code 0x%x: %s", analysis["analysis_id"], sample_id, analysis["analysis_result_code"], analysis["analysis_result_str"])

        # check sample VTI score
        if (sample["sample_vti_score"] is None) or (sample["sample_vti_score"] < self.vti_score_threshold):
            message = "Benign"
        else:
            message = "Potential malware"

        # Check for None in the score
        if not sample["sample_vti_score"] and message == 'Benign':
            sample["sample_vti_score"] = 0

        if not sample["sample_vti_score"] and message == 'Potential malware':
            sample["sample_vti_score"] = 100

        LOGGER.debug("Analysis result of sample with ID %u created successfully (message=%s link=%s score=%u)", sample_id, message, sample["sample_webif_url"], sample["sample_vti_score"])
        return AnalysisResult(
            message=message,
            extended_message="",
            link=sample["sample_webif_url"],
            score=sample["sample_vti_score"],
        )

    def check_result_for(self, md5_hash):
        LOGGER.debug("Checking result for md5 %s", md5_hash)
        try:
            result = self.rest_api.call("GET", "/rest/sample/md5/%s" % (md5_hash.lower()))
        except BaseException as exc:
            LOGGER.debug("Error while checking for md5 %s", md5_hash, exc_info=True)
            raise AnalysisTemporaryError(message="API error: %s" % (str(exc)), retry_in=self.retry_wait_time)

        LOGGER.debug("%u sample(s) found with md5 %s", len(result), md5_hash)
        if len(result) == 0:
            return None
        else:
            return self.create_result(result[0]["sample_id"])

    def analyze_binary(self, md5_hash, binary_file_stream):
        LOGGER.info("Submitting binary with md5 %s to VMRay" % (md5_hash))

        # submit file to VMRay
        try:
            result = self.rest_api.call("POST",
                                        "/rest/sample/submit",
                                        params={"archive_action": "ignore",
                                                "sample_file": binary_file_stream,
                                                "sample_filename_b64enc": base64.encodestring(md5_hash),
                                                "reanalyze": True})
        except VMRayRESTAPIError as exc:
            LOGGER.debug("Error submitting sample with md5 %s", md5_hash, exc_info=True)
            raise AnalysisTemporaryError(message="API error: %s" % str(exc), retry_in=self.retry_wait_time)

        if result.get("errors", None):
            raise AnalysisPermanentError(message="API error: %s" % str(result["errors"][0].get("error_msg","")))

        sample_id = result["samples"][0]["sample_id"]
        submission_id = result["submissions"][0]["submission_id"]

        LOGGER.debug("Waiting for submission with ID %u to finish all jobs", submission_id)

        # wait until all analyses have finished
        if "submission_finished" in result["submissions"][0]:
            wait_start = time.time()
            while True:
                time.sleep(self.loop_wait_time)
                if (time.time() - wait_start) > self.max_analysis_wait_time:
                    LOGGER.debug("Timed out waiting for result of submission with ID %u", submission_id)
                    raise AnalysisTemporaryError(message="Timed out waiting for analysis jobs to finish for submission %u" % (submission_id), retry_in=self.retry_wait_time)
                try:
                    submission = self.rest_api.call("GET", "/rest/submission/%u" % (submission_id))
                except:
                    LOGGER.debug("Could not get submission ID %u", submission_id)
                    continue
                if submission.get("submission_finished", False):
                    break
        else:
            # old method
            open_jobs = list(result["jobs"])
            wait_start = time.time()
            while len(open_jobs) > 0:
                # check for timeout
                if (time.time() - wait_start) > self.max_analysis_wait_time:
                    LOGGER.debug("Timed out waiting for result of submission with ID %u", submission_id)
                    raise AnalysisTemporaryError(message="Timed out waiting for analysis jobs to finish for submission %u" % (submission_id), retry_in=self.retry_wait_time)

                check_jobs = list(open_jobs)
                open_jobs = []
                for job in check_jobs:
                    try:
                        self.rest_api.call("GET", "/rest/job/%u" % (job["job_id"]))
                    except VMRayRESTAPIError as exc:
                        if exc.status_code == 404:
                            # job has finished
                            continue

                    # job is still there or server is unreachable
                    open_jobs.append(job)

                if len(open_jobs) == 0:
                    break

                time.sleep(self.loop_wait_time)

        LOGGER.debug("All jobs for submission with ID %u have finished", submission_id)
        return self.create_result(sample_id, submission_id=submission_id)


class VMRayConnector(DetonationDaemon):

    @property
    def integration_name(self):
        return 'Cb VmRay Connector 1.1.6'

    @property
    def filter_spec(self):
        # fixme
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append("(os_type:windows OR os_type:osx) orig_mod_len:[1 TO %d]" % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return " ".join(filters)

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("vmray_quick_scan_threads", 1)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("vmray_deep_scan_threads", 3)

    def get_provider(self):
        return VMRayProvider(
            self.name,
            self.vmray_server,
            self.vmray_api_key,
            verify_ssl=self.vmray_sslverify,
            vti_score_threshold=self.vmray_vti_score_threshold,
            max_analysis_wait_time=self.vmray_max_analysis_wait_time,
            retry_wait_time=self.vmray_retry_wait_time,
            loop_wait_time=self.vmray_loop_wait_time,
        )

    def get_metadata(self):
        return generate_feed(
            self.name,
            summary="VMRay Detonation Analysis",
            tech_data="An on-premises VMRay server is required to use this feed. There are no requirements to share any data with Carbon Black to use this feed.",
            provider_url="http://www.vmray.com",
            icon_path="/usr/share/cb/integrations/vmray/vmray-logo.png",
            display_name="VMRay",
            category="Connectors",
        )

    def validate_config(self):
        super(VMRayConnector, self).validate_config()

        self.check_required_options(["vmray_server", "vmray_api_key"])
        self.vmray_server = self.get_config_string("vmray_server", None)
        self.vmray_api_key = self.get_config_string("vmray_api_key", None)
        self.vmray_sslverify = self.get_config_boolean("vmray_sslverify", False)
        self.vmray_max_analysis_wait_time = self.get_config_integer("vmray_max_analysis_wait_time", DEF_MAX_ANALYSIS_WAIT_TIME)
        self.vmray_retry_wait_time = self.get_config_integer("vmray_retry_wait_time", DEF_RETRY_WAIT_TIME)
        self.vmray_loop_wait_time = self.get_config_integer("vmray_loop_wait_time", DEF_LOOP_WAIT_TIME)
        self.vmray_vti_score_threshold = self.get_config_integer("vmray_vti_score_threshold", DEF_VTI_SCORE_THRESHOLD)
        return True


def main():
    daemon = VMRayConnector(
        "vmraytest",
        configfile="/tmp/vmray_test/testing.conf",
        work_directory="/tmp/vmray_test",
        logfile="/tmp/vmray_test/test.log",
        debug=True,
    )
    daemon.start()


if __name__ == "__main__":
    main()
