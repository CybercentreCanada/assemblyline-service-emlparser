import os
import shutil

import pytest
from assemblyline.common import forge
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

import emlparser.emlparser

identify = forge.get_identify(use_cache=False)


@pytest.fixture()
def sample(request):
    sample_path = os.path.join("tests", "samples", request.param)
    sha256_of_file = identify.fileinfo(sample_path, skip_fuzzy_hashes=True)["sha256"]
    shutil.copy(sample_path, os.path.join("/tmp", sha256_of_file))
    yield sha256_of_file
    os.remove(os.path.join("/tmp", sha256_of_file))


def create_service_task(sample):
    fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

    return ServiceTask(
        {
            "sid": 1,
            "metadata": {},
            "deep_scan": False,
            "service_name": "Not Important",
            "service_config": {
                "extract_body_text": False,
                "save_emlparser_output": False,
            },
            "fileinfo": {
                k: v
                for k, v in identify.fileinfo(f"/tmp/{sample}", skip_fuzzy_hashes=True).items()
                if k in fileinfo_keys
            },
            "filename": sample,
            "min_classification": "TLP:WHITE",
            "max_files": 501,
            "ttl": 3600,
        }
    )


class TestService:
    @staticmethod
    @pytest.mark.parametrize("sample", ["issue33.eml"], indirect=True)
    def test_service(sample):
        config = helper.get_service_attributes().config

        cls = emlparser.emlparser.EmlParser(config=config)
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        assert "0766" in test_result["temp_submission_data"]["email_body"]
