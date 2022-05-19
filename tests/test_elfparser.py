import json
import os
import shutil

import pytest

import elfparser.elfparser

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples_hashes = [
    "17d02f610223768ff002f62fb989c2e179549d2843c4a7a62d05d0991276dc42",
    "5a93d676f9ac0b71f4ac3ca43a001df6fac89dba56cc8652a55cec9b84b53ab4",
]

samples = [
    {
        "sid": idx,
        "metadata": {},
        "deep_scan": False,
        "service_name": "elfparser",
        "service_config": {},
        "fileinfo": {
            "magic": "Not Important",
            "md5": "a" * 32,
            "mime": "Not Important",
            "sha1": "a" * 40,
            "sha256": sample,
            "size": 1,
            "type": "Not Important",
        },
        "filename": sample,
        "min_classification": "TLP:WHITE",
        "max_files": 501,
        "ttl": 3600,
    }
    for idx, sample in enumerate(samples_hashes)
]


def create_tmp_manifest():
    if not os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, TEMP_SERVICE_CONFIG_PATH)


def remove_tmp_manifest():
    if os.path.exists(TEMP_SERVICE_CONFIG_PATH):
        os.remove(TEMP_SERVICE_CONFIG_PATH)


class TestELFParser:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_start():
        cls = elfparser.elfparser.ELFPARSER()
        assert not hasattr(cls, "header_line")
        cls.start()
        assert hasattr(cls, "header_line")

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample):
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.task import Task

        cls = elfparser.elfparser.ELFPARSER()
        cls.start()

        service_task = ServiceTask(sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)

        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.load(f)
        f.close()

        # Assert values of the class instance are expected
        assert cls.file_res == service_request.result

        assert test_result == correct_result
