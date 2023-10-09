#  Copyright 2023 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


import json
from datetime import datetime

from django.db import DatabaseError
from kubernetes import client, config
from kubernetes.client import exceptions

from aap_eda.core import models
from aap_eda.core.enums import ActivationStatus
from aap_eda.services.ruleset.exceptions import (
    ActivationRecordNotFound,
    K8sActivationException,
)

from .activation_db_logger import ActivationDbLogger


class KubernetesReadLogs:
    def __init__(self, activation_db_logger: ActivationDbLogger):
        # Setup kubernetes api client
        config.load_incluster_config()

        self.client_api = client.CoreV1Api()
        self.activation_db_logger = activation_db_logger

    def run(
        self,
        activation_instance: models.ActivationInstance,
    ) -> None:
        activation = activation_instance.activation
        pod_name = f"activation-pod-{activation.pk}-{activation_instance.id}"

        ns_fileref = open(
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r"
        )
        namespace = ns_fileref.read()
        ns_fileref.close()
        try:
            if activation_instance.log_read_at:
                since = int(activation_instance.log_read_at.timestamp()) + 1
            else:
                start_dt = "2000-01-01T00:00:00-00:00"
                since = (
                    int(
                        datetime.strptime(
                            start_dt, "%Y-%m-%dT%H:%M:%S%z"
                        ).timestamp()
                    )
                    + 1
                )
            dt = None
            pod_details = json.loads(
                (
                    self.client_api.read_namespaced_pod(
                        name=pod_name,
                        namespace=namespace,
                        _preload_content=False,
                    )
                ).data
            )
            container = pod_details["status"]["containerStatuses"][0]
            if container["state"] in ["running", "exited"]:
                for line in self.client_api.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=namespace,
                    pretty=True,
                    since_seconds=since,
                    timestamps=True,
                ):
                    log = line.decode("utf-8")
                    dt = log.split()[0]
                    self.activation_db_logger.write(log)

            if dt:
                since = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S%z")
                self.activation_db_logger.flush()
                activation_instance.log_read_at = dt
                activation_instance.status = ActivationStatus.STOPPED
                activation_instance.save(update_fields=["log_read_at"])

        except exceptions.ApiException as e:
            if e.status == 404:  # Not Found
                raise K8sActivationException(
                    f"Failed to read logs of unavailable pod {pod_name}"
                )
            else:
                raise K8sActivationException(
                    f"Failed to read pod logs: \n {e}"
                )
        except DatabaseError:
            message = (
                f"Instance [id: {activation_instance.id}] is not present."
            )
            raise ActivationRecordNotFound(message)
        except Exception as e:
            raise K8sActivationException(f"Failed to read pod logs: \n {e}")
