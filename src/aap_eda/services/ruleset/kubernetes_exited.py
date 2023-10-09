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
import logging

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
from .kubernetes_read_logs import KubernetesReadLogs

logger = logging.getLogger(__name__)


class KubernetesExited:
    def __init__(self, activation_db_logger: ActivationDbLogger):
        # Setup kubernetes api client
        config.load_incluster_config()

        self.client_api = client.CoreV1Api()
        self.activation_db_logger = activation_db_logger

    def get_status(
        self,
        activation_instance: models.ActivationInstance,
    ) -> ActivationStatus:
        activation = activation_instance.activation
        status = ActivationStatus.RUNNING
        try:
            pod_name = (
                f"activation-pod-{activation.pk}-{activation_instance.id}"
            )

            ns_fileref = open(
                "/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r"
            )
            namespace = ns_fileref.read()
            ns_fileref.close()
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
            if container["state"] in ["exited"]:
                KubernetesReadLogs(self.activation_db_logger).run(
                    activation_instance
                )
                exit_code = container.state.terminated.exit_code
                reason = container.state.terminated.reason
                logger.info(
                    f"Pod {pod_name} exit_code {exit_code} reason {reason}"
                )
                if exit_code == 0:
                    activation_instance.status = ActivationStatus.COMPLETED
                else:
                    activation_instance.status = ActivationStatus.FAILED

                activation_instance.save(update_fields=["status"])
                status = activation_instance.status
            elif container["state"] in ["running"]:
                status = ActivationStatus.RUNNING

        except exceptions.ApiException as e:
            if e.status == 404:  # Not Found
                raise K8sActivationException(
                    f"Failed to get details of pod {pod_name}, its unavailable"
                )
            else:
                raise K8sActivationException(
                    f"Failed to read pod status: \n {e}"
                )
        except DatabaseError:
            message = (
                f"Instance [id: {activation_instance.id}] is not present."
            )
            raise ActivationRecordNotFound(message)
        except Exception as e:
            raise K8sActivationException(f"Failed to read pod status: \n {e}")

        return status
