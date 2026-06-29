#  Copyright 2024 Red Hat, Inc.
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

import logging
from typing import Union

from django.core.exceptions import ObjectDoesNotExist

import aap_eda.tasks.activation_request_queue as requests_queue
from aap_eda.core.enums import (
    ActivationRequest,
    ActivationStatus,
    ProcessParentType,
)
from aap_eda.core.models import Activation, ActivationRequestQueue, EventStream
from aap_eda.services.activation import exceptions
from aap_eda.services.activation.manager import ActivationManager

LOGGER = logging.getLogger(__name__)


def manage_process_job_id(process_parent_type: str, id: int) -> str:
    """Return the unique job id for the activation manager task."""
    return f"{process_parent_type}-{id}"


def rp_manage(process_parent_type: str, id: int) -> None:
    """Manage the activation with the given id.

    It will run pending user requests or monitor the activation
    if there are no pending requests.
    """
    try:
        if process_parent_type == ProcessParentType.ACTIVATION:
            klass = Activation
        else:
            klass = EventStream
        process_parent = klass.objects.get(id=id)
    except ObjectDoesNotExist:
        LOGGER.warning(
            f"{process_parent_type} with {id} no longer exists, "
            "activation manager task will not be processed",
        )
        return

    has_request_processed = False
    while_condition = True
    while while_condition:
        pending_requests = requests_queue.peek_all(process_parent_type, id)
        while_condition = bool(pending_requests)
        for request in pending_requests:
            if _run_request(process_parent, request):
                requests_queue.pop_until(process_parent_type, id, request.id)
                has_request_processed = True
            else:
                while_condition = False
                break

    if (
        not has_request_processed
        and process_parent.status == ActivationStatus.RUNNING
    ):
        LOGGER.info(
            f"Processing monitor request for {process_parent_type} {id}",
        )
        ActivationManager(process_parent).monitor()


def _run_request(
    process_parent: Union[Activation, EventStream],
    request: ActivationRequestQueue,
) -> bool:
    """Attempt to run a request for an activation via the manager."""
    process_parent_type = type(process_parent).__name__
    LOGGER.info(
        f"Processing request {request.request} for {process_parent_type} "
        f"{process_parent.id}",
    )
    start_commands = [ActivationRequest.START, ActivationRequest.AUTO_START]
    if (
        request.request in start_commands
        and not ActivationManager.check_new_process_allowed(
            process_parent_type,
            process_parent.id,
        )
    ):
        return False

    manager = ActivationManager(process_parent)
    try:
        if request.request in start_commands:
            manager.start(
                is_restart=request.request == ActivationRequest.AUTO_START,
            )
        elif request.request == ActivationRequest.STOP:
            manager.stop()
        elif request.request == ActivationRequest.RESTART:
            manager.restart()
        elif request.request == ActivationRequest.DELETE:
            manager.delete()
    except exceptions.MaxRunningProcessesError:
        return False
    except Exception as e:
        LOGGER.exception(
            f"Failed to process request {request.request} for "
            f"{process_parent_type} {process_parent.id}. Reason {str(e)}",
        )
    return True
