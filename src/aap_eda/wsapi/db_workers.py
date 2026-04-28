#  Copyright 2026 Red Hat, Inc.
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
"""
DB Workers for WebSocket message processing.

This module contains long-running asyncio workers that process messages
from queues and write to the database. This prevents the WebSocket consumer
from being blocked by database operations.

Architecture:
- Configurable number of action workers (default: 3, configurable via WEBSOCKET_ACTION_MESSAGE_WORKERS)
- 1 session stats worker
- 2 asyncio queues with unlimited depth (action_queue, session_stats_queue)
- Workers run continuously across all WebSocket connections
- Multiple connections can enqueue to the same shared queues
- Action workers process messages concurrently from the shared queue
- Each worker uses 1 DB connection, providing bounded concurrency
"""

import asyncio
import logging
from datetime import datetime
import time
from typing import Optional
from urllib.parse import urlparse, urlunparse

from channels.db import database_sync_to_async
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from aap_eda.core import models
from aap_eda.core.enums import DefaultCredentialType
from aap_eda.core.utils.credentials import get_resolved_secrets

from .messages import ActionMessage, HeartbeatMessage

logger = logging.getLogger(__name__)

# Module-level queues shared across all WebSocket connections
# Using maxsize=0 for unlimited queue depth
action_queue: asyncio.Queue = asyncio.Queue(maxsize=0)
session_stats_queue: asyncio.Queue = asyncio.Queue(maxsize=0)

# Track worker tasks
_worker_tasks = []
_workers_started = False
_workers_lock = asyncio.Lock()


def _parse_message_timestamp(reported_at: Optional[str]) -> datetime:
    """
    Parse the reported_at timestamp from HeartbeatMessage.
    Returns a timezone-aware datetime object.
    """
    if not reported_at:
        return timezone.now()

    parsed = parse_datetime(reported_at)
    if parsed is None:
        logger.warning(
            f"Failed to parse reported_at: {reported_at}, using current time"
        )
        return timezone.now()

    # Ensure timezone-aware
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed)

    return parsed


async def action_worker(worker_id: int = 0):
    """
    Long-running worker that processes ActionMessage items from the queue.
    Processes messages one at a time.

    Args:
        worker_id: Unique identifier for this worker (for logging)
    """
    logger.info(f"Action worker {worker_id} started")

    while True:
        try:
            # Wait for a message
            message = await action_queue.get()

            try:
                logger.debug(f"[Worker {worker_id}] Processing action message")
                await _process_action(message)
                logger.debug(
                    f"[Worker {worker_id}] Successfully processed action message"
                )
            except Exception as e:
                logger.error(
                    f"[Worker {worker_id}] Error processing action message: {e}",
                    exc_info=True,
                )
            finally:
                # Mark message as done
                action_queue.task_done()

        except asyncio.CancelledError:
            logger.info(f"Action worker {worker_id} cancelled")
            break
        except Exception as e:
            logger.error(
                f"[Worker {worker_id}] Unexpected error in action worker: {e}",
                exc_info=True,
            )
            await asyncio.sleep(0.1)


async def session_stats_worker():
    """
    Long-running worker that processes HeartbeatMessage (session stats) from the queue.

    Deduplicates messages within the queue by collecting messages for a brief period
    and keeping only the latest per activation. This prevents unnecessary database
    writes when multiple stats updates arrive in rapid succession.

    Uses SELECT FOR UPDATE to prevent race conditions across multiple servers.
    """
    logger.info("Session stats worker started with queue-level deduplication")

    DEDUP_TIMEOUT = 0.1  # 100ms - collect messages before deduplicating

    while True:
        messages_to_deduplicate = []
        message_count = 0

        try:
            # Monitor queue depth for potential blocking issues
            queue_depth = session_stats_queue.qsize()
            if queue_depth > 100:
                logger.warning(
                    f"Session stats queue depth high: {queue_depth} messages queued. "
                    f"Possible database blocking!"
                )
            elif queue_depth > 10:
                logger.info(f"Session stats queue depth: {queue_depth}")

            # Get the first message (blocking wait)
            first_message = await session_stats_queue.get()
            messages_to_deduplicate.append(first_message)
            message_count += 1

            # Collect additional messages for a brief period for deduplication
            try:
                while True:
                    message = await asyncio.wait_for(
                        session_stats_queue.get(), timeout=DEDUP_TIMEOUT
                    )
                    messages_to_deduplicate.append(message)
                    message_count += 1
            except asyncio.TimeoutError:
                # Timeout - process what we have
                pass

            # Deduplicate: keep only the latest message per (activation_id, ruleset_name)
            # This ensures all rulesets are preserved when ansible-rulebook loops through them
            latest_per_activation_ruleset = {}
            for message in messages_to_deduplicate:
                activation_id = message.activation_id
                ruleset_name = message.stats.get("ruleSetName")

                # Create composite key to preserve all rulesets
                key = (activation_id, ruleset_name)
                message_timestamp = _parse_message_timestamp(
                    message.reported_at
                )

                if key not in latest_per_activation_ruleset:
                    latest_per_activation_ruleset[key] = (
                        message,
                        message_timestamp,
                    )
                else:
                    existing_msg, existing_timestamp = latest_per_activation_ruleset[
                        key
                    ]
                    if message_timestamp >= existing_timestamp:
                        # Found a newer or equal timestamp message, replace the old one
                        # When timestamps are equal, keep the last message in the queue
                        latest_per_activation_ruleset[key] = (
                            message,
                            message_timestamp,
                        )

            discarded = message_count - len(latest_per_activation_ruleset)
            if discarded > 0:
                logger.info(
                    f"Deduplicated {message_count} session stats: "
                    f"processing {len(latest_per_activation_ruleset)}, discarded {discarded} stale messages"
                )

            # Process each deduplicated message (one per ruleset per activation)
            for (activation_id, ruleset_name), (message, _) in latest_per_activation_ruleset.items():
                try:
                    logger.debug(
                        f"Processing session stats for activation {activation_id}"
                    )
                    await _process_session_stats(message)
                    logger.debug(
                        f"Successfully processed session stats for activation {activation_id}"
                    )
                except Exception as e:
                    logger.error(
                        f"Error processing session stats for activation {activation_id}: {e}",
                        exc_info=True,
                    )

            # Mark all original messages as done
            for _ in range(message_count):
                session_stats_queue.task_done()

        except asyncio.CancelledError:
            logger.info("Session stats worker cancelled")
            break
        except Exception as e:
            logger.error(
                f"Unexpected error in session stats worker: {e}", exc_info=True
            )
            # Mark messages as done to prevent queue from blocking
            for _ in range(message_count):
                session_stats_queue.task_done()
            await asyncio.sleep(0.1)


@database_sync_to_async
def _process_action(message: ActionMessage) -> None:
    """
    Process a single ActionMessage and write audit data to the database.
    """

    logger.info(f"Processing action message {message.action_uuid}")

    with transaction.atomic():
        try:
            # Get activation instance
            activation_instance = (
                models.RulebookProcess.objects.select_related(
                    "organization"
                ).get(id=message.activation_id)
            )
        except ObjectDoesNotExist:
            logger.error(f"RulebookProcess {message.activation_id} not found")
            return

        # Get job instance if present
        job_instance_id = None
        if message.job_id:
            try:
                job_instance = models.JobInstance.objects.get(
                    uuid=message.job_id
                )
                job_instance_id = job_instance.id
            except ObjectDoesNotExist:
                logger.debug(f"JobInstance {message.job_id} not found")

        # Handle audit rule - get or create
        audit_rule, created = models.AuditRule.objects.get_or_create(
            rule_uuid=message.rule_uuid,
            fired_at=message.rule_run_at,
            defaults={
                "activation_instance_id": message.activation_id,
                "name": message.rule,
                "ruleset_uuid": message.ruleset_uuid,
                "ruleset_name": message.ruleset,
                "job_instance_id": job_instance_id,
                "status": message.status,
                "organization": activation_instance.organization,
            },
        )

        if not created:
            # Update existing rule status if needed
            if (
                audit_rule.status != message.status
                and audit_rule.status != "failed"
            ):
                audit_rule.status = message.status
                audit_rule.save(update_fields=["status"])
                logger.debug(
                    f"Updated audit rule {audit_rule.id} status to {message.status}"
                )

        # Handle audit action - get or create
        audit_action = None
        try:
            # Try to get existing action
            audit_action = models.AuditAction.objects.get(
                id=message.action_uuid
            )
            logger.debug(f"Found existing audit action {message.action_uuid}")
        except ObjectDoesNotExist:
            # Create new action if it doesn't exist
            # Get AAP credentials for URL construction
            inputs = {}
            aap_credential_type = models.CredentialType.objects.filter(
                name=DefaultCredentialType.AAP
            ).first()
            if aap_credential_type:
                credentials = (
                    activation_instance.get_parent()
                    .eda_credentials.filter(
                        credential_type_id=aap_credential_type.id
                    )
                    .first()
                )
                if credentials:
                    inputs = get_resolved_secrets(credentials)

            url = _get_action_url(message, inputs)

            # Create audit action
            audit_action = models.AuditAction.objects.create(
                id=message.action_uuid,
                fired_at=message.run_at,
                name=message.action,
                url=url,
                status=message.status,
                rule_fired_at=message.rule_run_at,
                audit_rule=audit_rule,
                status_message=message.message,
            )
            logger.debug(f"Created audit action {message.action_uuid}")

        # Handle audit events
        for event_meta in message.matching_events.values():
            meta = event_meta.get("meta")
            if meta:
                event_uuid = meta.get("uuid")
                if event_uuid:
                    # Check if event already exists
                    event_exists = models.AuditEvent.objects.filter(
                        id=event_uuid
                    ).exists()

                    if not event_exists:
                        # Extract the payload from event_meta
                        # The payload is all fields except 'meta'
                        payload = {k: v for k, v in event_meta.items() if k != 'meta'}

                        # Create audit event
                        audit_event = models.AuditEvent.objects.create(
                            id=event_uuid,
                            source_name=meta.get("source", {}).get("name"),
                            source_type=meta.get("source", {}).get("type"),
                            payload=payload,
                            received_at=meta.get("received_at"),
                            rule_fired_at=message.rule_run_at,
                        )
                        logger.debug(f"Created audit event {event_uuid}")
                    else:
                        # Get existing event
                        audit_event = models.AuditEvent.objects.get(
                            id=event_uuid
                        )

                    # Create event-action relationship if it doesn't exist
                    if audit_action:
                        audit_event.audit_actions.add(audit_action)
                        logger.debug(
                            f"Added relationship between event {event_uuid} and action {message.action_uuid}"
                        )
                    else:
                        logger.warning(
                            f"AuditAction {message.action_uuid} not available, skipping relationship"
                        )

    logger.info(f"Successfully processed action message {message.action_uuid}")


@database_sync_to_async
def _process_session_stats(message: HeartbeatMessage) -> None:
    """
    Process a single HeartbeatMessage (session stats) and write to the heartbeat table.

    Uses SELECT FOR UPDATE to prevent race conditions when multiple Daphne workers
    process messages for the same activation concurrently. Only updates if the
    incoming message is newer than existing data to prevent out-of-order messages
    from overwriting fresh data.
    """

    activation_id = message.activation_id
    ruleset_name = message.stats.get("ruleSetName")

    if not ruleset_name:
        logger.warning(
            f"Session stats message for activation {activation_id} missing ruleSetName. Skipping."
        )
        return

    logger.info(
        f"Processing session stats message for activation {activation_id}, ruleset {ruleset_name}"
    )

    start_time = time.time()

    # Verify the RulebookProcess exists before updating heartbeat
    # This prevents creating orphaned heartbeat records
    try:
        models.RulebookProcess.objects.get(id=activation_id)
    except ObjectDoesNotExist:
        logger.warning(
            f"RulebookProcess {activation_id} not found. Skipping stats update."
        )
        return

    # Add reported_at to the stats for per-ruleset freshness tracking
    stats_with_timestamp = {
        **message.stats,
        "reported_at": message.reported_at
    }

    # Use transaction with SELECT FOR UPDATE to prevent race conditions
    # across multiple Daphne workers processing messages concurrently
    with transaction.atomic():
        try:
            # Lock the row to prevent concurrent updates from other workers
            heartbeat = (
                models.RulebookProcessHeartbeat.objects.select_for_update().get(
                    process_id=activation_id
                )
            )
            created = False
        except ObjectDoesNotExist:
            # Create initial heartbeat record if it doesn't exist
            heartbeat = models.RulebookProcessHeartbeat.objects.create(
                process_id=activation_id,
                stats={ruleset_name: stats_with_timestamp}
            )
            created = True

        if not created:
            # Get existing stats for this ruleset
            existing_ruleset_stats = heartbeat.stats.get(ruleset_name, {})
            existing_reported_at = existing_ruleset_stats.get("reported_at")

            # Only update if new message is newer (or no existing data)
            # This prevents out-of-order messages from overwriting fresh data
            if not existing_reported_at or message.reported_at >= existing_reported_at:
                heartbeat.stats = {
                    **heartbeat.stats,
                    ruleset_name: stats_with_timestamp
                }
                # Save will auto-update updated_at via auto_now
                heartbeat.save()

                total_time = time.time() - start_time

                if total_time > 0.1:
                    logger.warning(
                        f"Session stats update for activation {activation_id}, ruleset {ruleset_name} "
                        f"took {total_time:.3f}s (expected <0.1s)"
                    )
                else:
                    logger.debug(
                        f"Updated heartbeat for activation {activation_id}, ruleset {ruleset_name} "
                        f"in {total_time:.3f}s"
                    )
            else:
                logger.debug(
                    f"Skipped stale stats for activation {activation_id}, ruleset {ruleset_name}: "
                    f"existing={existing_reported_at}, incoming={message.reported_at}"
                )

    if created:
        total_time = time.time() - start_time
        logger.info(
            f"Created new heartbeat record for activation {activation_id}, ruleset {ruleset_name} "
            f"in {total_time:.3f}s"
        )

    logger.info(
        f"Successfully processed session stats message for activation {activation_id}, ruleset {ruleset_name}"
    )


def _get_action_url(message: ActionMessage, inputs: dict) -> str:
    """Helper function to construct the action URL."""
    if message.action not in ("run_job_template", "run_workflow_template"):
        return ""
    url = message.url

    if not message.controller_job_id:
        return url

    if not inputs:
        return url

    api_url = inputs["host"]
    urlparts = urlparse(api_url)

    path = urlparts.path.rstrip("/")
    if path == "":
        path = "/"
    if path in settings.API_PATH_TO_UI_PATH_MAP:
        path = settings.API_PATH_TO_UI_PATH_MAP[path]

    if message.action == "run_job_template":
        slug = f"{path}/jobs/playbook/{message.controller_job_id}/details/"
    else:
        slug = f"{path}/jobs/workflow/{message.controller_job_id}/details/"

    result = urlunparse(
        [
            urlparts.scheme,
            urlparts.netloc,
            slug,
            urlparts.params,
            urlparts.query,
            urlparts.fragment,
        ]
    )
    logger.info("Updated Job URL %s", result)
    return result


async def start_workers():
    """
    Start the DB workers.

    This function is idempotent and can be called multiple times safely.
    It will only start the workers once. Should be called when the application
    starts (e.g., on first WebSocket connection).
    """
    global _workers_started, _worker_tasks

    async with _workers_lock:
        if _workers_started:
            logger.debug("DB workers already started, skipping")
            return

        logger.info("Starting DB workers...")

        # Get number of action workers from settings
        num_action_workers = getattr(
            settings, "WEBSOCKET_ACTION_MESSAGE_WORKERS", 3
        )
        logger.info(f"Starting {num_action_workers} action worker(s)")

        # Create and start the action worker tasks
        action_tasks = [
            asyncio.create_task(action_worker(worker_id=i))
            for i in range(num_action_workers)
        ]

        # Create and start the session stats worker task
        session_stats_task = asyncio.create_task(session_stats_worker())

        _worker_tasks = action_tasks + [session_stats_task]
        _workers_started = True

        logger.info(
            f"DB workers started successfully: {num_action_workers} action workers, 1 session stats worker"
        )


async def enqueue_action(message: ActionMessage):
    """
    Enqueue an ActionMessage for processing by the action worker.

    Note: Workers must be started before calling this function.
    Call start_workers() during application initialization.
    """
    await action_queue.put(message)
    logger.debug(
        f"Action message enqueued. Queue size: {action_queue.qsize()}"
    )


async def enqueue_session_stats(message: HeartbeatMessage):
    """
    Enqueue a HeartbeatMessage (session stats) for processing by the session stats worker.

    Note: Workers must be started before calling this function.
    Call start_workers() during application initialization.
    """
    await session_stats_queue.put(message)
    logger.debug(
        f"Session stats message enqueued. Queue size: {session_stats_queue.qsize()}"
    )


async def get_queue_stats():
    """Get statistics about the queues for monitoring/debugging."""
    return {
        "action_queue_size": action_queue.qsize(),
        "session_stats_queue_size": session_stats_queue.qsize(),
        "workers_started": _workers_started,
    }
