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
"""Tests for DB workers module."""

import asyncio
import uuid
from datetime import datetime

import pytest
import pytest_asyncio
from channels.db import database_sync_to_async
from django.utils import timezone

from aap_eda.core import models
from aap_eda.core.enums import ActivationStatus
from aap_eda.wsapi import db_workers
from aap_eda.wsapi.messages import ActionMessage, HeartbeatMessage


@pytest_asyncio.fixture
async def reset_workers():
    """Reset worker state before each test."""
    # Reset module-level state
    db_workers._workers_started = False
    db_workers._worker_tasks = []

    # Recreate queues with the current event loop
    # This is necessary because each test runs in its own event loop
    db_workers.action_queue = asyncio.Queue(maxsize=0)
    db_workers.session_stats_queue = asyncio.Queue(maxsize=0)

    yield

    # Cancel any running workers
    for task in db_workers._worker_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    db_workers._workers_started = False
    db_workers._worker_tasks = []


@pytest.fixture
def basic_activation_with_instance(
    default_organization: models.Organization,
    basic_activation: models.Activation,
) -> models.Activation:
    """Create activation with instance for testing."""
    models.RulebookProcess.objects.create(
        activation=basic_activation,
        organization=default_organization,
        status=ActivationStatus.RUNNING,
    )
    basic_activation.refresh_from_db()
    return basic_activation


@pytest.fixture
def sample_action_message(basic_activation_with_instance):
    """Create a sample ActionMessage."""
    action_uuid = str(uuid.uuid4())
    rule_uuid = str(uuid.uuid4())
    ruleset_uuid = str(uuid.uuid4())

    return ActionMessage(
        type="Action",
        action="run_job_template",
        action_uuid=action_uuid,
        activation_id=basic_activation_with_instance.latest_instance.id,
        run_at=timezone.now().isoformat(),
        ruleset="test-ruleset",
        ruleset_uuid=ruleset_uuid,
        rule="test-rule",
        rule_uuid=rule_uuid,
        matching_events={},
        status="successful",
        rule_run_at=timezone.now().isoformat(),
    )


@pytest.fixture
def sample_heartbeat_message(basic_activation_with_instance):
    """Create a sample HeartbeatMessage."""
    return HeartbeatMessage(
        type="SessionStats",
        activation_id=basic_activation_with_instance.latest_instance.id,
        stats={
            "ruleSetName": "test-ruleset",
            "numberOfRules": 5,
            "numberOfDisabledRules": 0,
            "rulesTriggered": 10,
            "eventsProcessed": 100,
            "eventsMatched": 10,
            "lastClockTime": timezone.now().isoformat(),
            "lastRuleFiredAt": timezone.now().isoformat(),
            "lastEventReceivedAt": timezone.now().isoformat(),
        },
        reported_at=timezone.now().isoformat(),
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestWorkerLifecycle:
    """Test worker startup and lifecycle."""

    async def test_start_workers_once(self, reset_workers, settings):
        """Test that workers start only once."""
        settings.WEBSOCKET_ACTION_MESSAGE_WORKERS = 2

        await db_workers.start_workers()

        assert db_workers._workers_started is True
        # 2 action workers + 1 session stats worker
        assert len(db_workers._worker_tasks) == 3

        # Try to start again - should not duplicate
        await db_workers.start_workers()
        assert len(db_workers._worker_tasks) == 3

    async def test_start_workers_custom_count(self, reset_workers, settings):
        """Test starting workers with custom action worker count."""
        settings.WEBSOCKET_ACTION_MESSAGE_WORKERS = 5

        await db_workers.start_workers()

        # 5 action workers + 1 session stats worker
        assert len(db_workers._worker_tasks) == 6

    async def test_get_queue_stats(self, reset_workers):
        """Test getting queue statistics."""
        stats = await db_workers.get_queue_stats()

        assert stats["action_queue_size"] == 0
        assert stats["session_stats_queue_size"] == 0
        assert stats["workers_started"] is False

        await db_workers.start_workers()

        stats = await db_workers.get_queue_stats()
        assert stats["workers_started"] is True


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestActionWorker:
    """Test action worker processing."""

    async def test_enqueue_and_process_action(
        self,
        reset_workers,
        sample_action_message,
        basic_activation_with_instance,
    ):
        """Test enqueueing and processing an action message."""
        await db_workers.start_workers()

        # Enqueue the message
        await db_workers.enqueue_action(sample_action_message)

        # Give worker time to process
        await asyncio.sleep(0.2)

        # Verify audit objects were created
        audit_rule = await database_sync_to_async(
            models.AuditRule.objects.filter(
                rule_uuid=sample_action_message.rule_uuid
            ).first
        )()

        assert audit_rule is not None
        assert audit_rule.name == "test-rule"
        assert audit_rule.status == "successful"

        audit_action = await database_sync_to_async(
            models.AuditAction.objects.filter(
                id=sample_action_message.action_uuid
            ).first
        )()

        assert audit_action is not None
        assert audit_action.name == "run_job_template"
        assert audit_action.status == "successful"

    async def test_action_worker_with_events(
        self,
        reset_workers,
        sample_action_message,
        basic_activation_with_instance,
    ):
        """Test action worker processing with matching events."""
        event_uuid = str(uuid.uuid4())

        # Add matching events to the message
        # The structure has event data at the same level as 'meta'
        # Payload should be extracted as everything except 'meta'
        sample_action_message.matching_events = {
            "m": {
                "key": "value",
                "extra_field": "extra_value",
                "meta": {
                    "uuid": event_uuid,
                    "source": {
                        "name": "test-source",
                        "type": "range",
                    },
                    "received_at": timezone.now().isoformat(),
                },
            }
        }

        await db_workers.start_workers()
        await db_workers.enqueue_action(sample_action_message)

        # Give worker time to process
        await asyncio.sleep(0.2)

        # Verify audit event was created
        audit_event = await database_sync_to_async(
            models.AuditEvent.objects.filter(id=event_uuid).first
        )()

        assert audit_event is not None
        assert audit_event.source_name == "test-source"
        assert audit_event.source_type == "range"
        # Payload should be all fields except 'meta'
        assert audit_event.payload == {"key": "value", "extra_field": "extra_value"}

    async def test_action_worker_missing_activation(
        self, reset_workers, sample_action_message
    ):
        """Test action worker handles missing activation gracefully."""
        # Use non-existent activation ID
        sample_action_message.activation_id = 99999

        await db_workers.start_workers()
        await db_workers.enqueue_action(sample_action_message)

        # Give worker time to process
        await asyncio.sleep(0.2)

        # Should not crash - verify no audit objects created
        audit_rule = await database_sync_to_async(
            models.AuditRule.objects.filter(
                rule_uuid=sample_action_message.rule_uuid
            ).first
        )()

        assert audit_rule is None

    async def test_multiple_action_workers(
        self, reset_workers, basic_activation_with_instance, settings
    ):
        """Test that multiple action workers process messages concurrently."""
        settings.WEBSOCKET_ACTION_MESSAGE_WORKERS = 3

        await db_workers.start_workers()

        # Get the activation instance id (requires DB access)
        @database_sync_to_async
        def get_instance_id():
            return basic_activation_with_instance.latest_instance.id

        activation_instance_id = await get_instance_id()

        # Enqueue multiple messages
        messages = []
        for i in range(10):
            msg = ActionMessage(
                type="Action",
                action="run_job_template",
                action_uuid=str(uuid.uuid4()),
                activation_id=activation_instance_id,
                run_at=timezone.now().isoformat(),
                ruleset="test-ruleset",
                ruleset_uuid=str(uuid.uuid4()),
                rule=f"test-rule-{i}",
                rule_uuid=str(uuid.uuid4()),
                matching_events={},
                status="successful",
                rule_run_at=timezone.now().isoformat(),
            )
            messages.append(msg)
            await db_workers.enqueue_action(msg)

        # Give workers time to process
        await asyncio.sleep(0.5)

        # Verify all rules were created
        count = await database_sync_to_async(models.AuditRule.objects.count)()
        assert count == 10


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestSessionStatsWorker:
    """Test session stats worker processing."""

    async def test_enqueue_and_process_session_stats(
        self,
        reset_workers,
        sample_heartbeat_message,
        basic_activation_with_instance,
    ):
        """Test enqueueing and processing session stats."""
        await db_workers.start_workers()

        # Enqueue the message
        await db_workers.enqueue_session_stats(sample_heartbeat_message)

        # Give worker time to process
        await asyncio.sleep(0.2)

        # Verify heartbeat was updated
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.filter(
                process_id=basic_activation_with_instance.latest_instance.id
            ).first
        )()

        assert heartbeat is not None
        assert "test-ruleset" in heartbeat.stats
        assert heartbeat.stats["test-ruleset"]["numberOfRules"] == 5
        assert heartbeat.stats["test-ruleset"]["rulesTriggered"] == 10
        # Verify reported_at is stored with the stats
        assert "reported_at" in heartbeat.stats["test-ruleset"]
        assert heartbeat.stats["test-ruleset"]["reported_at"] == sample_heartbeat_message.reported_at

    async def test_session_stats_deduplication(
        self,
        reset_workers,
        sample_heartbeat_message,
        basic_activation_with_instance,
    ):
        """Test that session stats worker deduplicates messages for the same ruleset."""
        await db_workers.start_workers()

        # Enqueue multiple messages for the same activation and ruleset
        base_time = timezone.now()

        # Older message
        activation_id = (
            basic_activation_with_instance.latest_instance.id
        )
        msg1 = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                "ruleSetName": "test-ruleset",
                "rulesTriggered": 5,
            },
            reported_at=(base_time).isoformat(),
        )

        # Newer message for the SAME ruleset
        msg2 = HeartbeatMessage(
            type="SessionStats",
            activation_id=basic_activation_with_instance.latest_instance.id,
            stats={
                "ruleSetName": "test-ruleset",  # Same ruleset
                "rulesTriggered": 10,
            },
            reported_at=(
                base_time
            ).isoformat(),  # Same time - will be deduplicated
        )

        await db_workers.enqueue_session_stats(msg1)
        await db_workers.enqueue_session_stats(msg2)

        # Give worker time to process (including dedup timeout)
        await asyncio.sleep(0.3)

        # Verify only the latest stats were saved
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=basic_activation_with_instance.latest_instance.id)

        # Should have the latest value (msg2) for the single ruleset
        assert heartbeat.stats["test-ruleset"]["rulesTriggered"] == 10
        # Should only have one ruleset in stats
        assert len(heartbeat.stats) == 1

    async def test_session_stats_multiple_rulesets_preserved(
        self,
        reset_workers,
        basic_activation_with_instance,
    ):
        """Test that multiple rulesets are preserved during deduplication.

        This verifies the fix for the bug where deduplication was using only
        activation_id as the key, causing messages for different rulesets
        to overwrite each other.
        """
        await db_workers.start_workers()

        # Get activation instance ID (requires DB access in async context)
        @database_sync_to_async
        def get_instance_id():
            return basic_activation_with_instance.latest_instance.id

        activation_id = await get_instance_id()
        base_time = timezone.now()

        # Three messages for different rulesets arriving quickly
        msg1 = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                "ruleSetName": "ruleset-A",
                "rulesTriggered": 100,
            },
            reported_at=base_time.isoformat(),
        )

        msg2 = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                "ruleSetName": "ruleset-B",
                "rulesTriggered": 200,
            },
            reported_at=base_time.isoformat(),
        )

        msg3 = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                "ruleSetName": "ruleset-C",
                "rulesTriggered": 300,
            },
            reported_at=base_time.isoformat(),
        )

        # Enqueue all three messages
        await db_workers.enqueue_session_stats(msg1)
        await db_workers.enqueue_session_stats(msg2)
        await db_workers.enqueue_session_stats(msg3)

        # Give worker time to process (including dedup timeout)
        await asyncio.sleep(0.3)

        # Verify ALL three rulesets are present
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=activation_id)

        # All three rulesets should be preserved
        assert len(heartbeat.stats) == 3
        assert "ruleset-A" in heartbeat.stats
        assert "ruleset-B" in heartbeat.stats
        assert "ruleset-C" in heartbeat.stats

        # Verify correct values
        assert heartbeat.stats["ruleset-A"]["rulesTriggered"] == 100
        assert heartbeat.stats["ruleset-B"]["rulesTriggered"] == 200
        assert heartbeat.stats["ruleset-C"]["rulesTriggered"] == 300

    async def test_session_stats_stale_message_rejection(
        self,
        reset_workers,
        basic_activation_with_instance,
    ):
        """Test that stale messages (old reported_at) are rejected.

        This verifies the fix for preventing out-of-order messages from
        overwriting fresh data.
        """
        await db_workers.start_workers()

        # Get activation instance ID (requires DB access in async context)
        @database_sync_to_async
        def get_instance_id():
            return basic_activation_with_instance.latest_instance.id

        activation_id = await get_instance_id()
        from datetime import timedelta

        # Process a newer message first
        newer_time = timezone.now()
        msg_newer = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                "ruleSetName": "test-ruleset",
                "rulesTriggered": 100,
                "eventsProcessed": 500,
            },
            reported_at=newer_time.isoformat(),
        )

        await db_workers.enqueue_session_stats(msg_newer)
        await asyncio.sleep(0.2)

        # Verify newer message was saved
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=activation_id)

        assert heartbeat.stats["test-ruleset"]["rulesTriggered"] == 100
        assert heartbeat.stats["test-ruleset"]["eventsProcessed"] == 500
        assert heartbeat.stats["test-ruleset"]["reported_at"] == newer_time.isoformat()

        # Now send a stale message with older reported_at
        older_time = newer_time - timedelta(seconds=10)
        msg_stale = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                "ruleSetName": "test-ruleset",
                "rulesTriggered": 50,  # Old value
                "eventsProcessed": 200,  # Old value
            },
            reported_at=older_time.isoformat(),  # Older timestamp
        )

        await db_workers.enqueue_session_stats(msg_stale)
        await asyncio.sleep(0.2)

        # Verify stale message was REJECTED - data should be unchanged
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=activation_id)

        # Should still have the newer values, not the stale ones
        assert heartbeat.stats["test-ruleset"]["rulesTriggered"] == 100
        assert heartbeat.stats["test-ruleset"]["eventsProcessed"] == 500
        assert heartbeat.stats["test-ruleset"]["reported_at"] == newer_time.isoformat()

    async def test_session_stats_missing_ruleset_name(
        self,
        reset_workers,
        basic_activation_with_instance,
    ):
        """Test session stats worker handles missing ruleSetName gracefully."""
        await db_workers.start_workers()

        # Get activation instance ID (requires DB access in async context)
        @database_sync_to_async
        def get_instance_id():
            return basic_activation_with_instance.latest_instance.id

        activation_id = await get_instance_id()

        # Message without ruleSetName
        msg = HeartbeatMessage(
            type="SessionStats",
            activation_id=activation_id,
            stats={
                # Missing "ruleSetName"
                "rulesTriggered": 100,
            },
            reported_at=timezone.now().isoformat(),
        )

        await db_workers.enqueue_session_stats(msg)
        await asyncio.sleep(0.2)

        # Should not crash - verify no stats were saved
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=activation_id)

        # Stats should be empty (only the initial empty dict)
        assert heartbeat.stats == {}

    async def test_session_stats_missing_activation(
        self, reset_workers, sample_heartbeat_message
    ):
        """Test session stats worker handles missing activation gracefully."""
        # Use non-existent activation ID
        sample_heartbeat_message.activation_id = 99999

        await db_workers.start_workers()
        await db_workers.enqueue_session_stats(sample_heartbeat_message)

        # Give worker time to process
        await asyncio.sleep(0.2)

        # Should not crash - verify no heartbeat created
        heartbeat = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.filter(
                process_id=99999
            ).first
        )()

        assert heartbeat is None

    async def test_session_stats_multiple_activations(
        self, reset_workers, default_organization
    ):
        """Test session stats worker handles multiple activations."""

        # Create two activations
        @database_sync_to_async
        def create_activation():
            rulebook = models.Rulebook.objects.create(
                name=f"test-rulebook-{uuid.uuid4()}",
                rulesets="---",
                organization=default_organization,
            )
            decision_env = models.DecisionEnvironment.objects.create(
                name=f"test-de-{uuid.uuid4()}",
                image_url="quay.io/test:latest",
                organization=default_organization,
            )
            activation = models.Activation.objects.create(
                name=f"test-activation-{uuid.uuid4()}",
                rulebook=rulebook,
                decision_environment=decision_env,
                organization=default_organization,
            )
            models.RulebookProcess.objects.create(
                activation=activation,
                organization=default_organization,
                status=ActivationStatus.RUNNING,
            )
            activation.refresh_from_db()
            return activation

        activation1 = await create_activation()
        activation2 = await create_activation()

        await db_workers.start_workers()

        # Get activation instance IDs (requires DB access)
        @database_sync_to_async
        def get_instance_ids():
            return (
                activation1.latest_instance.id,
                activation2.latest_instance.id,
            )

        instance_id1, instance_id2 = await get_instance_ids()

        # Enqueue stats for both activations
        msg1 = HeartbeatMessage(
            type="SessionStats",
            activation_id=instance_id1,
            stats={
                "ruleSetName": "ruleset-1",
                "rulesTriggered": 100,
            },
            reported_at=timezone.now().isoformat(),
        )

        msg2 = HeartbeatMessage(
            type="SessionStats",
            activation_id=instance_id2,
            stats={
                "ruleSetName": "ruleset-2",
                "rulesTriggered": 200,
            },
            reported_at=timezone.now().isoformat(),
        )

        await db_workers.enqueue_session_stats(msg1)
        await db_workers.enqueue_session_stats(msg2)

        # Give worker time to process
        await asyncio.sleep(0.3)

        # Verify both heartbeats were updated independently
        heartbeat1 = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=instance_id1)

        heartbeat2 = await database_sync_to_async(
            models.RulebookProcessHeartbeat.objects.get
        )(process_id=instance_id2)

        assert heartbeat1.stats["ruleset-1"]["rulesTriggered"] == 100
        assert heartbeat2.stats["ruleset-2"]["rulesTriggered"] == 200


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestHelperFunctions:
    """Test helper functions."""

    def test_parse_message_timestamp_valid(self):
        """Test parsing valid timestamp."""
        timestamp = "2024-04-28T12:00:00.000Z"
        result = db_workers._parse_message_timestamp(timestamp)

        assert isinstance(result, datetime)
        assert result.tzinfo is not None  # Should be timezone-aware

    def test_parse_message_timestamp_none(self):
        """Test parsing None timestamp returns current time."""
        result = db_workers._parse_message_timestamp(None)

        assert isinstance(result, datetime)
        assert result.tzinfo is not None

    def test_parse_message_timestamp_invalid(self):
        """Test parsing invalid timestamp returns current time."""
        result = db_workers._parse_message_timestamp("invalid-timestamp")

        assert isinstance(result, datetime)
        assert result.tzinfo is not None

    def test_get_action_url_non_job_action(self):
        """Test _get_action_url for non-job actions."""
        msg = ActionMessage(
            type="Action",
            action="debug",
            action_uuid=str(uuid.uuid4()),
            activation_id=1,
            run_at=timezone.now().isoformat(),
            ruleset="test",
            ruleset_uuid=str(uuid.uuid4()),
            rule="test",
            rule_uuid=str(uuid.uuid4()),
        )

        url = db_workers._get_action_url(msg, {})
        assert url == ""

    def test_get_action_url_job_template_without_controller_id(self):
        """Test _get_action_url for job template without controller job ID."""
        msg = ActionMessage(
            type="Action",
            action="run_job_template",
            action_uuid=str(uuid.uuid4()),
            activation_id=1,
            run_at=timezone.now().isoformat(),
            ruleset="test",
            ruleset_uuid=str(uuid.uuid4()),
            rule="test",
            rule_uuid=str(uuid.uuid4()),
            url="http://example.com/api/v2/job_templates/123/",
        )

        url = db_workers._get_action_url(msg, {})
        assert url == "http://example.com/api/v2/job_templates/123/"

    def test_get_action_url_job_template_with_controller_id(self):
        """Test _get_action_url for job template with controller job ID."""
        msg = ActionMessage(
            type="Action",
            action="run_job_template",
            action_uuid=str(uuid.uuid4()),
            activation_id=1,
            run_at=timezone.now().isoformat(),
            ruleset="test",
            ruleset_uuid=str(uuid.uuid4()),
            rule="test",
            rule_uuid=str(uuid.uuid4()),
            url="http://example.com/api/v2/job_templates/123/",
            controller_job_id="456",
        )

        inputs = {"host": "https://controller.example.com"}
        url = db_workers._get_action_url(msg, inputs)

        assert "controller.example.com" in url
        assert "456" in url
        assert "/jobs/playbook/" in url

    def test_get_action_url_workflow_template(self):
        """Test _get_action_url for workflow template."""
        msg = ActionMessage(
            type="Action",
            action="run_workflow_template",
            action_uuid=str(uuid.uuid4()),
            activation_id=1,
            run_at=timezone.now().isoformat(),
            ruleset="test",
            ruleset_uuid=str(uuid.uuid4()),
            rule="test",
            rule_uuid=str(uuid.uuid4()),
            url="http://example.com/api/v2/workflow_templates/123/",
            controller_job_id="789",
        )

        inputs = {"host": "https://controller.example.com"}
        url = db_workers._get_action_url(msg, inputs)

        assert "controller.example.com" in url
        assert "789" in url
        assert "/jobs/workflow/" in url
