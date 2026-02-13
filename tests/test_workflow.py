"""Tests for Workflow Orchestration."""

import pytest

from tollgate.workflow import (
    ApproverSpec,
    ConditionStepHandler,
    EscalationPath,
    InMemoryWorkflowStore,
    SQLiteWorkflowStore,
    StepStatus,
    StepType,
    WorkflowBuilder,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowInstance,
    WorkflowStatus,
    WorkflowStep,
    create_conditional_approval_workflow,
    create_simple_approval_workflow,
    create_two_level_approval_workflow,
)


class TestApproverSpec:
    """Tests for ApproverSpec."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        spec = ApproverSpec(
            approver_id="user-1",
            approver_type="user",
            required=True,
            timeout_seconds=3600.0,
        )

        d = spec.to_dict()

        assert d["approver_id"] == "user-1"
        assert d["approver_type"] == "user"
        assert d["required"] is True
        assert d["timeout_seconds"] == 3600.0

    def test_from_dict(self):
        """Test creating from dictionary."""
        d = {
            "approver_id": "group-1",
            "approver_type": "group",
            "required": False,
            "timeout_seconds": 1800.0,
        }

        spec = ApproverSpec.from_dict(d)

        assert spec.approver_id == "group-1"
        assert spec.approver_type == "group"
        assert spec.required is False
        assert spec.timeout_seconds == 1800.0


class TestEscalationPath:
    """Tests for EscalationPath."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        path = EscalationPath(
            approvers=(
                ApproverSpec("user-1"),
                ApproverSpec("user-2"),
            ),
            timeout_seconds=7200.0,
            max_levels=5,
        )

        d = path.to_dict()

        assert len(d["approvers"]) == 2
        assert d["timeout_seconds"] == 7200.0
        assert d["max_levels"] == 5

    def test_from_dict(self):
        """Test creating from dictionary."""
        d = {
            "approvers": [
                {"approver_id": "user-1"},
                {"approver_id": "user-2"},
            ],
            "timeout_seconds": 3600.0,
            "max_levels": 3,
        }

        path = EscalationPath.from_dict(d)

        assert len(path.approvers) == 2
        assert path.timeout_seconds == 3600.0


class TestWorkflowStep:
    """Tests for WorkflowStep."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        step = WorkflowStep(
            id="step-1",
            step_type=StepType.APPROVAL,
            name="First Approval",
            config={"approvers": [{"approver_id": "user-1"}]},
            next_step="step-2",
            timeout_seconds=3600.0,
        )

        d = step.to_dict()

        assert d["id"] == "step-1"
        assert d["step_type"] == "approval"
        assert d["name"] == "First Approval"
        assert d["next_step"] == "step-2"

    def test_from_dict(self):
        """Test creating from dictionary."""
        d = {
            "id": "step-1",
            "step_type": "condition",
            "name": "Check Risk",
            "config": {"field": "risk_level", "operator": "gt", "value": 5},
        }

        step = WorkflowStep.from_dict(d)

        assert step.id == "step-1"
        assert step.step_type == StepType.CONDITION
        assert step.name == "Check Risk"


class TestWorkflowDefinition:
    """Tests for WorkflowDefinition."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        definition = WorkflowDefinition(
            id="wf-1",
            name="Test Workflow",
            description="A test workflow",
            steps=(
                WorkflowStep(
                    id="step-1",
                    step_type=StepType.APPROVAL,
                    name="Approval",
                    config={},
                ),
            ),
            entry_step="step-1",
            version="1.0",
        )

        d = definition.to_dict()

        assert d["id"] == "wf-1"
        assert d["name"] == "Test Workflow"
        assert len(d["steps"]) == 1

    def test_from_dict(self):
        """Test creating from dictionary."""
        d = {
            "id": "wf-1",
            "name": "Test Workflow",
            "description": "A test",
            "steps": [
                {"id": "step-1", "step_type": "approval", "name": "Approve"},
            ],
            "entry_step": "step-1",
        }

        definition = WorkflowDefinition.from_dict(d)

        assert definition.id == "wf-1"
        assert len(definition.steps) == 1

    def test_get_step(self):
        """Test getting a step by ID."""
        definition = WorkflowDefinition(
            id="wf-1",
            name="Test",
            description="",
            steps=(
                WorkflowStep("step-1", StepType.APPROVAL, "Step 1", {}),
                WorkflowStep("step-2", StepType.ACTION, "Step 2", {}),
            ),
            entry_step="step-1",
        )

        step = definition.get_step("step-2")
        assert step is not None
        assert step.name == "Step 2"

        missing = definition.get_step("step-3")
        assert missing is None


class TestWorkflowInstance:
    """Tests for WorkflowInstance."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        instance = WorkflowInstance(
            id="inst-1",
            workflow_id="wf-1",
            status=WorkflowStatus.RUNNING,
            context={"key": "value"},
            current_step="step-1",
        )

        d = instance.to_dict()

        assert d["id"] == "inst-1"
        assert d["workflow_id"] == "wf-1"
        assert d["status"] == "running"
        assert d["context"]["key"] == "value"

    def test_from_dict(self):
        """Test creating from dictionary."""
        d = {
            "id": "inst-1",
            "workflow_id": "wf-1",
            "status": "awaiting_approval",
            "context": {},
            "current_step": "step-1",
            "step_executions": {},
        }

        instance = WorkflowInstance.from_dict(d)

        assert instance.id == "inst-1"
        assert instance.status == WorkflowStatus.AWAITING_APPROVAL


class TestInMemoryWorkflowStore:
    """Tests for InMemoryWorkflowStore."""

    @pytest.fixture
    def store(self):
        """Create an in-memory store."""
        return InMemoryWorkflowStore()

    @pytest.mark.asyncio
    async def test_save_and_get_definition(self, store):
        """Test saving and getting a workflow definition."""
        definition = WorkflowDefinition(
            id="wf-1",
            name="Test",
            description="",
            steps=(WorkflowStep("s1", StepType.APPROVAL, "Step", {}),),
            entry_step="s1",
        )

        await store.save_definition(definition)
        result = await store.get_definition("wf-1")

        assert result is not None
        assert result.name == "Test"

    @pytest.mark.asyncio
    async def test_list_definitions(self, store):
        """Test listing workflow definitions."""
        for i in range(3):
            definition = WorkflowDefinition(
                id=f"wf-{i}",
                name=f"Workflow {i}",
                description="",
                steps=(WorkflowStep("s1", StepType.APPROVAL, "Step", {}),),
                entry_step="s1",
            )
            await store.save_definition(definition)

        definitions = await store.list_definitions()
        assert len(definitions) == 3

    @pytest.mark.asyncio
    async def test_save_and_get_instance(self, store):
        """Test saving and getting a workflow instance."""
        instance = WorkflowInstance(
            id="inst-1",
            workflow_id="wf-1",
            status=WorkflowStatus.RUNNING,
            context={"test": True},
        )

        await store.save_instance(instance)
        result = await store.get_instance("inst-1")

        assert result is not None
        assert result.context["test"] is True

    @pytest.mark.asyncio
    async def test_list_instances_by_status(self, store):
        """Test listing instances by status."""
        for i, status in enumerate([
            WorkflowStatus.RUNNING,
            WorkflowStatus.AWAITING_APPROVAL,
            WorkflowStatus.COMPLETED,
        ]):
            instance = WorkflowInstance(
                id=f"inst-{i}",
                workflow_id="wf-1",
                status=status,
                context={},
            )
            await store.save_instance(instance)

        running = await store.list_instances(status=WorkflowStatus.RUNNING)
        assert len(running) == 1

        awaiting = await store.list_instances(status=WorkflowStatus.AWAITING_APPROVAL)
        assert len(awaiting) == 1


class TestSQLiteWorkflowStore:
    """Tests for SQLiteWorkflowStore."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a SQLite store."""
        return SQLiteWorkflowStore(str(tmp_path / "workflows.db"))

    @pytest.mark.asyncio
    async def test_save_and_get_definition(self, store):
        """Test saving and getting a workflow definition."""
        definition = WorkflowDefinition(
            id="wf-1",
            name="Test",
            description="Test workflow",
            steps=(WorkflowStep("s1", StepType.APPROVAL, "Step", {}),),
            entry_step="s1",
        )

        await store.save_definition(definition)
        result = await store.get_definition("wf-1")

        assert result is not None
        assert result.name == "Test"

    @pytest.mark.asyncio
    async def test_save_and_get_instance(self, store):
        """Test saving and getting a workflow instance."""
        instance = WorkflowInstance(
            id="inst-1",
            workflow_id="wf-1",
            status=WorkflowStatus.RUNNING,
            context={"key": "value"},
        )

        await store.save_instance(instance)
        result = await store.get_instance("inst-1")

        assert result is not None
        assert result.context["key"] == "value"


class TestWorkflowBuilder:
    """Tests for WorkflowBuilder."""

    def test_simple_workflow(self):
        """Test building a simple workflow."""
        workflow = (
            WorkflowBuilder("wf-1", "Simple")
            .with_description("A simple workflow")
            .add_approval_step(
                "approve",
                "Approval Required",
                [ApproverSpec("user-1")],
            )
            .build()
        )

        assert workflow.id == "wf-1"
        assert workflow.name == "Simple"
        assert len(workflow.steps) == 1
        assert workflow.entry_step == "approve"

    def test_chained_workflow(self):
        """Test building a chained workflow."""
        workflow = (
            WorkflowBuilder("wf-2", "Chained")
            .add_approval_step(
                "step1",
                "First Approval",
                [ApproverSpec("user-1")],
                next_step="step2",
            )
            .add_approval_step(
                "step2",
                "Second Approval",
                [ApproverSpec("user-2")],
            )
            .build()
        )

        assert len(workflow.steps) == 2
        step1 = workflow.get_step("step1")
        assert step1 is not None
        assert step1.next_step == "step2"

    def test_conditional_workflow(self):
        """Test building a conditional workflow."""
        workflow = (
            WorkflowBuilder("wf-3", "Conditional")
            .add_condition_step(
                "check",
                "Check Value",
                field="amount",
                operator="gt",
                value=1000,
                on_true="high_approval",
                on_false="low_approval",
            )
            .add_approval_step(
                "high_approval",
                "High Value Approval",
                [ApproverSpec("manager")],
            )
            .add_approval_step(
                "low_approval",
                "Low Value Approval",
                [ApproverSpec("supervisor")],
            )
            .set_entry_step("check")
            .build()
        )

        assert workflow.entry_step == "check"
        check_step = workflow.get_step("check")
        assert check_step is not None
        assert check_step.config["on_true"] == "high_approval"

    def test_with_escalation(self):
        """Test building workflow with escalation."""
        workflow = (
            WorkflowBuilder("wf-4", "Escalation")
            .add_approval_step("approve", "Approval", [ApproverSpec("user-1")])
            .with_escalation(
                [ApproverSpec("manager"), ApproverSpec("director")],
                timeout_seconds=7200.0,
                max_levels=2,
            )
            .build()
        )

        assert workflow.escalation_path is not None
        assert len(workflow.escalation_path.approvers) == 2
        assert workflow.escalation_path.max_levels == 2


class TestConditionStepHandler:
    """Tests for ConditionStepHandler."""

    @pytest.fixture
    def handler(self):
        """Create a condition handler."""
        return ConditionStepHandler()

    @pytest.mark.asyncio
    async def test_eq_condition(self, handler):
        """Test equals condition."""
        step = WorkflowStep(
            id="check",
            step_type=StepType.CONDITION,
            name="Check",
            config={
                "field": "status",
                "operator": "eq",
                "value": "active",
                "on_true": "active_path",
                "on_false": "inactive_path",
            },
        )
        instance = WorkflowInstance(
            id="inst",
            workflow_id="wf",
            status=WorkflowStatus.RUNNING,
            context={},
        )

        status, result, error = await handler.execute(
            step, instance, {"status": "active"}
        )

        assert status == StepStatus.COMPLETED
        assert result["condition_met"] is True
        assert result["next_step"] == "active_path"

    @pytest.mark.asyncio
    async def test_gt_condition(self, handler):
        """Test greater than condition."""
        step = WorkflowStep(
            id="check",
            step_type=StepType.CONDITION,
            name="Check Amount",
            config={
                "field": "amount",
                "operator": "gt",
                "value": 1000,
                "on_true": "high",
                "on_false": "low",
            },
        )
        instance = WorkflowInstance(
            id="inst",
            workflow_id="wf",
            status=WorkflowStatus.RUNNING,
            context={},
        )

        status, result, _ = await handler.execute(step, instance, {"amount": 500})

        assert result["condition_met"] is False
        assert result["next_step"] == "low"

    @pytest.mark.asyncio
    async def test_in_condition(self, handler):
        """Test in list condition."""
        step = WorkflowStep(
            id="check",
            step_type=StepType.CONDITION,
            name="Check Role",
            config={
                "field": "role",
                "operator": "in",
                "value": ["admin", "manager"],
                "on_true": "allowed",
                "on_false": "denied",
            },
        )
        instance = WorkflowInstance(
            id="inst",
            workflow_id="wf",
            status=WorkflowStatus.RUNNING,
            context={},
        )

        status, result, _ = await handler.execute(step, instance, {"role": "admin"})

        assert result["condition_met"] is True


class TestWorkflowEngine:
    """Tests for WorkflowEngine."""

    @pytest.fixture
    def store(self):
        """Create an in-memory store."""
        return InMemoryWorkflowStore()

    @pytest.fixture
    def engine(self, store):
        """Create a workflow engine."""
        return WorkflowEngine(store)

    @pytest.mark.asyncio
    async def test_register_workflow(self, engine, store):
        """Test registering a workflow."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )

        await engine.register_workflow(workflow)

        result = await store.get_definition("wf-1")
        assert result is not None

    @pytest.mark.asyncio
    async def test_start_workflow(self, engine):
        """Test starting a workflow."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-1", {"key": "value"})

        assert instance.id is not None
        assert instance.workflow_id == "wf-1"
        assert instance.status == WorkflowStatus.PENDING
        assert instance.context["key"] == "value"

    @pytest.mark.asyncio
    async def test_start_nonexistent_workflow(self, engine):
        """Test starting a nonexistent workflow."""
        with pytest.raises(ValueError, match="not found"):
            await engine.start_workflow("nonexistent")

    @pytest.mark.asyncio
    async def test_execute_approval_step(self, engine):
        """Test executing an approval step."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-1")
        instance = await engine.execute_step(instance.id)

        assert instance.status == WorkflowStatus.AWAITING_APPROVAL

    @pytest.mark.asyncio
    async def test_submit_approval(self, engine):
        """Test submitting an approval."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-1")
        instance = await engine.execute_step(instance.id)

        # Submit approval
        instance = await engine.submit_approval(instance.id, "user-1", True)

        assert instance.status == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_submit_denial(self, engine):
        """Test submitting a denial."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-1")
        instance = await engine.execute_step(instance.id)

        # Submit denial
        instance = await engine.submit_approval(instance.id, "user-1", False)

        assert instance.status == WorkflowStatus.FAILED

    @pytest.mark.asyncio
    async def test_conditional_workflow_true_path(self, engine):
        """Test conditional workflow taking true path."""
        workflow = create_conditional_approval_workflow(
            "wf-cond",
            "Conditional",
            condition_field="risk_level",
            condition_value="high",
            high_risk_approvers=[ApproverSpec("security")],
            low_risk_approvers=[ApproverSpec("manager")],
        )
        await engine.register_workflow(workflow)

        # Start with high risk
        instance = await engine.start_workflow("wf-cond", {"risk_level": "high"})
        instance = await engine.run_to_completion(instance.id)

        assert instance.status == WorkflowStatus.AWAITING_APPROVAL
        assert instance.current_step == "high_risk_approval"

    @pytest.mark.asyncio
    async def test_conditional_workflow_false_path(self, engine):
        """Test conditional workflow taking false path."""
        workflow = create_conditional_approval_workflow(
            "wf-cond",
            "Conditional",
            condition_field="risk_level",
            condition_value="high",
            high_risk_approvers=[ApproverSpec("security")],
            low_risk_approvers=[ApproverSpec("manager")],
        )
        await engine.register_workflow(workflow)

        # Start with low risk
        instance = await engine.start_workflow("wf-cond", {"risk_level": "low"})
        instance = await engine.run_to_completion(instance.id)

        assert instance.status == WorkflowStatus.AWAITING_APPROVAL
        assert instance.current_step == "low_risk_approval"

    @pytest.mark.asyncio
    async def test_two_level_approval(self, engine):
        """Test two-level approval workflow."""
        workflow = create_two_level_approval_workflow(
            "wf-2level",
            "Two Level",
            first_level_approvers=[ApproverSpec("supervisor")],
            second_level_approvers=[ApproverSpec("manager")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-2level")
        instance = await engine.execute_step(instance.id)

        # First level
        assert instance.current_step == "level1"
        instance = await engine.submit_approval(instance.id, "supervisor", True)

        # Should move to second level
        assert instance.current_step == "level2"
        assert instance.status == WorkflowStatus.AWAITING_APPROVAL

        # Second level
        instance = await engine.submit_approval(instance.id, "manager", True)
        assert instance.status == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_cancel_workflow(self, engine):
        """Test cancelling a workflow."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-1")
        instance = await engine.cancel_workflow(instance.id)

        assert instance.status == WorkflowStatus.CANCELLED
        assert instance.completed_at is not None

    @pytest.mark.asyncio
    async def test_escalate_workflow(self, engine):
        """Test escalating a workflow."""
        workflow = (
            WorkflowBuilder("wf-esc", "Escalation Test")
            .add_approval_step("approve", "Approval", [ApproverSpec("user-1")])
            .with_escalation(
                [ApproverSpec("manager")],
                timeout_seconds=3600.0,
                max_levels=2,
            )
            .build()
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-esc")
        instance = await engine.execute_step(instance.id)

        # Escalate
        instance = await engine.escalate(instance.id)

        assert instance.status == WorkflowStatus.ESCALATED
        assert instance.escalation_level == 1

    @pytest.mark.asyncio
    async def test_get_pending_approvals(self, engine, store):
        """Test getting pending approvals."""
        workflow = create_simple_approval_workflow(
            "wf-1",
            "Simple",
            [ApproverSpec("user-1")],
        )
        await engine.register_workflow(workflow)

        instance = await engine.start_workflow("wf-1")
        await engine.execute_step(instance.id)

        # Get pending approvals
        pending = await engine.get_pending_approvals("user-1")

        assert len(pending) == 1
        assert pending[0][0].id == instance.id


class TestWorkflowTemplates:
    """Tests for workflow templates."""

    def test_simple_approval_workflow(self):
        """Test simple approval workflow template."""
        workflow = create_simple_approval_workflow(
            "wf-simple",
            "Simple Approval",
            [ApproverSpec("user-1"), ApproverSpec("user-2")],
        )

        assert workflow.id == "wf-simple"
        assert len(workflow.steps) == 1
        assert workflow.steps[0].step_type == StepType.APPROVAL

    def test_two_level_approval_workflow(self):
        """Test two-level approval workflow template."""
        workflow = create_two_level_approval_workflow(
            "wf-2level",
            "Two Level",
            [ApproverSpec("supervisor")],
            [ApproverSpec("manager")],
        )

        assert len(workflow.steps) == 2
        level1 = workflow.get_step("level1")
        assert level1 is not None
        assert level1.next_step == "level2"

    def test_conditional_approval_workflow(self):
        """Test conditional approval workflow template."""
        workflow = create_conditional_approval_workflow(
            "wf-cond",
            "Conditional",
            "risk_level",
            "high",
            [ApproverSpec("security")],
            [ApproverSpec("manager")],
        )

        assert workflow.entry_step == "check_risk"
        check = workflow.get_step("check_risk")
        assert check is not None
        assert check.step_type == StepType.CONDITION
