"""Replay of persisted Agent records from before model-policy pinning."""

import hashlib
import json
from pathlib import Path

import pytest

from agent_pipeline.contracts import AgentModelPolicy, Q1Status, Stage1AgentPolicy
from agent_pipeline.controller.service import ReplayMismatch
from agent_pipeline.controller.store import Store


def legacy_digest(snapshot):
    """Independent copy of the 565b5c4 input encoding, without new helpers."""
    task = snapshot["pending_task"]
    value = {
        "agent_task": task["agent_task"],
        "candidate": snapshot["candidate"],
        "hcap_revision": snapshot["binding"]["hcap_revision"],
        "analysis_ref": snapshot["analysis_ref"],
        "plan_ref": (snapshot["plan_ref"] if task["agent_task"] ==
                     "reachability_planning" else None),
        "repair": task["repair"],
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def load_base_database(world):
    fixture = json.loads((Path(__file__).parent / "fixtures" /
                          "legacy_agent_replay.json").read_text())
    tables = fixture["tables"]
    # Persist the original JSON shapes directly: validating then dumping new
    # models would insert model_policy:null into historical PendingTasks.
    for policy in tables["policies"]:
        world.store.db.execute("INSERT OR REPLACE INTO policies VALUES (?, ?)",
                               (policy["policy_id"], json.dumps(policy)))
    for job in tables["jobs"]:
        world.store.db.execute("INSERT INTO jobs VALUES (?, ?, ?, ?)",
                               (job["job_id"], job["state"], job["seq"],
                                json.dumps(job)))
    for transition in tables["transitions"]:
        world.store.db.execute("INSERT INTO transitions VALUES (?, ?, ?)",
                               (transition["job_id"], transition["seq"],
                                json.dumps(transition)))
    for attempt in tables["attempts"]:
        world.store.db.execute("INSERT INTO attempts VALUES (?, ?, ?, ?)",
                               (attempt["task_id"], attempt["attempt"],
                                attempt["job_id"], json.dumps(attempt)))
    for candidate in tables["candidates"]:
        target = {key: value for key, value in candidate.items()
                  if key != "candidate_id"}
        world.store.db.execute("INSERT INTO candidates VALUES (?, ?, ?)",
                               (candidate["candidate_id"], json.dumps(target),
                                json.dumps(candidate)))
    return tables["jobs"][0]["job_id"]


def reopen(world):
    world.store.close()
    world.store = Store(world.tmp / "jobs.sqlite")
    world.controller = world._controller()


def test_base_created_agent_database_replays_before_and_after_recovery(world):
    job_id = load_base_database(world)
    reopen(world)
    stored = world.job(job_id)
    assert "model_policy" not in stored.pending_task.model_fields_set
    assert stored.pending_task.input_digest == legacy_digest(
        stored.model_dump(mode="json"))
    original_rows = world.store.db.execute(
        "SELECT body FROM transitions ORDER BY seq").fetchall()
    assert world.c.replay(job_id) == stored

    assert world.c.recover() == []
    current = world.job(job_id)
    assert current.pending_task.attempt == 2
    assert current.pending_task.input_digest == stored.pending_task.input_digest
    assert current.pending_task.model_policy is None
    assert world.agents.requests[-1].model_policy == \
        world.store.policy("p1").stage1_agents.candidate_analysis
    assert world.c.replay(job_id) == current
    # Recovery and replay must not rewrite any historical snapshot.
    assert world.store.db.execute(
        "SELECT body FROM transitions WHERE seq <= ? ORDER BY seq",
        (stored.seq,)).fetchall() == original_rows

    # Finishing the old task creates a modern planning task with a policy pin.
    world.analysis(job_id)
    assert world.job(job_id).pending_task.model_policy is not None
    assert world.c.replay(job_id) == world.job(job_id)
    world.restart()
    assert world.c.replay(job_id) == world.job(job_id)


def persist_legacy_agent_tasks(world, job_id):
    """Persist historical shapes for analysis, planning, retries and repairs."""
    digests = {}
    rows = world.store.db.execute(
        "SELECT seq, body FROM transitions WHERE job_id = ? ORDER BY seq",
        (job_id,)).fetchall()
    for seq, raw in rows:
        value = json.loads(raw)
        snapshot = value["job"]
        task = snapshot["pending_task"]
        if task is not None and task["kind"] == "agent":
            digest = digests.setdefault(task["task_id"], legacy_digest(snapshot))
            task.pop("model_policy")
            task["input_digest"] = digest
        world.store.db.execute(
            "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = ?",
            (json.dumps(value), job_id, seq))
    world.store.db.execute("UPDATE jobs SET body = ? WHERE job_id = ?",
                           (json.dumps(snapshot), job_id))
    for task_id, attempt, raw in world.store.db.execute(
            "SELECT task_id, attempt, body FROM attempts WHERE job_id = ?",
            (job_id,)).fetchall():
        value = json.loads(raw)
        value["input_digest"] = digests[task_id]
        world.store.db.execute(
            "UPDATE attempts SET body = ? WHERE task_id = ? AND attempt = ?",
            (json.dumps(value), task_id, attempt))


@pytest.mark.parametrize("stage", ["analysis", "planning", "retry", "repair"])
def test_legacy_agent_stages_preserve_historical_policy_on_restart(
        make_world, stage):
    original = Stage1AgentPolicy(
        candidate_analysis=AgentModelPolicy(provider="old", model="analysis"),
        reachability_planning=AgentModelPolicy(provider="old", model="planning"))
    world = make_world(stage1_agents=original)
    job_id = world.submit()
    if stage in ("planning", "repair"):
        world.analysis(job_id)
    if stage == "repair":
        world.plan(job_id)
        world.run(job_id, Q1Status.NOT_REACHED)
    if stage == "retry":
        task = world.job(job_id).pending_task
        world.c.on_agent_failure(task.task_id, task.attempt, "transient")
    expected_model = world.agents.requests[-1].model_policy
    persist_legacy_agent_tasks(world, job_id)
    reopen(world)
    stored = world.job(job_id)
    assert world.c.replay(job_id) == stored
    replacement = world.store.policy("p1").model_copy(update={
        "policy_id": "new", "stage1_agents": Stage1AgentPolicy(
            candidate_analysis=AgentModelPolicy(provider="new", model="analysis"),
            reachability_planning=AgentModelPolicy(provider="new", model="planning")),
    })
    world.store.save_policy(replacement)
    world.c.set_policy(job_id, "new")
    assert world.c.replay(job_id) == world.job(job_id)
    world.restart()
    assert world.c.replay(job_id) == world.job(job_id)
    assert world.agents.requests[-1].model_policy == expected_model
    assert world.job(job_id).pending_task.task_id == stored.pending_task.task_id
    assert world.job(job_id).pending_task.input_digest == stored.pending_task.input_digest


@pytest.mark.parametrize("alteration", [
    "digest", "modern-digest", "policy", "null-policy", "task-id", "attempt",
    "analysis-ref", "candidate", "binding",
])
def test_tampered_historical_agent_snapshot_is_rejected(world, alteration):
    job_id = load_base_database(world)
    # Authenticate the untampered database first so rejection below cannot
    # accidentally pass just because all historical replays are broken.
    assert world.c.replay(job_id) == world.job(job_id)
    row = world.store.db.execute(
        "SELECT body FROM transitions WHERE job_id = ? AND seq = 1",
        (job_id,)).fetchone()
    value = json.loads(row[0])
    snapshot = value["job"]
    task = snapshot["pending_task"]
    if alteration == "digest":
        task["input_digest"] = "0" * 64
    elif alteration == "modern-digest":
        from agent_pipeline.controller import events as ev
        initial = world.store.transitions(job_id)[0].job
        actual = world.c.machine.handle(initial, ev.EVENT.validate_python(value["event"]))
        task["input_digest"] = actual.job.pending_task.input_digest
    elif alteration == "policy":
        task["model_policy"] = AgentModelPolicy(
            provider="other", model="tampered").model_dump(mode="json")
    elif alteration == "null-policy":
        task["model_policy"] = None
    elif alteration == "task-id":
        task["task_id"] = job_id + ".t99"
    elif alteration == "attempt":
        task["attempt"] = 3
    elif alteration == "analysis-ref":
        snapshot["analysis_ref"] = "a" * 64
    elif alteration == "candidate":
        snapshot["candidate"]["candidate_id"] = "VC-other"
    elif alteration == "binding":
        snapshot["binding"]["hcap_revision"] = "b" * 64
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = 1",
        (json.dumps(value), job_id))
    world.store.db.execute("UPDATE jobs SET body = ? WHERE job_id = ?",
                           (json.dumps(snapshot), job_id))
    reopen(world)
    with pytest.raises(ReplayMismatch, match="seq 1"):
        world.c.replay(job_id)


@pytest.mark.parametrize("alteration", ["digest", "policy", "missing-policy"])
def test_current_agent_policy_and_digest_still_compare_exactly(world, alteration):
    job_id = world.submit()
    assert world.c.replay(job_id) == world.job(job_id)
    value = json.loads(world.store.db.execute(
        "SELECT body FROM transitions WHERE job_id = ? AND seq = 1",
        (job_id,)).fetchone()[0])
    task = value["job"]["pending_task"]
    if alteration == "digest":
        task["input_digest"] = "0" * 64
    elif alteration == "policy":
        task["model_policy"]["model"] = "changed"
    else:
        task.pop("model_policy")
    world.store.db.execute(
        "UPDATE transitions SET body = ? WHERE job_id = ? AND seq = 1",
        (json.dumps(value), job_id))
    with pytest.raises(ReplayMismatch, match="seq 1"):
        world.c.replay(job_id)
