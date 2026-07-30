import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { createA2aTaskStateCustody, createA2aTaskStateCustodyFromEnvironment, a2aTaskStateRecord, internals } from "../src/a2a-task-state-custody.mjs";

function fakeR2() {
  const store = new Map();
  return {
    async putCurrent(key, { body, byteLength, sha256, mediaType }) {
      assert.equal(byteLength, body.length);
      assert.ok(/^[a-f0-9]{64}$/u.test(sha256));
      store.set(key, { body, mediaType, etag: `etag-${store.size}` });
    },
    async get(key) {
      const object = store.get(key);
      return object ? Object.freeze({ body: object.body, mediaType: object.mediaType, etag: object.etag }) : null;
    },
    async list(prefix) {
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix));
      return Object.freeze({ keys, continuationToken: undefined });
    },
  };
}

function envelope(status) {
  return { protocol: "A2A", protocolVersion: "1.0", tenant: "tenant-a", task: { id: "task-1", status: { state: status } } };
}

test("put then get returns the head version", async () => {
  const custody = createA2aTaskStateCustody({ client: fakeR2() });
  const record = a2aTaskStateRecord(envelope("TASK_STATE_WORKING"));
  await custody.put({ taskId: "task-1", tenant: "tenant-a", ...record });
  const head = await custody.get({ taskId: "task-1", tenant: "tenant-a" });
  assert.equal(head.envelope.task.status.state, "TASK_STATE_WORKING");
});

test("environment factory retires R2 for thin task state", () => {
  assert.throws(
    () => createA2aTaskStateCustodyFromEnvironment({ API_KEY_CLOUDFLARE_R2_EDIT: "token" }),
    /R2 custody is retired/u,
  );
});

test("a terminal task state refuses to absorb a further transition", async () => {
  const custody = createA2aTaskStateCustody({ client: fakeR2() });
  const first = a2aTaskStateRecord(envelope("TASK_STATE_COMPLETED"));
  await custody.put({ taskId: "task-1", tenant: "tenant-a", ...first });
  const second = a2aTaskStateRecord(envelope("TASK_STATE_WORKING"));
  await assert.rejects(() => custody.put({ taskId: "task-1", tenant: "tenant-a", ...second }));
});

test("list groups versions by task and returns each head", async () => {
  const custody = createA2aTaskStateCustody({ client: fakeR2() });
  const record = a2aTaskStateRecord(envelope("TASK_STATE_WORKING"));
  await custody.put({ taskId: "task-1", tenant: "tenant-a", ...record });
  const listed = await custody.list({ tenant: "tenant-a" });
  assert.equal(listed.length, 1);
  assert.equal(listed[0].taskId, "task-1");
});

test("inspect retains every fork branch without selecting a task head", async () => {
  const client = fakeR2();
  const custody = createA2aTaskStateCustody({ client });
  const first = a2aTaskStateRecord(envelope("TASK_STATE_COMPLETED"));
  await custody.put({ taskId: "task-1", tenant: "tenant-a", ...first });
  const branch = a2aTaskStateRecord({ ...envelope("TASK_STATE_FAILED"), task: { id: "task-1", status: { state: "TASK_STATE_FAILED" } } });
  const key = `a2a-task-state/v2/${createHash("sha256").update("tenant-a").digest("hex")}/${createHash("sha256").update("task-1").digest("hex")}/${branch.sha256}.a2a-task-state.json.gz`;
  const carrier = { type: "A2aTaskStateVersion", taskId: "task-1", tenant: "tenant-a", sha256: branch.sha256, predecessor: null, envelope: branch.envelope };
  const body = gzipSync(Buffer.from(`${internals.canonicalJson(carrier)}\n`));
  await client.putCurrent(key, { body, byteLength: body.length, sha256: createHash("sha256").update(body).digest("hex"), mediaType: "application/gzip" });
  const observed = await custody.inspect({ taskId: "task-1", tenant: "tenant-a" });
  assert.equal(observed.status, "forked");
  assert.deepEqual(observed.heads.map((value) => value.sha256), [first.sha256, branch.sha256].sort());
  await assert.rejects(() => custody.get({ taskId: "task-1", tenant: "tenant-a" }), /A2A task-state fork/u);
  const mergedEnvelope = structuredClone(branch.envelope);
  mergedEnvelope.task.metadata = { reconciliation: "equivalent-terminal-outcome" };
  await custody.reconcileEquivalent({
    taskId: "task-1",
    tenant: "tenant-a",
    heads: observed.heads.map((value) => value.sha256),
    envelope: mergedEnvelope,
    equivalence: { type: "A2aEquivalentTerminalOutcome", outcomeDigest: "sha256:identical-artifact" },
  });
  const settled = await custody.get({ taskId: "task-1", tenant: "tenant-a" });
  assert.equal(settled.envelope.task.metadata.reconciliation, "equivalent-terminal-outcome");
  assert.deepEqual(settled.predecessors, [first.sha256, branch.sha256].sort());
});

test("invalid predecessor is quarantined without preventing valid replay", async () => {
  const client = fakeR2(), custody = createA2aTaskStateCustody({ client });
  const valid = a2aTaskStateRecord(envelope("TASK_STATE_WORKING"));
  await custody.put({ taskId: "task-1", tenant: "tenant-a", ...valid });
  const invalid = { type: "A2aTaskStateVersion", taskId: "task-legacy", tenant: "tenant-a", sha256: valid.sha256, predecessor: "legacy", envelope: { ...valid.envelope, task: { ...valid.envelope.task, id: "task-legacy" } } };
  const legacyKey = "a2a-task-state/v2/" + createHash("sha256").update("tenant-a").digest("hex") + "/" + createHash("sha256").update("task-legacy").digest("hex") + "/legacy.a2a-task-state.json.gz";
  const body = gzipSync(Buffer.from(internals.canonicalJson(invalid) + "\n"));
  await client.putCurrent(legacyKey, { body, byteLength: body.length, sha256: createHash("sha256").update(body).digest("hex"), mediaType: "application/gzip" });
  assert.deepEqual((await custody.list({ tenant: "tenant-a" })).map((record) => record.taskId), ["task-1"]);
  assert.equal((await custody.list({ tenant: "tenant-a" })).length, 1, "restart-safe repeated replay keeps the one valid task");
});
