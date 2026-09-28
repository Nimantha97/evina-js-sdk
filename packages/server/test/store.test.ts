/**
 * Transaction store unit tests — M3
 *
 * Covers FR-25 / ADR-007:
 *   - save / get / delete semantics
 *   - TTL expiry (lazy on get + background sweep) with injected clock
 *   - clone isolation (no shared-reference mutation)
 *   - timer lifecycle (enable / disable / stop)
 */

import { describe, it, expect, vi } from "vitest";
import {
  InMemoryTransactionStore,
  TOKEN_TTL_MS,
} from "../src/store";
import type { StoredTransaction } from "../src/types";

function makeRecord(overrides: Partial<StoredTransaction> = {}): StoredTransaction {
  return {
    ti: "tx-1",
    token: "tok-1",
    country: "LK",
    createdAt: 1000,
    expiresAt: 5000,
    ...overrides,
  };
}

describe("TOKEN_TTL_MS", () => {
  it("is 6 hours in milliseconds (EVINA_API_FACTS §9)", () => {
    expect(TOKEN_TTL_MS).toBe(6 * 60 * 60 * 1000);
  });
});

describe("InMemoryTransactionStore — CRUD", () => {
  it("saves and retrieves a record", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await store.save(makeRecord());
    await expect(store.get("tx-1")).resolves.toEqual(makeRecord());
  });

  it("returns null for an unknown ti", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await expect(store.get("nope")).resolves.toBeNull();
  });

  it("returns null for a non-string ti", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await expect(
      store.get(123 as unknown as string),
    ).resolves.toBeNull();
  });

  it("deletes a record", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await store.save(makeRecord());
    await store.delete("tx-1");
    await expect(store.get("tx-1")).resolves.toBeNull();
  });

  it("delete is idempotent for an unknown ti", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await expect(store.delete("nope")).resolves.toBeUndefined();
  });

  it("overwrites an existing record with the same ti", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await store.save(makeRecord({ token: "first" }));
    await store.save(makeRecord({ token: "second" }));
    const got = await store.get("tx-1");
    expect(got?.token).toBe("second");
    expect(store.size).toBe(1);
  });
});

describe("InMemoryTransactionStore — save validation", () => {
  it("rejects an empty ti", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    await expect(store.save(makeRecord({ ti: "" }))).rejects.toBeInstanceOf(
      TypeError,
    );
    store.stop();
  });

  it("rejects a non-string ti", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    await expect(
      store.save(makeRecord({ ti: 42 as unknown as string })),
    ).rejects.toBeInstanceOf(TypeError);
    store.stop();
  });
});

describe("InMemoryTransactionStore — TTL expiry (lazy)", () => {
  it("treats an entry past expiresAt as absent and removes it", async () => {
    let clock = 1000;
    const store = new InMemoryTransactionStore({
      now: () => clock,
      sweepIntervalMs: 0,
    });
    await store.save(makeRecord({ expiresAt: 2000 }));
    clock = 2001;
    await expect(store.get("tx-1")).resolves.toBeNull();
    expect(store.size).toBe(0); // lazily purged
  });

  it("expires exactly at expiresAt (<=)", async () => {
    let clock = 1000;
    const store = new InMemoryTransactionStore({
      now: () => clock,
      sweepIntervalMs: 0,
    });
    await store.save(makeRecord({ expiresAt: 2000 }));
    clock = 2000;
    await expect(store.get("tx-1")).resolves.toBeNull();
  });

  it("keeps an entry that is still within its TTL", async () => {
    const store = new InMemoryTransactionStore({
      now: () => 1500,
      sweepIntervalMs: 0,
    });
    await store.save(makeRecord({ expiresAt: 2000 }));
    await expect(store.get("tx-1")).resolves.not.toBeNull();
  });
});

describe("InMemoryTransactionStore — sweep", () => {
  it("purges only expired entries and returns the count", async () => {
    let clock = 1000;
    const store = new InMemoryTransactionStore({
      now: () => clock,
      sweepIntervalMs: 0,
    });
    await store.save(makeRecord({ ti: "a", expiresAt: 2000 }));
    await store.save(makeRecord({ ti: "b", expiresAt: 9000 }));
    clock = 3000;

    expect(store.sweep()).toBe(1);
    expect(store.size).toBe(1);
    await expect(store.get("b")).resolves.not.toBeNull();
  });

  it("returns 0 when nothing is expired", async () => {
    const store = new InMemoryTransactionStore({
      now: () => 0,
      sweepIntervalMs: 0,
    });
    await store.save(makeRecord({ expiresAt: 9999 }));
    expect(store.sweep()).toBe(0);
  });

  it("runs automatically on the sweep interval", async () => {
    vi.useFakeTimers();
    try {
      let clock = 1000;
      const store = new InMemoryTransactionStore({
        now: () => clock,
        sweepIntervalMs: 100,
      });
      await store.save(makeRecord({ expiresAt: 2000 }));
      clock = 3000;
      vi.advanceTimersByTime(100);
      expect(store.size).toBe(0);
      store.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("InMemoryTransactionStore — clone isolation", () => {
  it("does not store a live reference to the caller's object", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    const input = makeRecord();
    await store.save(input);
    input.token = "mutated-after-save";
    const got = await store.get("tx-1");
    expect(got?.token).toBe("tok-1");
  });

  it("does not return a live reference into the store", async () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0, now: () => 0 });
    await store.save(makeRecord());
    const first = await store.get("tx-1");
    if (first) first.token = "mutated-returned";
    const second = await store.get("tx-1");
    expect(second?.token).toBe("tok-1");
  });
});

describe("InMemoryTransactionStore — timer lifecycle", () => {
  it("creates a store with defaults and can be stopped", () => {
    const store = new InMemoryTransactionStore();
    expect(store.size).toBe(0);
    store.stop();
  });

  it("stop() is safe to call multiple times", () => {
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    store.stop();
    store.stop();
    expect(store.size).toBe(0);
  });

  it("uses the real Date.now clock when none is injected", async () => {
    // No `now` option → exercises the default () => Date.now() clock.
    const store = new InMemoryTransactionStore({ sweepIntervalMs: 0 });
    // expiresAt far in the past relative to the real wall clock → expired.
    await store.save(makeRecord({ expiresAt: 1 }));
    await expect(store.get("tx-1")).resolves.toBeNull();
  });
});
