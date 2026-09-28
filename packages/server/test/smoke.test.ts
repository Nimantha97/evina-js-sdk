import { describe, it, expect } from "vitest";

import { SDK_NAME } from "../src/index";

// M0 smoke test: proves the toolchain (TS strict, Vitest, coverage) is wired up
// end-to-end. Real behavioural tests arrive with M1+.
describe("M0 bootstrap", () => {
  it("exposes the package name", () => {
    expect(SDK_NAME).toBe("@ideabiz/evina-sdk");
  });
});
