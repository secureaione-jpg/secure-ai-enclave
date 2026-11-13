import { describe, expect, it } from "vitest";
import { judgeNumbers, localNumberModel, readQuestion } from "./localNumberModel";
import { numberQuestion } from "../../cloudflare-worker/redactionNumbers";

describe("the local number judge", () => {
  it("keeps quantities, money, years and year-months", () => {
    expect(judgeNumbers("We shipped 2400 units at $3200 in 2024, report 202403.", ["2400", "3200", "2024", "202403"])).toEqual([]);
    expect(judgeNumbers("Response time fell to 240 ms across 15000 requests.", ["15000"])).toEqual([]);
  });

  it("takes numbers a word names, a building number, and dotted phone numbers", () => {
    expect(judgeNumbers("Payment will be made from 10972500.", ["10972500"])).toEqual(["10972500"]);
    expect(judgeNumbers("Policy 48817 is up for renewal.", ["48817"])).toEqual(["48817"]);
    expect(judgeNumbers("She lives at 4821 Maple Street.", ["4821"])).toEqual(["4821"]);
    expect(judgeNumbers("Call me on (98) 7561.5671 tonight.", ["7561.5671"])).toEqual(["7561.5671"]);
  });

  it("reads the question the number stage writes, and answers in its envelope", async () => {
    const q = numberQuestion("Payment will be made from 10972500 for 30 units.", [{ value: "10972500", index: 26 }]);
    expect(readQuestion(q)?.candidates).toEqual(["10972500"]);
    expect(await localNumberModel("", q, 1000)).toEqual({ response: ["10972500"] });
  });
});
