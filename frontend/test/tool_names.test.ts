import { describe, expect, it } from "vitest";
import { splitNames, toolNameProblems } from "../lib/tool_names";

const known = [
  { name: "deepwiki.read_wiki_structure", kind: "mcp" as const, usable: true },
  { name: "deepwiki.ask_wiki_question", kind: "mcp" as const, usable: false },
  { name: "crm.lookup", kind: "http" as const, usable: true },
];

describe("toolNameProblems", () => {
  it("names a typo and a tool not approved yet", () => {
    const names = splitNames("deepwiki.read_wiki_structure, deepwiki.ask_question, deepwiki.ask_wiki_question, crm.lookup");
    expect(toolNameProblems(names, known)).toEqual({
      unknown: ["deepwiki.ask_question"],
      notApproved: ["deepwiki.ask_wiki_question"],
    });
  });
  it("is exact: no patterns, no case folding", () => {
    expect(toolNameProblems(["deepwiki.*", "CRM.lookup"], known).unknown).toEqual(["deepwiki.*", "CRM.lookup"]);
  });
  it("says nothing before the list is loaded", () => {
    expect(toolNameProblems(["anything"], null)).toEqual({ unknown: [], notApproved: [] });
  });
  it("splits a comma list", () => {
    expect(splitNames(" a, b ,, c ")).toEqual(["a", "b", "c"]);
  });
});
