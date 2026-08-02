import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { matchesRequestDraftSearch, parseDraftTagInput, requestDraftCollectionPath } from "../src/requestCollections.ts";
import type { RequestCollectionWorkspace, RequestDraft } from "../src/types.ts";

const workspace: RequestCollectionWorkspace = {
  collections: [{
    id: "collection-shop", name: "商城 API", description: "", defaultHeaders: [], defaultAuth: { kind: "none" },
    sortOrder: 0, draftCount: 1, folderCount: 2, createdAt: 1, updatedAt: 1,
  }],
  folders: [
    { id: "folder-auth", collectionId: "collection-shop", name: "账号", depth: 1, sortOrder: 0, draftCount: 1, createdAt: 1, updatedAt: 1 },
    { id: "folder-login", collectionId: "collection-shop", parentId: "folder-auth", name: "登录", depth: 2, sortOrder: 0, draftCount: 1, createdAt: 1, updatedAt: 1 },
  ],
  drafts: [],
};

function draft(overrides: Partial<RequestDraft> = {}): RequestDraft {
  return {
    id: "draft-login", name: "获取登录挑战", method: "POST", url: "https://api.example.test/v2/auth/challenge",
    headers: [], body: "", bodyType: "none", auth: { kind: "none" }, settings: {},
    collectionId: "collection-shop", folderId: "folder-login", tags: ["鉴权", "Smoke Test"],
    createdAt: 1, updatedAt: 1, ...overrides,
  };
}

describe("request collection helpers", () => {
  it("parses comma and line separated tags while preserving first spelling", () => {
    assert.deepEqual(parseDraftTagInput("鉴权, Smoke Test\nsmoke test； 回归，鉴权"), ["鉴权", "Smoke Test", "回归"]);
  });

  it("builds a complete collection path for nested folders", () => {
    assert.equal(requestDraftCollectionPath(draft(), workspace), "商城 API / 账号 / 登录");
    assert.equal(requestDraftCollectionPath(draft({ collectionId: undefined, folderId: undefined }), workspace), "未归档");
  });

  it("searches name, method, URL, tags and collection path with all terms", () => {
    const item = draft();
    for (const query of ["登录挑战", "post", "auth/challenge", "smoke", "商城 登录", "鉴权 POST"]) {
      assert.equal(matchesRequestDraftSearch(item, workspace, query), true, query);
    }
    assert.equal(matchesRequestDraftSearch(item, workspace, "支付 POST"), false);
  });
});
