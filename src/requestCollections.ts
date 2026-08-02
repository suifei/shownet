import type { RequestCollectionWorkspace, RequestDraft } from "./types";

export function parseDraftTagInput(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[\n,，;；]+/)
    .map((tag) => tag.trim().replace(/\s+/g, " "))
    .filter((tag) => {
      if (!tag) return false;
      const key = tag.toLocaleLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

export function requestDraftCollectionPath(
  draft: Pick<RequestDraft, "collectionId" | "folderId">,
  workspace: Pick<RequestCollectionWorkspace, "collections" | "folders">,
): string {
  const collection = workspace.collections.find((item) => item.id === draft.collectionId);
  if (!collection) return "未归档";
  const segments = [collection.name];
  const folderSegments: string[] = [];
  const visited = new Set<string>();
  let folder = workspace.folders.find((item) => item.id === draft.folderId);
  while (folder && folder.collectionId === collection.id && !visited.has(folder.id)) {
    visited.add(folder.id);
    folderSegments.push(folder.name);
    folder = workspace.folders.find((item) => item.id === folder?.parentId);
  }
  return [...segments, ...folderSegments.reverse()].join(" / ");
}

export function matchesRequestDraftSearch(
  draft: RequestDraft,
  workspace: Pick<RequestCollectionWorkspace, "collections" | "folders">,
  query: string,
): boolean {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const searchable = [
    draft.name,
    draft.method,
    draft.url,
    ...draft.tags,
    requestDraftCollectionPath(draft, workspace),
  ].join("\n").toLocaleLowerCase();
  return terms.every((term) => searchable.includes(term));
}
