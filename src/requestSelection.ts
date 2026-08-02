export interface RequestSelectionState {
  selectedIds: string[];
  focusedId?: string;
  anchorId?: string;
}

export type RequestSelectionAction =
  | { type: "click"; id: string; ids: string[]; toggle?: boolean; range?: boolean }
  | { type: "selectAll"; ids: string[]; focusedId?: string }
  | { type: "move"; direction: -1 | 1; ids: string[]; extend?: boolean }
  | { type: "reconcile"; ids: string[] }
  | { type: "clear" };

export const initialRequestSelection: RequestSelectionState = { selectedIds: [] };

export function requestSelectionReducer(state: RequestSelectionState, action: RequestSelectionAction): RequestSelectionState {
  if (action.type === "clear") return initialRequestSelection;
  if (action.type === "selectAll") {
    const focusedId = action.focusedId && action.ids.includes(action.focusedId)
      ? action.focusedId
      : state.focusedId && action.ids.includes(state.focusedId)
        ? state.focusedId
        : action.ids[0];
    return { selectedIds: unique(action.ids), focusedId, anchorId: focusedId };
  }
  if (action.type === "reconcile") {
    const available = new Set(action.ids);
    const selectedIds = state.selectedIds.filter((id) => available.has(id));
    const focusedId = state.focusedId && available.has(state.focusedId)
      ? state.focusedId
      : selectedIds[0] ?? nearestAvailable(state.focusedId, action.ids);
    const anchorId = state.anchorId && available.has(state.anchorId) ? state.anchorId : focusedId;
    return { selectedIds, focusedId, anchorId };
  }
  if (action.type === "move") {
    if (action.ids.length === 0) return initialRequestSelection;
    const currentIndex = Math.max(0, action.ids.indexOf(state.focusedId ?? ""));
    const nextIndex = Math.min(action.ids.length - 1, Math.max(0, currentIndex + action.direction));
    const focusedId = action.ids[nextIndex];
    if (!action.extend) return { selectedIds: [focusedId], focusedId, anchorId: focusedId };
    const anchorId = state.anchorId && action.ids.includes(state.anchorId) ? state.anchorId : (state.focusedId ?? focusedId);
    return { selectedIds: rangeBetween(action.ids, anchorId, focusedId), focusedId, anchorId };
  }

  if (action.range) {
    const anchorId = state.anchorId && action.ids.includes(state.anchorId) ? state.anchorId : action.id;
    const range = rangeBetween(action.ids, anchorId, action.id);
    return {
      selectedIds: action.toggle ? unique([...state.selectedIds, ...range]) : range,
      focusedId: action.id,
      anchorId,
    };
  }
  if (action.toggle) {
    const selectedIds = state.selectedIds.includes(action.id)
      ? state.selectedIds.filter((id) => id !== action.id)
      : [...state.selectedIds, action.id];
    return { selectedIds, focusedId: action.id, anchorId: action.id };
  }
  return { selectedIds: [action.id], focusedId: action.id, anchorId: action.id };
}

function rangeBetween(ids: string[], startId: string, endId: string) {
  const start = ids.indexOf(startId);
  const end = ids.indexOf(endId);
  if (start < 0 || end < 0) return [endId];
  return ids.slice(Math.min(start, end), Math.max(start, end) + 1);
}

function unique(ids: string[]) {
  return [...new Set(ids)];
}

function nearestAvailable(_previous: string | undefined, ids: string[]) {
  return ids[0];
}
