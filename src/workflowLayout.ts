export const WORKFLOW_NODE_WIDTH = 112;
export const WORKFLOW_NODE_HEIGHT = 92;
export const WORKFLOW_EDGE_WIDTH = 28;
export const WORKFLOW_TURN_HEIGHT = 36;

const FLOW_HORIZONTAL_PADDING = 40;
const FLOW_VERTICAL_PADDING = 40;
const SINGLE_ROW_LIMIT = 5;

export interface WorkflowLayout {
  columns: number;
  rows: number;
  graphWidth: number;
  graphHeight: number;
}

export function calculateWorkflowLayout(
  stageCount: number,
  containerWidth: number,
  containerHeight: number,
): WorkflowLayout {
  const count = Math.max(0, Math.floor(stageCount));
  if (count === 0) {
    return { columns: 0, rows: 0, graphWidth: 0, graphHeight: 0 };
  }

  const availableWidth = Math.max(
    WORKFLOW_NODE_WIDTH,
    Math.floor(containerWidth || 720) - FLOW_HORIZONTAL_PADDING,
  );
  const availableHeight = Math.max(
    WORKFLOW_NODE_HEIGHT,
    Math.floor(containerHeight || 420) - FLOW_VERTICAL_PADDING,
  );
  const maxColumns = Math.max(
    1,
    Math.min(
      count,
      Math.floor((availableWidth + WORKFLOW_EDGE_WIDTH) / (WORKFLOW_NODE_WIDTH + WORKFLOW_EDGE_WIDTH)),
    ),
  );

  if (count <= SINGLE_ROW_LIMIT && count <= maxColumns) {
    return measureLayout(count, count);
  }

  // A constrained Sugiyama-style rank pass: score each feasible column count,
  // then let the view alternate rank direction to keep a linear DAG compact.
  const targetAspectRatio = clamp(availableWidth / availableHeight, 1.2, 2.4);
  let best = measureLayout(count, 1);
  let bestScore = Number.POSITIVE_INFINITY;

  for (let columns = 1; columns <= maxColumns; columns += 1) {
    const candidate = measureLayout(count, columns);
    const verticalOverflow = Math.max(0, candidate.graphHeight - availableHeight) / availableHeight;
    const candidateAspectRatio = candidate.graphWidth / candidate.graphHeight;
    const aspectPenalty = Math.abs(Math.log(candidateAspectRatio / targetAspectRatio));
    const emptySlots = candidate.rows * candidate.columns - count;
    const raggedRowPenalty = (emptySlots / count) * 0.18;
    const rowPenalty = candidate.rows * 0.015;
    const score = verticalOverflow * 100 + aspectPenalty + raggedRowPenalty + rowPenalty;

    if (score < bestScore) {
      best = candidate;
      bestScore = score;
    }
  }

  return best;
}

export function partitionWorkflowStages<T>(stages: readonly T[], columns: number): T[][] {
  const rowSize = Math.max(1, Math.floor(columns));
  const rows: T[][] = [];
  for (let index = 0; index < stages.length; index += rowSize) {
    rows.push(stages.slice(index, index + rowSize));
  }
  return rows;
}

function measureLayout(stageCount: number, columns: number): WorkflowLayout {
  const boundedColumns = Math.max(1, Math.min(stageCount, columns));
  const rows = Math.ceil(stageCount / boundedColumns);
  return {
    columns: boundedColumns,
    rows,
    graphWidth: boundedColumns * WORKFLOW_NODE_WIDTH + (boundedColumns - 1) * WORKFLOW_EDGE_WIDTH,
    graphHeight: rows * WORKFLOW_NODE_HEIGHT + (rows - 1) * WORKFLOW_TURN_HEIGHT,
  };
}

function clamp(value: number, minimum: number, maximum: number) {
  return Math.min(maximum, Math.max(minimum, value));
}
