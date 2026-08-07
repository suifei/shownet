/**
 * Whether a toast is reporting something that went wrong.
 *
 * Every toast rendered a green tick regardless of what it said, so
 * "转发目标请求失败: http2 error" arrived looking like a success. That is the
 * same shape as a status flag that cannot express failure — the user has to
 * read the sentence to find out the app is telling them about a problem.
 *
 * This is a heuristic over the vocabulary the app actually uses rather than a
 * type-level distinction, because `setToast` takes a bare string from ~60 call
 * sites. It is deliberately conservative: anything it does not recognise stays
 * neutral rather than being claimed as a success.
 */
export type ToastTone = "success" | "error" | "neutral";

/** Words that only appear when something failed. */
const FAILURE = [
  "失败",
  "错误",
  "无法",
  "不能",
  "超时",
  "已损坏",
  "不可用",
  "未完成",
  "被拒绝",
  "异常",
  // "MCP Server 已保存，连接测试未通过" pairs a success word with a failure —
  // without this it scored as a win and rendered a tick over a failed test.
  "未通过",
  "未成功",
  "不可达",
  "error",
  "failed",
  "timeout",
  "cannot",
  "unable",
];

/** Words that confirm something completed. */
const SUCCESS = [
  "已保存",
  "已生效",
  "已完成",
  "已安装",
  "已导出",
  "已复制",
  "已清除",
  "已启用",
  "已创建",
  "已删除",
  "已重命名",
  "已开始",
  "已停止",
  "已打开",
  "已加入",
  "已应用",
  "已恢复",
];

export function toastTone(message: string): ToastTone {
  const text = message.toLowerCase();
  if (FAILURE.some((word) => text.includes(word.toLowerCase()))) return "error";
  if (SUCCESS.some((word) => message.includes(word))) return "success";
  return "neutral";
}
