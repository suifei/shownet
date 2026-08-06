import { X } from "lucide-react";

interface ShortcutsSheetProps {
  onClose: () => void;
}

interface ShortcutGroup {
  title: string;
  note?: string;
  /** With `alt`, the keys are alternatives (↑ / ↓); otherwise a combination. */
  items: Array<{ keys: string[]; description: string; alt?: boolean }>;
}

/**
 * The request grid supports multi-column sort, range select, keyboard
 * navigation, column drag, resize and double-click auto-fit — none of which
 * appear anywhere in the UI. They were reachable only through `title` tooltips
 * or by accident.
 */
const GROUPS: ShortcutGroup[] = [
  {
    title: "全局",
    items: [
      { keys: ["⌘", "K"], description: "打开命令面板，搜索任何功能" },
      { keys: ["?"], description: "打开这份快捷键说明" },
      { keys: ["Esc"], description: "依次关闭：详情 → 筛选 → 选择" },
    ],
  },
  {
    title: "流量列表",
    items: [
      { keys: ["↑", "↓"], description: "上下移动当前行", alt: true },
      { keys: ["Enter"], description: "打开或关闭详情面板" },
      { keys: ["⌘", "A"], description: "全选当前窗口的请求" },
      { keys: ["⌘", "点击"], description: "加选或取消单条，不打开详情" },
      { keys: ["Shift", "点击"], description: "连选一段范围" },
      { keys: ["右键"], description: "打开请求操作菜单" },
    ],
  },
  {
    title: "列与排序",
    note: "以下操作都在表头进行。",
    items: [
      { keys: ["点击"], description: "按该列排序，再点切换升降序或取消" },
      { keys: ["Shift", "点击"], description: "追加为次级排序条件，序号显示优先级" },
      { keys: ["拖动列名"], description: "调整列的先后顺序" },
      { keys: ["拖动分隔线"], description: "调整列宽" },
      { keys: ["双击分隔线"], description: "按内容自适应列宽" },
      { keys: ["右键"], description: "配置显示哪些列" },
    ],
  },
];

export function ShortcutsSheet({ onClose }: ShortcutsSheetProps) {
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="shortcuts-sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby="shortcuts-sheet-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <span className="section-kicker">KEYBOARD &amp; MOUSE</span>
            <h2 id="shortcuts-sheet-title">快捷操作</h2>
          </div>
          <button className="icon-button" onClick={onClose} title="关闭"><X size={18} /></button>
        </header>
        <div className="shortcuts-sheet__groups">
          {GROUPS.map((group) => (
            <section key={group.title}>
              <h3>{group.title}</h3>
              {group.note && <p>{group.note}</p>}
              <dl>
                {group.items.map((item) => (
                  <div key={item.description}>
                    <dt>
                      {item.keys.map((key, index) => (
                        <span key={key}>
                          {index > 0 && <i>{item.alt ? "/" : "+"}</i>}
                          <kbd>{key}</kbd>
                        </span>
                      ))}
                    </dt>
                    <dd>{item.description}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      </section>
    </div>
  );
}
