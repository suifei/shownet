import { X } from "lucide-react";

import { t } from "../i18n.ts";

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
function shortcutGroups(): ShortcutGroup[] {
  const click = t("shortcuts.click");
  const right = t("shortcuts.rightClick");
  return [
    {
      title: t("shortcuts.global"),
      items: [
        { keys: ["⌘", "K"], description: t("shortcuts.openPalette") },
        { keys: ["?"], description: t("shortcuts.openThis") },
        { keys: ["Esc"], description: t("shortcuts.escape") },
      ],
    },
    {
      title: t("shortcuts.list"),
      items: [
        { keys: ["↑", "↓"], description: t("shortcuts.move"), alt: true },
        { keys: ["Enter"], description: t("shortcuts.toggleDetail") },
        { keys: ["⌘", "A"], description: t("shortcuts.selectAll") },
        { keys: ["⌘", click], description: t("shortcuts.cmdClick") },
        { keys: ["Shift", click], description: t("shortcuts.shiftClick") },
        { keys: [right], description: t("shortcuts.rowMenu") },
      ],
    },
    {
      title: t("shortcuts.columns"),
      note: t("shortcuts.columnsNote"),
      items: [
        { keys: [click], description: t("shortcuts.sort") },
        { keys: ["Shift", click], description: t("shortcuts.multiSort") },
        { keys: [t("shortcuts.dragName")], description: t("shortcuts.reorder") },
        { keys: [t("shortcuts.dragSplit")], description: t("shortcuts.resize") },
        { keys: [t("shortcuts.dblSplit")], description: t("shortcuts.autofit") },
        { keys: [right], description: t("shortcuts.columnsMenu") },
      ],
    },
  ];
}

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
            <h2 id="shortcuts-sheet-title">{t("shortcuts.title")}</h2>
          </div>
          <button className="icon-button" onClick={onClose} title={t("common.close")}><X size={18} /></button>
        </header>
        <div className="shortcuts-sheet__groups">
          {shortcutGroups().map((group) => (
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
