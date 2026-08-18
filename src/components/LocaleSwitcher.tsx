import { Languages } from "lucide-react";
import { useRef, useState } from "react";
import { REGISTERED_PACKS, getActivePack, t } from "../i18n.ts";
import { useDismissibleLayer } from "../useDismissibleLayer";

interface LocaleSwitcherProps {
  onChange: (locale: string) => void;
}

export function LocaleSwitcher({ onChange }: LocaleSwitcherProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  useDismissibleLayer(open, rootRef, () => setOpen(false));
  const activeId = getActivePack().id;

  return (
    <div className="locale-switcher" data-locale-switcher="" ref={rootRef}>
      <button
        type="button"
        className={`icon-button locale-switcher__button ${open ? "is-open" : ""}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("shell.language")}
        title={t("shell.language")}
        onClick={() => setOpen((current) => !current)}
      >
        <Languages size={16} />
      </button>
      {open && (
        <div className="locale-switcher__menu" role="listbox" aria-label={t("shell.languageMenu")}>
          {REGISTERED_PACKS.map((pack) => (
            <button
              key={pack.id}
              type="button"
              role="option"
              aria-selected={pack.id === activeId}
              className={pack.id === activeId ? "is-active" : ""}
              onClick={() => {
                onChange(pack.id);
                setOpen(false);
              }}
            >
              <span>{pack.nativeName}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
