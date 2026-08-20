import { Monitor, Moon, Sun } from "lucide-react";
import { useRef, useState, type ComponentType } from "react";
import { t, type MessageKey } from "../i18n.ts";
import { THEME_PREFERENCES, type ThemePreference } from "../theme.ts";
import { useDismissibleLayer } from "../useDismissibleLayer";

interface ThemeSwitcherProps {
  preference: ThemePreference;
  onChange: (preference: ThemePreference) => void;
}

const THEME_ICONS: Record<ThemePreference, ComponentType<{ size?: number }>> = {
  system: Monitor,
  light: Sun,
  dark: Moon,
};

const THEME_LABELS = {
  system: "shell.theme.system",
  light: "shell.theme.light",
  dark: "shell.theme.dark",
} as const satisfies Record<ThemePreference, MessageKey>;

export function ThemeSwitcher({ preference, onChange }: ThemeSwitcherProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  useDismissibleLayer(open, rootRef, () => setOpen(false));
  const ActiveIcon = THEME_ICONS[preference];

  return (
    <div className="chrome-switcher" data-theme-switcher="" ref={rootRef}>
      <button
        type="button"
        className={`icon-button chrome-switcher__button ${open ? "is-open" : ""}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("shell.theme")}
        title={t("shell.theme")}
        onClick={() => setOpen((current) => !current)}
      >
        <ActiveIcon size={16} />
      </button>
      {open && (
        <div className="chrome-switcher__menu" role="listbox" aria-label={t("shell.themeMenu")}>
          {THEME_PREFERENCES.map((id) => {
            const Icon = THEME_ICONS[id];
            return (
              <button
                key={id}
                type="button"
                role="option"
                aria-selected={id === preference}
                className={id === preference ? "is-active" : ""}
                onClick={() => {
                  onChange(id);
                  setOpen(false);
                }}
              >
                <Icon size={15} />
                <span>{t(THEME_LABELS[id])}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
