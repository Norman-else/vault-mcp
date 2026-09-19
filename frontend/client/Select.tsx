import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { createPortal } from "react-dom";
import { Icon } from "./components";

export function Select({
  id,
  label,
  value,
  options,
  onChange,
  disabled = false,
  popupMinWidth = 220,
}: {
  id: string;
  label?: string;
  value: string;
  options: {
    value: string;
    label: string;
    description?: string;
    badges?: string[];
  }[];
  onChange: (value: string) => void;
  disabled?: boolean;
  popupMinWidth?: number;
}) {
  const listId = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const popup = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [position, setPosition] = useState<CSSProperties>({});
  const selected = options.findIndex((option) => option.value === value);
  const expanded = open && !disabled && options.length > 0;
  const search = useRef({ text: "", time: 0 });
  function show() {
    setActive(Math.max(0, selected));
    setOpen(true);
  }
  function choose(index: number) {
    const option = options[index];
    if (!option) return;
    setOpen(false);
    trigger.current?.focus();
    if (option.value !== value) onChange(option.value);
  }
  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);
  useLayoutEffect(() => {
    if (!expanded) return;
    function positionPopup() {
      const rect = trigger.current?.getBoundingClientRect();
      if (!rect) return;
      const below = window.innerHeight - rect.bottom - 12;
      const above = rect.top - 12;
      const upwards = below < 220 && above > below;
      const width = Math.min(Math.max(rect.width, popupMinWidth), window.innerWidth - 16);
      setPosition({
        position: "fixed",
        width,
        left: Math.max(
          8,
          Math.min(
            rect.left,
            window.innerWidth - width - 8,
          ),
        ),
        top: upwards ? undefined : rect.bottom + 4,
        bottom: upwards ? window.innerHeight - rect.top + 4 : undefined,
        maxHeight: Math.max(40, Math.min(280, upwards ? above : below)),
      });
    }
    positionPopup();
    window.addEventListener("resize", positionPopup);
    window.addEventListener("scroll", positionPopup, true);
    const outside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (
        !trigger.current?.contains(target) &&
        !popup.current?.contains(target)
      )
        setOpen(false);
    };
    document.addEventListener("pointerdown", outside);
    return () => {
      window.removeEventListener("resize", positionPopup);
      window.removeEventListener("scroll", positionPopup, true);
      document.removeEventListener("pointerdown", outside);
    };
  }, [expanded, popupMinWidth]);
  useEffect(() => {
    if (expanded)
      popup.current?.children[active]?.scrollIntoView({ block: "nearest" });
  }, [expanded, active]);
  return (
    <div className="custom-select">
      <button
        ref={trigger}
        id={id}
        type="button"
        role="combobox"
        aria-label={label}
        className="select-trigger"
        disabled={disabled || !options.length}
        aria-haspopup="listbox"
        aria-expanded={expanded}
        aria-controls={expanded ? listId : undefined}
        aria-activedescendant={expanded ? `${listId}-${active}` : undefined}
        onClick={() => (expanded ? setOpen(false) : show())}
        onBlur={(event) => {
          if (!popup.current?.contains(event.relatedTarget)) setOpen(false);
        }}
        onKeyDownCapture={(event) => {
          if (event.key === "Escape" && expanded) {
            event.preventDefault();
            event.stopPropagation();
            setOpen(false);
          } else if (event.key === "Tab") setOpen(false);
          else if (
            ["Enter", " ", "ArrowDown", "ArrowUp", "Home", "End"].includes(
              event.key,
            )
          ) {
            event.preventDefault();
            event.stopPropagation();
            if (!expanded) show();
            else if (event.key === "Enter" || event.key === " ") choose(active);
            else if (event.key === "Home") setActive(0);
            else if (event.key === "End") setActive(options.length - 1);
            else
              setActive(
                (index) =>
                  (index +
                    (event.key === "ArrowDown" ? 1 : -1) +
                    options.length) %
                  options.length,
              );
          } else if (
            event.key.length === 1 &&
            !event.ctrlKey &&
            !event.metaKey &&
            !event.altKey
          ) {
            const now = Date.now();
            search.current.text =
              (now - search.current.time < 700 ? search.current.text : "") +
              event.key.toLowerCase();
            search.current.time = now;
            const index = options.findIndex((option) =>
              option.label.toLowerCase().startsWith(search.current.text),
            );
            if (index >= 0) {
              if (!expanded) setOpen(true);
              setActive(index);
            }
          }
        }}
      >
        <span>{options[selected]?.label ?? value}</span>
        <Icon name="chevron" />
      </button>
      {expanded &&
        createPortal(
          <div
            ref={popup}
            id={listId}
            role="listbox"
            aria-labelledby={id}
            className="select-popup"
            style={position}
            onMouseDown={(event) => event.preventDefault()}
          >
            {options.map((option, index) => (
              <div
                key={option.value}
                id={`${listId}-${index}`}
                role="option"
                aria-selected={option.value === value}
                className={`select-option${index === active ? " active" : ""}`}
                onMouseMove={() => setActive(index)}
                onClick={() => choose(index)}
              >
                <span className="select-option-content">
                  <span className="select-option-heading">
                    <span>{option.label}</span>
                    {option.badges?.map((badge) => (
                      <span className="select-option-badge" key={badge}>{badge}</span>
                    ))}
                  </span>
                  {option.description && (
                    <span className="select-option-description">{option.description}</span>
                  )}
                </span>
                {option.value === value && <Icon name="check" />}
              </div>
            ))}
          </div>,
          trigger.current?.closest(".modal") ?? document.body,
        )}
    </div>
  );
}
