import {
  cloneElement,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type HTMLAttributes,
  type ReactElement,
} from "react";
import { createPortal } from "react-dom";

// The child must be a DOM element; cloning keeps flex/grid layout unchanged.
export function Tooltip({
  content,
  children,
}: {
  content: string;
  children: ReactElement<HTMLAttributes<HTMLElement>>;
}) {
  const id = useId();
  const anchor = useRef<HTMLElement | null>(null);
  const popup = useRef<HTMLDivElement>(null);
  const timer = useRef<number | undefined>(undefined);
  const focused = useRef(false);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0 });
  const clearTimer = () => window.clearTimeout(timer.current);
  const close = () => {
    clearTimer();
    setOpen(false);
  };
  const show = (element: HTMLElement) => {
    clearTimer();
    anchor.current = element;
    document.dispatchEvent(
      new CustomEvent("vault-tooltip-open", { detail: id }),
    );
    setOpen(true);
  };
  const leave = () => {
    clearTimer();
    timer.current = window.setTimeout(() => {
      if (!focused.current) setOpen(false);
    }, 200);
  };

  useEffect(() => {
    const otherOpened = (event: Event) => {
      if ((event as CustomEvent<string>).detail !== id) close();
    };
    document.addEventListener("vault-tooltip-open", otherOpened);
    return () => {
      clearTimer();
      document.removeEventListener("vault-tooltip-open", otherOpened);
    };
  }, [id]);

  useLayoutEffect(() => {
    if (!open) return;
    const update = () => {
      if (!anchor.current || !popup.current) return;
      const rect = anchor.current.getBoundingClientRect();
      const tip = popup.current.getBoundingClientRect();
      const margin = 8;
      const below = rect.bottom + margin;
      setPosition({
        left: Math.max(
          margin,
          Math.min(
            rect.left + (rect.width - tip.width) / 2,
            window.innerWidth - tip.width - margin,
          ),
        ),
        top: Math.max(
          margin,
          Math.min(
            below + tip.height <= window.innerHeight - margin
              ? below
              : rect.top - tip.height - margin,
            window.innerHeight - tip.height - margin,
          ),
        ),
      });
    };
    update();
    const observer = new ResizeObserver(update);
    if (popup.current) observer.observe(popup.current);
    if (anchor.current) observer.observe(anchor.current);
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    // Capture before the modal's native bubbling Escape handler.
    const escape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopImmediatePropagation();
      close();
    };
    window.addEventListener("keydown", escape, true);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
      window.removeEventListener("keydown", escape, true);
    };
  }, [open, content]);

  const props = children.props;
  return (
    <>
      {cloneElement(children, {
        "aria-describedby":
          [props["aria-describedby"], open ? id : undefined]
            .filter(Boolean)
            .join(" ") || undefined,
        onMouseEnter: (event) => {
          props.onMouseEnter?.(event);
          show(event.currentTarget);
        },
        onMouseLeave: (event) => {
          props.onMouseLeave?.(event);
          leave();
        },
        onFocus: (event) => {
          props.onFocus?.(event);
          focused.current = true;
          show(event.currentTarget);
        },
        onBlur: (event) => {
          props.onBlur?.(event);
          focused.current = false;
          close();
        },
        onClick: (event) => {
          close();
          props.onClick?.(event);
        },
      })}
      {open &&
        createPortal(
          <div
            ref={popup}
            id={id}
            role="tooltip"
            className="tooltip"
            style={position}
            onMouseEnter={clearTimer}
            onMouseLeave={leave}
          >
            {content}
          </div>,
          document.body,
        )}
    </>
  );
}
