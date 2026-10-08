import { useEffect, useId, useRef, useState } from "react";
import { Check, ChevronDown } from "lucide-react";

export default function KeySelect({
  id,
  label,
  keys,
  value,
  placeholder,
  disabled,
  onChange,
}) {
  const listId = useId();
  const container = useRef(null);
  const trigger = useRef(null);
  const typeahead = useRef({ text: "", time: 0 });
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const selected = keys.find((key) => key.id === value);
  const expanded = open && !disabled && keys.length > 0;

  useEffect(() => {
    if (!expanded) return;
    const closeOutside = (event) => {
      if (!container.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("pointerdown", closeOutside);
    return () => document.removeEventListener("pointerdown", closeOutside);
  }, [expanded]);

  useEffect(() => {
    if (expanded)
      document
        .getElementById(`${listId}-${active}`)
        ?.scrollIntoView({ block: "nearest" });
  }, [expanded, active, listId]);

  function show() {
    setActive(
      Math.max(
        0,
        keys.findIndex((key) => key.id === value),
      ),
    );
    setOpen(true);
  }
  function choose(key) {
    if (key.id !== value) onChange(key.id);
    setOpen(false);
    trigger.current?.focus();
  }
  function handleKeyDown(event) {
    if (disabled || !keys.length) return;
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      if (!expanded) {
        show();
        if (event.key === "Home") setActive(0);
        if (event.key === "End") setActive(keys.length - 1);
      } else {
        setActive((index) =>
          event.key === "Home"
            ? 0
            : event.key === "End"
              ? keys.length - 1
              : (index + (event.key === "ArrowDown" ? 1 : -1) + keys.length) %
                keys.length,
        );
      }
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (expanded) choose(keys[active] || keys[0]);
      else show();
    } else if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
    } else if (event.key === "Tab") {
      setOpen(false);
    } else if (
      event.key.length === 1 &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey
    ) {
      event.preventDefault();
      const now = Date.now();
      const text =
        (now - typeahead.current.time < 700 ? typeahead.current.text : "") +
        event.key.toLowerCase();
      typeahead.current = { text, time: now };
      const index = keys.findIndex(
        (key) =>
          key.name.toLowerCase().startsWith(text) ||
          key.email?.toLowerCase().startsWith(text),
      );
      if (!expanded) show();
      if (index >= 0) setActive(index);
    }
  }

  return (
    <div
      className="key-select"
      ref={container}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <button
        ref={trigger}
        id={id}
        type="button"
        className={`key-select-trigger ${expanded ? "is-open" : ""}`}
        role="combobox"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={Boolean(expanded)}
        aria-controls={expanded ? listId : undefined}
        aria-activedescendant={expanded ? `${listId}-${active}` : undefined}
        disabled={disabled}
        onClick={() => (expanded ? setOpen(false) : show())}
        onKeyDown={handleKeyDown}
      >
        <span className="key-select-value">
          {selected ? (
            <>
              <strong>{selected.name}</strong>
              {selected.email && <span>{selected.email}</span>}
            </>
          ) : (
            placeholder
          )}
        </span>
        <ChevronDown size={17} />
      </button>
      {expanded && (
        <ul
          id={listId}
          className="key-select-menu"
          role="listbox"
          aria-label={label}
        >
          {keys.map((key, index) => (
            <li
              id={`${listId}-${index}`}
              key={key.id}
              role="option"
              aria-selected={key.id === value}
              className={`key-select-option ${index === active ? "is-active" : ""}`}
              onPointerMove={() => setActive(index)}
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => choose(key)}
            >
              <div className="key-option-details">
                <strong>{key.name}</strong>
                {key.email && <span>{key.email}</span>}
              </div>
              <span className="key-option-check">
                {key.id === value && <Check size={17} />}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
