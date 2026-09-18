import { useEffect, useRef } from "react";
import { EditorView, basicSetup } from "codemirror";
import { json } from "@codemirror/lang-json";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";

const vaultHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: tags.propertyName, color: "var(--text)" },
    { tag: tags.string, color: "var(--primary)" },
    { tag: [tags.number, tags.bool, tags.null], color: "var(--success)" },
    { tag: tags.punctuation, color: "var(--secondary)" },
    { tag: tags.invalid, color: "var(--danger)" },
  ]),
);

export function CodeEditor({
  value,
  onChange,
  label,
  invalid,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  invalid: boolean;
}) {
  const host = useRef<HTMLDivElement>(null);
  const editor = useRef<EditorView | null>(null);
  const change = useRef(onChange);
  change.current = onChange;
  useEffect(() => {
    const view = new EditorView({
      doc: value,
      parent: host.current!,
      extensions: [
        basicSetup,
        json(),
        vaultHighlight,
        EditorView.lineWrapping,
        EditorView.contentAttributes.of({
          "aria-label": label,
          "aria-describedby": "json-help",
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) change.current(update.state.doc.toString());
        }),
      ],
    });
    editor.current = view;
    return () => {
      view.destroy();
      editor.current = null;
    };
  }, []);
  useEffect(() => {
    const view = editor.current;
    if (view && value !== view.state.doc.toString())
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: value },
      });
  }, [value]);
  useEffect(() => {
    editor.current?.contentDOM.setAttribute("aria-invalid", String(invalid));
  }, [invalid]);
  return <div ref={host} className="code-editor" />;
}
