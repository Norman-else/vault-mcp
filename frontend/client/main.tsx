import { createRoot } from "react-dom/client";
import { StrictMode } from "react";
import { Session } from "./Session";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Session />
  </StrictMode>,
);
