import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { App } from "./App";
import { applyTheme, resolveTheme } from "./lib/theme";
import "./styles.css";

// Apply the persisted/system theme before first paint to avoid a flash.
applyTheme(resolveTheme());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);

