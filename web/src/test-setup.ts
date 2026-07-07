import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// globals:false means RTL cannot auto-register cleanup — unmount after each test manually.
afterEach(() => {
  cleanup();
});
