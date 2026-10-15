"use client";
// Normal navigation target for the demo. Renders the same storefront as "/",
// so legitimate browsing of these pages returns 200 (the capture-proxy sensor
// then sees them as Normal traffic, not 404 errors).
import Home from "../page";

export default function Page() {
  return <Home />;
}
