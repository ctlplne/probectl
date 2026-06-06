# probectl browser-worker (S36, F15): a Playwright + Chromium image for the browser-
# synthetic fleet. Based on the official Playwright image (bundles a pinned,
# headless-ready Chromium + the OS deps), so the worker runs without host browser
# setup. The container runs one transaction per invocation; the probectl fleet owns
# concurrency, isolation (it kills the process on timeout), and worker recycling.
# Digest-pinned (U-061); keep the npm playwright version in lockstep with the tag.
FROM mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948

WORKDIR /worker

# Install only the worker's deps (the base image already has the browsers).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY worker.mjs ./

# Run as the image's non-root user (the Playwright image provides "pwuser").
USER pwuser

# Reads the Script JSON on stdin, writes the Result JSON on stdout.
ENTRYPOINT ["node", "worker.mjs"]
