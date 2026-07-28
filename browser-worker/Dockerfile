# probectl browser-worker (S36, F15): a Playwright + Chromium image for the browser-
# synthetic fleet. Based on the official Playwright image (bundles a pinned,
# headless-ready Chromium + the OS deps), so the worker runs without host browser
# setup. The container runs one transaction per invocation; the probectl fleet owns
# concurrency, isolation (it kills the process on timeout), and worker recycling.
# Digest-pinned (U-061); keep the npm playwright version in lockstep with the tag.
FROM mcr.microsoft.com/playwright:v1.62.0-noble@sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07

WORKDIR /worker

# Install only the worker's deps (the base image already has the browsers).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY worker.mjs ./

# Run as the image's non-root user (the Playwright image provides "pwuser").
USER pwuser

# Reads the Script JSON on stdin, writes the Result JSON on stdout.
ENTRYPOINT ["node", "worker.mjs"]
