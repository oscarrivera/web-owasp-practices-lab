import { createApp } from './app.js';
import { assertLocalVulnMode, listenHost, listenPort, vulnLabsEnabled } from './config.js';

const host = listenHost();
assertLocalVulnMode(host);

const app = createApp();
const port = listenPort();

app.listen(port, host, () => {
  console.info(`web-owasp-practices-lab listening on http://${host}:${port}`);
  console.info(`mode=${vulnLabsEnabled() ? 'vulnerable (opt-in)' : 'fixed (default)'}`);
  if (vulnLabsEnabled()) {
    console.warn('ENABLE_VULN_LABS=true. Localhost only. Do not expose this process.');
  }
});
