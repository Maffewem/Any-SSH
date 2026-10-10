import { buildApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const { app, setup } = await buildApp(config);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}

await app.listen({ host: config.host, port: config.port });

if (setup.token) {
  // Printed only to the server console: whoever can read it controls this host anyway.
  console.log(
    [
      '',
      '================ Any-SSH first-run setup ================',
      ` Open ${config.allowedOrigins[0]}/ and create the administrator.`,
      ` Setup token: ${setup.token}`,
      '=========================================================',
      '',
    ].join('\n'),
  );
}
