// Fixture for fatal-exit.test.mjs. Not a test itself.
import http from 'node:http';
import { logEvent } from '../../src/lib/log.ts';
import { createFatalErrorHandler, installFatalErrorHandlers } from '../../src/lib/process-safety.ts';

const mode = process.env.FIXTURE_MODE ?? 'reject';
const drainMs = Number(process.env.FIXTURE_DRAIN_MS ?? 2_000);

const server = http.createServer((request, response) => {
  if (request.url === '/hang') return; // never answered: keeps a connection open while draining
  response.end('ok');
});

server.listen(0, '127.0.0.1', () => {
  installFatalErrorHandlers(
    process,
    createFatalErrorHandler({
      closeServer: (done) => {
        server.close(() => done());
        server.closeIdleConnections?.();
      },
      log: logEvent,
      exit: (code) => process.exit(code),
      drainMs,
    }),
  );
  console.log('FIXTURE_READY');

  const { port } = server.address() as { port: number };
  if (mode === 'hang') http.get({ host: '127.0.0.1', port, path: '/hang' }).on('error', () => {});

  setTimeout(() => {
    if (mode === 'throw') throw new Error('fixture uncaught exception');
    void Promise.reject(new Error('fixture unhandled rejection with Bearer abc123secret'));
  }, 100);
});
