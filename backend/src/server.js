const { createApp } = require('./app');
const { startInboundServer } = require('./mail/transport');
const { PRODUCTION, PORT } = require('./config');

if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET must be set. Generate one with: openssl rand -hex 32');

const app = createApp();
app.listen(PORT, () => console.log(`elusive running on http://localhost:${PORT}`));
startInboundServer();
