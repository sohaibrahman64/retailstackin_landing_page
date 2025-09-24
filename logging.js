const fs = require('fs');
const path = require('path');

// Ensure logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    try {
        fs.mkdirSync(logsDir, { recursive: true });
    } catch (err) {
        // As a last resort, log to console if directory creation fails
        console.error('Failed to create logs directory:', err.message);
    }
}

function getDateStamp(date = new Date()) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

let currentDate = getDateStamp();
let currentStream = createStream(currentDate);

function createStream(dateStamp) {
    const filename = path.join(logsDir, `app-${dateStamp}.log`);
    try {
        return fs.createWriteStream(filename, { flags: 'a', encoding: 'utf8' });
    } catch (err) {
        console.error('Failed to open log file:', err.message);
        return null;
    }
}

function rotateStreamIfNeeded() {
    const nowStamp = getDateStamp();
    if (nowStamp !== currentDate) {
        try {
            if (currentStream) {
                currentStream.end();
            }
        } catch (_) {}
        currentDate = nowStamp;
        currentStream = createStream(currentDate);
    }
}

const levelOrder = { error: 0, warn: 1, info: 2, http: 3, debug: 4 };
const envLevel = (process.env.LOG_LEVEL || 'info').toLowerCase();
const enabledLevelIndex = levelOrder[envLevel] ?? levelOrder.info;

function isLevelEnabled(level) {
    const idx = levelOrder[level] ?? levelOrder.info;
    return idx <= enabledLevelIndex;
}

function formatLine(level, message, meta) {
    const ts = new Date().toISOString();
    const base = { level, message };
    let metaText = '';
    if (meta && Object.keys(meta).length > 0) {
        try {
            metaText = ' ' + JSON.stringify(meta);
        } catch (_) {
            metaText = ' ' + String(meta);
        }
    }
    return `${ts} ${level.toUpperCase()} ${message}${metaText}\n`;
}

function writeLine(line) {
    rotateStreamIfNeeded();
    if (currentStream) {
        try {
            currentStream.write(line);
        } catch (err) {
            // Fallback to console to avoid losing logs
            console.error('Logger write failed:', err.message);
            try {
                process.stderr.write(line);
            } catch (_) {}
        }
    } else {
        try {
            process.stdout.write(line);
        } catch (_) {}
    }
}

function log(level, message, meta = {}) {
    if (!isLevelEnabled(level)) return;
    const line = formatLine(level, String(message), meta);
    writeLine(line);
}

const logger = {
    error(message, meta) { log('error', message, meta); },
    warn(message, meta) { log('warn', message, meta); },
    info(message, meta) { log('info', message, meta); },
    http(message, meta) { log('http', message, meta); },
    debug(message, meta) { log('debug', message, meta); },
    // Express middleware for basic request logging
    requestLogger(req, res, next) {
        const start = Date.now();
        const { method, originalUrl } = req;
        res.on('finish', () => {
            const durationMs = Date.now() - start;
            const statusCode = res.statusCode;
            log('http', `${method} ${originalUrl} ${statusCode} ${durationMs}ms`, {
                ip: req.ip,
                userAgent: req.headers['user-agent'] || undefined
            });
        });
        next();
    }
};

module.exports = logger;


