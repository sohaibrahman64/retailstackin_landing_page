const nodemailer = require('nodemailer');
const logger = require('./logging');

// Create a reusable transporter using environment configuration
// Expected env vars:
// SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE ("true"/"false"), FROM_EMAIL, OWNER_EMAIL

function createTransporter() {
    const port = Number(process.env.SMTP_PORT || 587);
    const secure = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || port === 465;

    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port,
        secure,
        auth: process.env.SMTP_USER ? {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        } : undefined
    });

    return transporter;
}

const transporter = createTransporter();

async function sendMail(options) {
    const from = process.env.FROM_EMAIL || 'no-reply@retailstack.in';
    const mailOptions = { from, ...options };
    try {
        const info = await transporter.sendMail(mailOptions);
        logger.info('Email sent', { messageId: info.messageId, to: mailOptions.to, subject: mailOptions.subject });
        return info;
    } catch (err) {
        logger.error('Email send failed', { error: err && err.message ? err.message : err, to: mailOptions.to, subject: mailOptions.subject });
        throw err;
    }
}

function buildOwnerEmail(data) {
    const subject = 'New RetailStackIn signup';
    const text = `A new user has signed up:\n\n` +
        `Name: ${data.name}\n` +
        `Email: ${data.email}\n` +
        `Phone: ${data.phone_no}\n` +
        `Business Type: ${data.business_type}\n` +
        `GST Type: ${data.gst_type}\n` +
        `City: ${data.city}`;
    const html = `<h2>New RetailStackIn signup</h2>` +
        `<ul>` +
        `<li><strong>Name:</strong> ${escapeHtml(data.name)}</li>` +
        `<li><strong>Email:</strong> ${escapeHtml(data.email)}</li>` +
        `<li><strong>Phone:</strong> ${escapeHtml(data.phone_no)}</li>` +
        `<li><strong>Business Type:</strong> ${escapeHtml(data.business_type)}</li>` +
        `<li><strong>GST Type:</strong> ${escapeHtml(data.gst_type)}</li>` +
        `<li><strong>City:</strong> ${escapeHtml(data.city)}</li>` +
        `</ul>`;
    return { subject, text, html };
}

function buildUserEmail(data) {
    const subject = 'Thanks for signing up for RetailStackIn';
    const text = `Hi ${data.name},\n\nThanks for signing up! Our team will contact you shortly once RetailStackIn is launched.\n\n— RetailStackIn`;
    const html = `<p>Hi ${escapeHtml(data.name)},</p>` +
        `<p>Thanks for signing up! Our team will contact you shortly once RetailStackIn is launched.</p>` +
        `<p>— RetailStackIn</p>`;
    return { subject, text, html };
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function sendOwnerNotification(data) {
    const ownerEmail = process.env.OWNER_EMAIL || 'sohaib.rahman64@gmail.com';
    const content = buildOwnerEmail(data);
    return sendMail({ to: ownerEmail, subject: content.subject, text: content.text, html: content.html });
}

async function sendUserWelcome(data) {
    const content = buildUserEmail(data);
    return sendMail({ to: data.email, subject: content.subject, text: content.text, html: content.html });
}

module.exports = {
    sendOwnerNotification,
    sendUserWelcome
};


