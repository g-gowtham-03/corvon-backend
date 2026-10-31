import { config } from './config.js';

export async function sendOtp({ type, destination, code }) {
  const body = `Your CORVON RECOVERY verification code is ${code}. It expires in 5 minutes.`;
  if (type === 'email') {
    if (!config.RESEND_API_KEY || !config.EMAIL_FROM) throw new Error('EMAIL_DELIVERY_NOT_CONFIGURED');
    const response = await fetch(config.RESEND_API_URL, { method: 'POST', headers: { Authorization: `Bearer ${config.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: config.EMAIL_FROM, to: [destination], subject: 'CORVON RECOVERY verification code', text: body }) });
    if (!response.ok) throw new Error('EMAIL_DELIVERY_FAILED');
    return;
  }
  if (!config.TWILIO_ACCOUNT_SID || !config.TWILIO_AUTH_TOKEN || !config.TWILIO_FROM_NUMBER) throw new Error('SMS_DELIVERY_NOT_CONFIGURED');
  const auth = Buffer.from(`${config.TWILIO_ACCOUNT_SID}:${config.TWILIO_AUTH_TOKEN}`).toString('base64');
  const params = new URLSearchParams({ From: config.TWILIO_FROM_NUMBER, To: destination, Body: body });
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${config.TWILIO_ACCOUNT_SID}/Messages.json`, { method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: params });
  if (!response.ok) throw new Error('SMS_DELIVERY_FAILED');
}
