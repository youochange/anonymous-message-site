// api/submit.js
import crypto from 'crypto';

// For Vercel, you'll need to use a database or external storage
// Options: Vercel KV, MongoDB, PostgreSQL, etc.
// This example uses a simple in-memory storage (will reset on each deployment)
let messages = [];

// Simple rate limiting for serverless
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 15;
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return true;
  }
  
  const record = rateLimitMap.get(ip);
  if (now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return true;
  }
  
  if (record.count >= maxRequests) {
    return false;
  }
  
  record.count++;
  return true;
}

// IP Geolocation
async function getLocationFromIP(ip) {
  try {
    const cleanIP = ip.replace(/^::ffff:/, '');
    if (cleanIP === '127.0.0.1' || cleanIP === '::1' || cleanIP === 'localhost') {
      return { country: 'Local', city: 'Local', region: 'Local' };
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const response = await fetch(`http://ip-api.com/json/${cleanIP}`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.status === 'success') {
      return {
        country: data.country || 'Unknown',
        city: data.city || 'Unknown',
        region: data.regionName || 'Unknown',
        timezone: data.timezone,
        isp: data.isp
      };
    }
  } catch (error) {
    console.error('Location lookup failed:', error);
  }
  return { country: 'Unknown', city: 'Unknown', region: 'Unknown' };
}

// Parse User Agent
function parseUserAgent(userAgent) {
  const info = {
    browser: 'Unknown',
    os: 'Unknown',
    device: 'Unknown',
    isMobile: false,
    isBot: false
  };
  
  if (!userAgent) return info;
  
  // Check for bots
  const botPatterns = ['bot', 'crawler', 'spider', 'scraper'];
  info.isBot = botPatterns.some(pattern => userAgent.toLowerCase().includes(pattern));
  
  // Browser detection
  if (userAgent.includes('Chrome')) info.browser = 'Chrome';
  else if (userAgent.includes('Firefox')) info.browser = 'Firefox';
  else if (userAgent.includes('Safari')) info.browser = 'Safari';
  else if (userAgent.includes('Edge')) info.browser = 'Edge';
  else if (userAgent.includes('Opera')) info.browser = 'Opera';
  
  // OS detection
  if (userAgent.includes('Windows')) info.os = 'Windows';
  else if (userAgent.includes('Mac')) info.os = 'macOS';
  else if (userAgent.includes('Linux')) info.os = 'Linux';
  else if (userAgent.includes('Android')) info.os = 'Android';
  else if (userAgent.includes('iOS')) info.os = 'iOS';
  
  // Device detection
  if (userAgent.includes('Mobile')) {
    info.device = 'Mobile';
    info.isMobile = true;
  } else if (userAgent.includes('Tablet')) {
    info.device = 'Tablet';
    info.isMobile = true;
  } else {
    info.device = 'Desktop';
  }
  
  return info;
}

// Generate unique fingerprint
function generateFingerprint(req) {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  const data = [
    ip,
    req.headers['user-agent'],
    req.headers['accept-language'],
    req.headers['accept-encoding']
  ].join('|');
  
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// Get real IP address
function getRealIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress ||
         'unknown';
}

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Check rate limit
  const ip = getRealIP(req);
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }
  
  try {
    console.log('=== SUBMISSION STARTED ===');
    console.log('Request body:', req.body);
    
    // Check if body exists and is an object
    if (!req.body || typeof req.body !== 'object') {
      console.log('Invalid request body:', req.body);
      return res.status(400).json({ 
        success: false,
        error: 'Invalid request body. Please send JSON data.' 
      });
    }
    
    const { message, name } = req.body;
    
    // Validation
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      console.log('Validation failed: Empty message. Received:', message);
      return res.status(400).json({ 
        success: false,
        error: 'Message is required and cannot be empty' 
      });
    }
    if (message.length > 1000) {
      console.log('Validation failed: Message too long');
      return res.status(400).json({ 
        success: false,
        error: 'Message too long (maximum 1000 characters)' 
      });
    }
    if (name && name.length > 100) {
      console.log('Validation failed: Name too long');
      return res.status(400).json({ 
        success: false,
        error: 'Name too long (maximum 100 characters)' 
      });
    }

    console.log('Validation passed');

    // Get user info
    const ip = getRealIP(req);
    const userAgentInfo = parseUserAgent(req.headers['user-agent']);
    const fingerprint = generateFingerprint(req);
    
    console.log('User info gathered:', { 
      ip, 
      browser: userAgentInfo.browser, 
      device: userAgentInfo.device,
      os: userAgentInfo.os,
      isMobile: userAgentInfo.isMobile,
      fingerprint
    });
    
    // Get location
    let location = { country: 'Unknown', city: 'Unknown', region: 'Unknown' };
    try {
      console.log('Looking up location for IP:', ip);
      location = await getLocationFromIP(ip);
      console.log('Location resolved:', location);
    } catch (error) {
      console.error('Location lookup failed:', error);
    }
    
    // Create message object
    const messageObj = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      message: message.trim(),
      name: name ? name.trim() : 'anonymous',
      timestamp: new Date().toISOString(),
      ip: ip,
      fingerprint: fingerprint,
      location: location,
      userAgent: req.headers['user-agent'] || 'Unknown',
      browser: userAgentInfo.browser,
      os: userAgentInfo.os,
      device: userAgentInfo.device,
      isMobile: userAgentInfo.isMobile,
      isBot: userAgentInfo.isBot,
      headers: {
        acceptLanguage: req.headers['accept-language'],
        acceptEncoding: req.headers['accept-encoding'],
        referer: req.headers.referer,
        origin: req.headers.origin
      },
      messageLength: message.length,
      hasName: !!name,
      submissionDay: new Date().toLocaleDateString(),
      submissionHour: new Date().getHours(),
      suspiciousActivity: {
        isBot: userAgentInfo.isBot,
        hasReferer: !!req.headers.referer,
        multipleSubmissions: false
      }
    };

    console.log('Message object created with ID:', messageObj.id);
    
    // Check for multiple submissions
    const previousSubmissions = messages.filter(msg => 
      msg.fingerprint === fingerprint && 
      new Date(msg.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
    );
    
    if (previousSubmissions.length > 0) {
      messageObj.suspiciousActivity.multipleSubmissions = true;
      messageObj.suspiciousActivity.previousSubmissions = previousSubmissions.length;
      console.log('Multiple submissions detected:', previousSubmissions.length);
    }
    
    // Add message to in-memory storage
    messages.unshift(messageObj);
    
    // Keep only last 1000 messages
    if (messages.length > 1000) {
      messages.splice(1000);
    }
    
    console.log('Message saved successfully');
    
    res.status(200).json({ 
      success: true,
      message: 'Message submitted successfully! Thank you for your message.',
      msg: 'Message submitted successfully! Thank you for your message.', // This fixes the 404 issue
      id: messageObj.id,
      status: 'OK',
      data: {
        messageId: messageObj.id,
        timestamp: messageObj.timestamp,
        name: messageObj.name,
        messageLength: messageObj.messageLength,
        totalMessages: messages.length,
        location: messageObj.location?.city || 'Unknown'
      }
    });
    
  } catch (error) {
    console.error('=== ERROR IN SUBMISSION ===');
    console.error('Error details:', error);
    
    res.status(500).json({ 
      success: false,
      error: 'Internal server error. Please try again later.',
      message: 'Something went wrong on our end.'
    });
  }
}