const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Render-specific configurations
app.set('trust proxy', 1); // Essential for Render's proxy setup

// Enhanced CORS for Render deployment
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? [
        process.env.FRONTEND_URL, 
        process.env.DOMAIN_URL,
        /\.onrender\.com$/, // Allow all Render subdomains
        /^https?:\/\/localhost(:\d+)?$/ // Allow localhost for testing
      ]
    : true,
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Security headers for production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });
}

// Rate limiting - optimized for Render
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Slightly more lenient for global users
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path.startsWith('/admin') || req.path === '/health'
});

// File paths - check for persistent disk or use temp
const DATA_DIR = process.env.RENDER_PERSISTENT_DISK || __dirname;
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

// Initialize data files with better error handling
async function initializeFiles() {
  try {
    // Ensure data directory exists
    await fs.mkdir(DATA_DIR, { recursive: true });
    
    // Initialize messages file
    try {
      await fs.access(MESSAGES_FILE);
    } catch {
      await fs.writeFile(MESSAGES_FILE, JSON.stringify([]));
      console.log('📁 Created new messages.json file');
    }
    
    // Initialize admin file
    try {
      await fs.access(ADMIN_FILE);
    } catch {
      const adminData = {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'changeme123',
        sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
        createdAt: new Date().toISOString()
      };
      await fs.writeFile(ADMIN_FILE, JSON.stringify(adminData, null, 2));
      console.log('🔐 Created new admin.json file');
      
      if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
        console.log('⚠️  WARNING: Using default admin credentials! Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables!');
      }
    }
  } catch (error) {
    console.error('Location lookup failed:', error);
  }
  return { country: 'Unknown', city: 'Unknown', region: 'Unknown' };
}

// Parse User Agent for detailed info
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

// Generate unique fingerprint for tracking
function generateFingerprint(req) {
  const data = [
    req.ip,
    req.get('User-Agent'),
    req.get('Accept-Language'),
    req.get('Accept-Encoding')
  ].join('|');
  
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// Get real IP address - optimized for Render
function getRealIP(req) {
  return req.ip || 
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket && req.connection.socket.remoteAddress) ||
         'unknown';
}

// Message submission endpoint
app.post('/submit', limiter, async (req, res) => {
  try {
    const { message, name } = req.body;
    
    // Enhanced validation
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message is required and cannot be empty' });
    }
    if (message.length > 1000) {
      return res.status(400).json({ error: 'Message too long (maximum 1000 characters)' });
    }
    if (name && name.length > 100) {
      return res.status(400).json({ error: 'Name too long (maximum 100 characters)' });
    }

    // Get IP and user info
    const ip = getRealIP(req);
    const userAgentInfo = parseUserAgent(req.get('User-Agent'));
    const fingerprint = generateFingerprint(req);
    
    // Get location (non-blocking)
    let location = { country: 'Unknown', city: 'Unknown', region: 'Unknown' };
    try {
      location = await getLocationFromIP(ip);
    } catch (error) {
      console.error('Location lookup failed:', error);
    }
    
    // Create message object
    const messageObj = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      message: message.trim(),
      name: name ? name.trim() : 'anonymous',
      timestamp: new Date().toISOString(),
      
      // Network Information
      ip: ip,
      fingerprint: fingerprint,
      location: location,
      
      // Device/Browser Information
      userAgent: req.get('User-Agent') || 'Unknown',
      browser: userAgentInfo.browser,
      os: userAgentInfo.os,
      device: userAgentInfo.device,
      isMobile: userAgentInfo.isMobile,
      isBot: userAgentInfo.isBot,
      
      // Request Headers
      headers: {
        acceptLanguage: req.get('Accept-Language'),
        acceptEncoding: req.get('Accept-Encoding'),
        referer: req.get('Referer'),
        origin: req.get('Origin'),
        userAgent: req.get('User-Agent')
      },
      
      // Additional Metadata
      messageLength: message.length,
      hasName: !!name,
      submissionDay: new Date().toLocaleDateString(),
      submissionHour: new Date().getHours(),
      
      // Security flags
      suspiciousActivity: {
        isBot: userAgentInfo.isBot,
        hasReferer: !!req.get('Referer'),
        multipleSubmissions: false
      }
    };

    // Read existing messages
    const messages = await readMessages();
    
    // Check for multiple submissions
    const previousSubmissions = messages.filter(msg => 
      msg.fingerprint === fingerprint && 
      new Date(msg.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
    );
    
    if (previousSubmissions.length > 0) {
      messageObj.suspiciousActivity.multipleSubmissions = true;
      messageObj.suspiciousActivity.previousSubmissions = previousSubmissions.length;
    }
    
    // Add message to array
    messages.unshift(messageObj);
    
    // Keep only last 1000 messages
    if (messages.length > 1000) {
      messages.splice(1000);
    }
    
    // Save messages
    await saveMessages(messages);
    
    // Log submission
    console.log('✅ New message submitted:');
    console.log(`   From: ${messageObj.name} (${messageObj.location?.city || 'Unknown'})`);
    console.log(`   Device: ${messageObj.device} | Browser: ${messageObj.browser} | OS: ${messageObj.os}`);
    console.log(`   Message: "${message.substring(0, 50)}${message.length > 50 ? '...' : ''}"`);
    console.log(`   Total messages: ${messages.length}`);
    
    res.json({ 
      success: true,
      message: 'Message submitted successfully! Thank you for your message.',
      id: messageObj.id 
    });
    
  } catch (error) {
    console.error('❌ Error submitting message:', error);
    res.status(500).json({ error: 'Internal server error. Please try again later.' });
  }
});

// Admin endpoint
app.get('/admin/messages', async (req, res) => {
  try {
    const { username, password } = req.query;
    
    let adminData;
    try {
      adminData = JSON.parse(await fs.readFile(ADMIN_FILE, 'utf8'));
    } catch (error) {
      console.error('Error reading admin file:', error);
      return res.status(500).json({ error: 'Server configuration error' });
    }
    
    if (!username || !password || username !== adminData.username || password !== adminData.password) {
      console.log('❌ Unauthorized admin access attempt');
      return res.status(401).json({ error: 'Unauthorized access' });
    }
    
    const messages = await readMessages();
    
    // Generate analytics
    const analytics = {
      total: messages.length,
      today: messages.filter(msg => 
        new Date(msg.timestamp).toDateString() === new Date().toDateString()
      ).length,
      uniqueVisitors: new Set(messages.map(msg => msg.fingerprint)).size,
      countries: {},
      browsers: {},
      devices: {},
      hourlyDistribution: {},
      suspiciousMessages: messages.filter(msg => 
        msg.suspiciousActivity?.isBot || msg.suspiciousActivity?.multipleSubmissions
      ).length
    };
    
    // Count by categories
    messages.forEach(msg => {
      const country = msg.location?.country || 'Unknown';
      analytics.countries[country] = (analytics.countries[country] || 0) + 1;
      
      analytics.browsers[msg.browser] = (analytics.browsers[msg.browser] || 0) + 1;
      analytics.devices[msg.device] = (analytics.devices[msg.device] || 0) + 1;
      
      const hour = new Date(msg.timestamp).getHours();
      analytics.hourlyDistribution[hour] = (analytics.hourlyDistribution[hour] || 0) + 1;
    });
    
    console.log('✅ Admin accessed messages dashboard');
    
    res.json({ 
      success: true,
      messages: messages.slice(0, 50),
      analytics,
      total: messages.length 
    });
    
  } catch (error) {
    console.error('❌ Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete message endpoint
app.delete('/admin/messages/:id', async (req, res) => {
  try {
    const { username, password } = req.query;
    const { id } = req.params;
    
    const adminData = JSON.parse(await fs.readFile(ADMIN_FILE, 'utf8'));
    
    if (!username || !password || username !== adminData.username || password !== adminData.password) {
      return res.status(401).json({ error: 'Unauthorized access' });
    }
    
    const messages = await readMessages();
    const filteredMessages = messages.filter(msg => msg.id !== id);
    
    if (filteredMessages.length === messages.length) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    await saveMessages(filteredMessages);
    console.log(`🗑️  Message ${id} deleted by admin`);
    
    res.json({ success: true, message: 'Message deleted successfully' });
    
  } catch (error) {
    console.error('❌ Error deleting message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Test endpoint
app.post('/test', (req, res) => {
  console.log('🧪 Test endpoint hit:', {
    body: req.body,
    ip: getRealIP(req),
    userAgent: req.get('User-Agent'),
    headers: req.headers
  });
  res.json({ 
    success: true, 
    message: 'Test endpoint working!',
    received: req.body,
    ip: getRealIP(req),
    timestamp: new Date().toISOString()
  });
});

// Health check - important for Render
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  console.log('❌ 404 - Endpoint not found:', req.method, req.path);
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
async function startServer() {
  try {
    await initializeFiles();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log('🚀 Anonymous Message Server Started on Render!');
      console.log(`📱 Port: ${PORT}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔒 Data Directory: ${DATA_DIR}`);
      
      if (process.env.NODE_ENV === 'production') {
        console.log('✅ Production mode enabled');
        console.log('🔐 Using environment variables for admin credentials');
      } else {
        console.log('⚠️  Development mode - set NODE_ENV=production for deployment');
      }
      
      console.log('📊 Ready to receive messages!');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

startServer();.error('❌ Error initializing files:', error);
    throw error;
  }
}

// Helper functions with better error handling
async function readMessages() {
  try {
    const data = await fs.readFile(MESSAGES_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading messages:', error);
    return [];
  }
}

async function saveMessages(messages) {
  try {
    await fs.writeFile(MESSAGES_FILE, JSON.stringify(messages, null, 2));
  } catch (error) {
    console.error('Error saving messages:', error);
    throw error;
  }
}

// IP Geolocation with timeout and fallback
async function getLocationFromIP(ip) {
  try {
    const cleanIP = ip.replace(/^::ffff:/, '');
    if (cleanIP === '127.0.0.1' || cleanIP === '::1' || cleanIP === 'localhost') {
      return { country: 'Local', city: 'Local', region: 'Local' };
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // Reduced timeout for Render
    
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
    console