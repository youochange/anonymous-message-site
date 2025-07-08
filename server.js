const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Render-specific configurations
app.set('trust proxy', 1);

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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path.startsWith('/admin') || req.path === '/health'
});

// File paths
const DATA_DIR = process.env.RENDER_PERSISTENT_DISK || path.join(__dirname, 'data');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

// Debug file locations
console.log('=== FILE LOCATION DEBUG ===');
console.log('__dirname:', __dirname);
console.log('DATA_DIR:', DATA_DIR);
console.log('MESSAGES_FILE:', MESSAGES_FILE);
console.log('process.env.RENDER_PERSISTENT_DISK:', process.env.RENDER_PERSISTENT_DISK);

// Admin credentials
const ADMIN_CONFIG = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'changeme123',
  sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex')
};

// Validate admin credentials
function validateAdminConfig() {
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
    console.log('WARNING: Using default admin credentials! Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables!');
  }
  
  if (ADMIN_CONFIG.username === 'admin' && ADMIN_CONFIG.password === 'changeme123') {
    console.log('SECURITY WARNING: Using default admin credentials in production!');
  }
}

// Initialize data files
async function initializeFiles() {
  try {
    console.log('=== INITIALIZING FILES ===');
    console.log('Creating data directory:', DATA_DIR);
    await fs.mkdir(DATA_DIR, { recursive: true });
    
    try {
      await fs.access(MESSAGES_FILE);
      console.log('Messages file found at:', MESSAGES_FILE);
      
      // Check current file content
      const currentContent = await fs.readFile(MESSAGES_FILE, 'utf8');
      const currentMessages = JSON.parse(currentContent);
      console.log('Current messages count:', currentMessages.length);
    } catch {
      console.log('Messages file not found, creating new one at:', MESSAGES_FILE);
      await fs.writeFile(MESSAGES_FILE, JSON.stringify([]));
      console.log('Created new messages.json file');
    }
    
    validateAdminConfig();
    
  } catch (error) {
    console.error('Error initializing files:', error);
    throw error;
  }
}

// Helper functions
async function readMessages() {
  try {
    console.log('Reading messages from:', MESSAGES_FILE);
    const data = await fs.readFile(MESSAGES_FILE, 'utf8');
    const messages = JSON.parse(data);
    console.log('Successfully read', messages.length, 'messages');
    return messages;
  } catch (error) {
    console.error('Error reading messages:', error);
    return [];
  }
}

async function saveMessages(messages) {
  try {
    console.log('Saving', messages.length, 'messages to:', MESSAGES_FILE);
    await fs.writeFile(MESSAGES_FILE, JSON.stringify(messages, null, 2));
    console.log('Successfully saved messages to file');
    
    // Verify the save
    const verifyData = await fs.readFile(MESSAGES_FILE, 'utf8');
    const verifyMessages = JSON.parse(verifyData);
    console.log('Verification: File now contains', verifyMessages.length, 'messages');
    
  } catch (error) {
    console.error('Error saving messages:', error);
    throw error;
  }
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
  const data = [
    req.ip,
    req.get('User-Agent'),
    req.get('Accept-Language'),
    req.get('Accept-Encoding')
  ].join('|');
  
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// Get real IP address
function getRealIP(req) {
  return req.ip || 
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket && req.connection.socket.remoteAddress) ||
         'unknown';
}

// Admin authentication middleware
function authenticateAdmin(req, res, next) {
  const { username, password } = req.query;
  
  if (!username || !password || username !== ADMIN_CONFIG.username || password !== ADMIN_CONFIG.password) {
    console.log('Unauthorized admin access attempt');
    return res.status(401).json({ error: 'Unauthorized access' });
  }
  
  next();
}

// Routes
app.post('/submit', limiter, async (req, res) => {
  console.log('=== SUBMISSION STARTED ===');
  console.log('Request body:', req.body);
  console.log('Request body type:', typeof req.body);
  console.log('Request IP:', getRealIP(req));
  console.log('Request headers:', {
    'user-agent': req.get('User-Agent'),
    'content-type': req.get('Content-Type'),
    'origin': req.get('Origin'),
    'referer': req.get('Referer')
  });
  
  // Set response headers early
  res.setHeader('Content-Type', 'application/json');
  
  try {
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
    const userAgentInfo = parseUserAgent(req.get('User-Agent'));
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
      userAgent: req.get('User-Agent') || 'Unknown',
      browser: userAgentInfo.browser,
      os: userAgentInfo.os,
      device: userAgentInfo.device,
      isMobile: userAgentInfo.isMobile,
      isBot: userAgentInfo.isBot,
      headers: {
        acceptLanguage: req.get('Accept-Language'),
        acceptEncoding: req.get('Accept-Encoding'),
        referer: req.get('Referer'),
        origin: req.get('Origin')
      },
      messageLength: message.length,
      hasName: !!name,
      submissionDay: new Date().toLocaleDateString(),
      submissionHour: new Date().getHours(),
      suspiciousActivity: {
        isBot: userAgentInfo.isBot,
        hasReferer: !!req.get('Referer'),
        multipleSubmissions: false
      }
    };

    console.log('Message object created with ID:', messageObj.id);
    console.log('Message preview:', message.substring(0, 100) + (message.length > 100 ? '...' : ''));

    // Read existing messages
    console.log('=== READING EXISTING MESSAGES ===');
    const messages = await readMessages();
    console.log('Existing messages count:', messages.length);
    
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
    
    // Add message
    console.log('=== ADDING MESSAGE TO ARRAY ===');
    messages.unshift(messageObj);
    console.log('Message added to array, new count:', messages.length);
    
    // Keep only last 1000 messages
    if (messages.length > 1000) {
      messages.splice(1000);
      console.log('Trimmed to 1000 messages');
    }
    
    // Save messages
    console.log('=== SAVING MESSAGES ===');
    await saveMessages(messages);
    console.log('Messages saved successfully');
    
    // Final verification
    console.log('=== FINAL VERIFICATION ===');
    const finalVerification = await readMessages();
    console.log('Final verification: File contains', finalVerification.length, 'messages');
    
    const lastMessage = finalVerification[0];
    if (lastMessage && lastMessage.id === messageObj.id) {
      console.log('✓ SUCCESS: New message is at the top of the file');
    } else {
      console.log('✗ WARNING: New message might not have been saved correctly');
    }
    
    // Log submission summary
    console.log('=== SUBMISSION SUMMARY ===');
    console.log(`From: ${messageObj.name} (${messageObj.location?.city || 'Unknown'})`);
    console.log(`Device: ${messageObj.device} | Browser: ${messageObj.browser} | OS: ${messageObj.os}`);
    console.log(`Message: "${message.substring(0, 50)}${message.length > 50 ? '...' : ''}"`);
    console.log(`Total messages: ${messages.length}`);
    console.log(`File path: ${MESSAGES_FILE}`);
    
    res.json({ 
      success: true,
      message: 'Message submitted successfully! Thank you for your message.',
      id: messageObj.id,
      status: 'OK',
      data: {
        messageId: messageObj.id,
        timestamp: messageObj.timestamp,
        name: messageObj.name,
        messageLength: messageObj.messageLength,
        totalMessages: messages.length,
        location: messageObj.location?.city || 'Unknown'
      },
      debug: {
        messagesCount: messages.length,
        filePath: MESSAGES_FILE,
        timestamp: new Date().toISOString(),
        messageId: messageObj.id
      }
    });
    
  } catch (error) {
    console.error('=== ERROR IN SUBMISSION ===');
    console.error('Error details:', error);
    console.error('Stack trace:', error.stack);
    
    // Ensure we always return a proper JSON response
    res.status(500).json({ 
      success: false,
      error: 'Internal server error. Please try again later.',
      message: 'Something went wrong on our end.',
      debug: process.env.NODE_ENV === 'development' ? {
        error: error.message,
        stack: error.stack
      } : undefined
    });
  }
});

app.get('/admin/messages', authenticateAdmin, async (req, res) => {
  try {
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
    
    console.log('Admin accessed messages dashboard');
    
    res.json({ 
      success: true,
      messages: messages.slice(0, 50),
      analytics,
      total: messages.length 
    });
    
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const messages = await readMessages();
    const filteredMessages = messages.filter(msg => msg.id !== id);
    
    if (filteredMessages.length === messages.length) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    await saveMessages(filteredMessages);
    console.log(`Message ${id} deleted by admin`);
    
    res.json({ success: true, message: 'Message deleted successfully' });
    
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/test', (req, res) => {
  console.log('=== TEST ENDPOINT HIT ===');
  console.log('Test endpoint hit:', {
    body: req.body,
    bodyType: typeof req.body,
    ip: getRealIP(req),
    userAgent: req.get('User-Agent'),
    contentType: req.get('Content-Type'),
    headers: req.headers
  });
  
  res.json({ 
    success: true, 
    message: 'Test endpoint working!',
    received: req.body,
    ip: getRealIP(req),
    timestamp: new Date().toISOString(),
    headers: {
      'content-type': req.get('Content-Type'),
      'user-agent': req.get('User-Agent')
    }
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development',
    dataDir: DATA_DIR,
    messagesFile: MESSAGES_FILE
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  console.log('404 - Endpoint not found:', req.method, req.path);
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server function
async function startServer() {
  try {
    await initializeFiles();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log('=== SERVER STARTED ===');
      console.log('Anonymous Message Server Started!');
      console.log(`Port: ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`Data Directory: ${DATA_DIR}`);
      console.log(`Messages File: ${MESSAGES_FILE}`);
      console.log(`Admin Username: ${ADMIN_CONFIG.username}`);
      
      if (process.env.NODE_ENV === 'production') {
        console.log('Production mode enabled');
        console.log('Using environment variables for admin credentials');
      } else {
        console.log('Development mode - set NODE_ENV=production for deployment');
      }
      
      console.log('Ready to receive messages!');
      console.log('=== SERVER READY ===');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

// Start the server
startServer();