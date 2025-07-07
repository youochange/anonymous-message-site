const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
let PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many messages submitted, please try again later.' }
});

const MESSAGES_FILE = path.join(__dirname, 'messages.json');
const ADMIN_FILE = path.join(__dirname, 'admin.json');

// Initialize data files
async function initializeFiles() {
  try {
    await fs.access(MESSAGES_FILE);
  } catch {
    await fs.writeFile(MESSAGES_FILE, JSON.stringify([]));
  }
  
  try {
    await fs.access(ADMIN_FILE);
  } catch {
    const adminData = {
      username: 'admin',
      password: 'changeme123',
      sessionSecret: 'your-secret-key-here'
    };
    await fs.writeFile(ADMIN_FILE, JSON.stringify(adminData, null, 2));
  }
}

// Helper functions
async function readMessages() {
  try {
    const data = await fs.readFile(MESSAGES_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

async function saveMessages(messages) {
  await fs.writeFile(MESSAGES_FILE, JSON.stringify(messages, null, 2));
}

// IP Geolocation function (using a free API)
async function getLocationFromIP(ip) {
  try {
    // Remove IPv6 prefix if present
    const cleanIP = ip.replace(/^::ffff:/, '');
    if (cleanIP === '127.0.0.1' || cleanIP === '::1') {
      return { country: 'Local', city: 'Local', region: 'Local' };
    }
    
    const response = await fetch(`http://ip-api.com/json/${cleanIP}`);
    const data = await response.json();
    
    if (data.status === 'success') {
      return {
        country: data.country,
        city: data.city,
        region: data.regionName,
        timezone: data.timezone,
        isp: data.isp
      };
    }
  } catch (error) {
    console.error('Error getting location:', error);
  }
  return null;
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

// Generate unique fingerprint for tracking return visitors
function generateFingerprint(req) {
  const data = [
    req.ip,
    req.get('User-Agent'),
    req.get('Accept-Language'),
    req.get('Accept-Encoding')
  ].join('|');
  
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// Enhanced message submission endpoint
app.post('/submit', limiter, async (req, res) => {
  try {
    const { message, name } = req.body;
    
    // Validation
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'Message is required' });
    }
    if (message.length > 1000) {
      return res.status(400).json({ error: 'Message too long' });
    }
    if (name && name.length > 100) {
      return res.status(400).json({ error: 'Name too long' });
    }

    // Get IP address
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
    
    // Get location data
    const location = await getLocationFromIP(ip);
    
    // Parse user agent
    const userAgentInfo = parseUserAgent(req.get('User-Agent'));
    
    // Generate fingerprint
    const fingerprint = generateFingerprint(req);
    
    // Create comprehensive message object
    const messageObj = {
      id: Date.now().toString(),
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
        connection: req.get('Connection'),
        dnt: req.get('DNT'), // Do Not Track
        secFetchSite: req.get('Sec-Fetch-Site'),
        secFetchMode: req.get('Sec-Fetch-Mode'),
        secFetchUser: req.get('Sec-Fetch-User'),
        secFetchDest: req.get('Sec-Fetch-Dest')
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
        multipleSubmissions: false // Will be updated below
      }
    };

    // Read existing messages
    const messages = await readMessages();
    
    // Check for multiple submissions from same fingerprint
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
    
    // Log submission with key details
    console.log(`New message from ${messageObj.name} (${messageObj.location?.city || 'Unknown location'})`);
    console.log(`Device: ${messageObj.device} | Browser: ${messageObj.browser} | OS: ${messageObj.os}`);
    console.log(`Message: ${message.substring(0, 50)}...`);
    
    res.json({ 
      msg: 'Message submitted successfully! Thank you for your message.',
      id: messageObj.id 
    });
    
  } catch (error) {
    console.error('Error submitting message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Enhanced admin endpoint with analytics
app.get('/admin/messages', async (req, res) => {
  try {
    const { username, password } = req.query;
    
    const adminData = JSON.parse(await fs.readFile(ADMIN_FILE, 'utf8'));
    
    if (username !== adminData.username || password !== adminData.password) {
      return res.status(401).json({ error: 'Unauthorized' });
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
      // Countries
      const country = msg.location?.country || 'Unknown';
      analytics.countries[country] = (analytics.countries[country] || 0) + 1;
      
      // Browsers
      analytics.browsers[msg.browser] = (analytics.browsers[msg.browser] || 0) + 1;
      
      // Devices
      analytics.devices[msg.device] = (analytics.devices[msg.device] || 0) + 1;
      
      // Hourly distribution
      const hour = new Date(msg.timestamp).getHours();
      analytics.hourlyDistribution[hour] = (analytics.hourlyDistribution[hour] || 0) + 1;
    });
    
    res.json({ 
      messages: messages.slice(0, 50), // Only send first 50 for performance
      analytics,
      total: messages.length 
    });
    
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete message endpoint
app.delete('/admin/messages/:id', async (req, res) => {
  try {
    const { username, password } = req.query;
    const { id } = req.params;
    
    const adminData = JSON.parse(await fs.readFile(ADMIN_FILE, 'utf8'));
    
    if (username !== adminData.username || password !== adminData.password) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const messages = await readMessages();
    const filteredMessages = messages.filter(msg => msg.id !== id);
    
    if (filteredMessages.length === messages.length) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    await saveMessages(filteredMessages);
    res.json({ msg: 'Message deleted successfully' });
    
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Find available port
function findAvailablePort(startPort, maxPort = 65535) {
  return new Promise((resolve, reject) => {
    const server = require('net').createServer();
    
    server.listen(startPort, () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        if (startPort < maxPort) {
          resolve(findAvailablePort(startPort + 1, maxPort));
        } else {
          reject(new Error('No available ports found'));
        }
      } else {
        reject(err);
      }
    });
  });
}

// Start server
async function startServer() {
  try {
    await initializeFiles();
    
    try {
      PORT = await findAvailablePort(PORT);
    } catch (error) {
      console.error('Error finding available port:', error);
      process.exit(1);
    }
    
    app.listen(PORT, () => {
      console.log(`🚀 Enhanced Anonymous Message Server running on port ${PORT}`);
      console.log(`📱 Visit: http://localhost:${PORT}`);
      console.log(`🔧 Admin panel: http://localhost:${PORT}/admin/messages?username=admin&password=changeme123`);
      console.log(`⚠️  Remember to change the default admin credentials!`);
      console.log(`📊 Enhanced tracking enabled - collecting comprehensive user data`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();