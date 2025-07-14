// api/admin/messages.js
// Import messages from submit.js (this is a limitation - you'll need a database)
let messages = []; // This will be empty since it's a different instance

// Admin credentials
const ADMIN_CONFIG = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'changeme123'
};

// Admin authentication
function authenticateAdmin(req) {
  const { username, password } = req.query;
  
  if (!username || !password || username !== ADMIN_CONFIG.username || password !== ADMIN_CONFIG.password) {
    return false;
  }
  
  return true;
}

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  
  // Authenticate admin
  if (!authenticateAdmin(req)) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }
  
  if (req.method === 'GET') {
    try {
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
      
      res.status(200).json({ 
        success: true,
        messages: messages.slice(0, 50),
        analytics,
        total: messages.length 
      });
      
    } catch (error) {
      console.error('Error fetching messages:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  } else if (req.method === 'DELETE') {
    try {
      const { id } = req.query;
      
      const filteredMessages = messages.filter(msg => msg.id !== id);
      
      if (filteredMessages.length === messages.length) {
        return res.status(404).json({ error: 'Message not found' });
      }
      
      messages = filteredMessages;
      console.log(`Message ${id} deleted by admin`);
      
      res.status(200).json({ success: true, message: 'Message deleted successfully' });
      
    } catch (error) {
      console.error('Error deleting message:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}
