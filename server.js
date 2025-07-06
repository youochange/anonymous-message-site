const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com', 'https://www.yourdomain.com'] 
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    error: 'Too many messages sent. Please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/submit', limiter);

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static('public'));

// Validation middleware
const validateMessage = [
  body('message')
    .isLength({ min: 1, max: 1000 })
    .withMessage('Message must be between 1 and 1000 characters')
    .trim()
    .escape(),
  body('name')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Name must be less than 100 characters')
    .trim()
    .escape(),
];

// Utility functions
const getMessagesFilePath = () => path.join(__dirname, 'data', 'messages.json');

const ensureDataDirectory = async () => {
  const dataDir = path.join(__dirname, 'data');
  try {
    await fs.access(dataDir);
  } catch {
    await fs.mkdir(dataDir, { recursive: true });
  }
};

const readMessages = async () => {
  const filePath = getMessagesFilePath();
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
};

const writeMessages = async (messages) => {
  const filePath = getMessagesFilePath();
  await fs.writeFile(filePath, JSON.stringify(messages, null, 2));
};

// Routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/api/messages', async (req, res) => {
  try {
    const messages = await readMessages();
    // Return all messages for admin panel, reversed (newest first)
    const sortedMessages = messages.slice().reverse();
    res.json({ 
      messages: sortedMessages,
      total: messages.length
    });
  } catch (error) {
    console.error('Error reading messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.delete('/api/messages/:id', async (req, res) => {
  try {
    const messageId = req.params.id;
    const messages = await readMessages();
    
    const initialLength = messages.length;
    const filteredMessages = messages.filter(msg => msg.id !== messageId);
    
    if (filteredMessages.length === initialLength) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    await writeMessages(filteredMessages);
    
    console.log(`Message ${messageId} deleted`);
    res.json({ 
      success: true,
      message: 'Message deleted successfully' 
    });
    
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.post('/submit', validateMessage, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: errors.array() 
      });
    }

    const { message, name } = req.body;
    
    // Create message object
    const msg = {
      id: Date.now().toString(),
      message: message.trim(),
      name: name?.trim() || 'Anonymous',
      timestamp: new Date().toISOString(),
      ip: req.ip || req.connection.remoteAddress, // For analytics (consider privacy)
    };

    // Ensure data directory exists
    await ensureDataDirectory();

    // Read existing messages
    const messages = await readMessages();
    
    // Add new message
    messages.push(msg);
    
    // Keep only last 1000 messages to prevent file from growing too large
    if (messages.length > 1000) {
      messages.splice(0, messages.length - 1000);
    }
    
    // Write messages back to file
    await writeMessages(messages);
    
    console.log(`New message received from ${msg.name}: ${msg.message.substring(0, 50)}...`);
    
    res.json({ 
      success: true,
      msg: 'Message saved successfully! Thank you for reaching out.',
      id: msg.id
    });
    
  } catch (error) {
    console.error('Error saving message:', error);
    res.status(500).json({ 
      error: 'Failed to save message. Please try again later.' 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`📁 Data directory: ${path.join(__dirname, 'data')}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});