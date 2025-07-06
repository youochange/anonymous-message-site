const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static('public'));

app.post('/submit', (req, res) => {
  const { message, name } = req.body;
  const msg = { message, name, time: new Date() };

  const filePath = path.join(__dirname, 'messages.json');
  let messages = [];

  if (fs.existsSync(filePath)) {
    messages = JSON.parse(fs.readFileSync(filePath));
  }

  messages.push(msg);
  fs.writeFileSync(filePath, JSON.stringify(messages, null, 2));

  res.json({ msg: 'Message saved! Thank you.' });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
