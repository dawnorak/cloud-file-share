const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;

app.use(
  session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
  })
);

// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Folder where uploaded files will be stored
  },
  filename: (req, file, cb) => {
    const fileName = Date.now() + path.extname(file.originalname);
    cb(null, fileName);
  },
});

const upload = multer({ storage });

// Serve static files
app.use(express.static('public'));

// Parse JSON and URL-encoded query
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let users = [];
const usersFilePath = path.join(__dirname, 'users.json');
if (fs.existsSync(usersFilePath)) {
  const usersData = fs.readFileSync(usersFilePath, 'utf-8');
  users = JSON.parse(usersData);
} else {
  // Create users.json file with an empty array if it doesn't exist
  fs.writeFileSync(usersFilePath, '[]');
}

// Hash a password using bcrypt
const hashPassword = async (password) => {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
};

// Check if password matches hashed version
const comparePassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

// Check if the user is authenticated for login
function isLoginAuthenticated(req, res, next) {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).send('Invalid username or password');
  }
  req.session.user = user;
  next();
}

// Check if the user is authenticated for file upload
function isUploadAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send('Authentication required');
  }
  next();
}

// Define routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/login.html');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username
  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).send('Invalid username or password');
  }

  // Compare input password with hashed password
  const passwordMatch = await comparePassword(password, user.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid username or password');
  }

  // User is authenticated, redirect to the file upload page
  res.redirect('/upload');
});

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/views/register.html'); // Send the registration page
});

app.post('/register', async (req, res) => {
  const { newUsername, newPassword } = req.body;

  // Check if username already exists
  if (users.some((user) => user.username === newUsername)) {
    return res.status(400).send('Username already exists');
  }

  // Hash the password
  const hashedPassword = await hashPassword(newPassword);

  // Add the new user to the users array
  const newUser = { username: newUsername, password: hashedPassword };
  users.push(newUser);

  // Save the updated users array to the JSON file
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));

  res.redirect('/'); // Redirect back to the login page
});

app.get('/upload', (req, res) => {
  res.sendFile(__dirname + '/views/upload.html');
});

app.post('/upload', isUploadAuthenticated, upload.single('file'), (req, res) => {
  // Handle file upload here
  const file = req.file;
  if (!file) {
    return res.status(400).send('No file selected');
  }
  // Save file metadata or process it as needed
  return res.send('File uploaded successfully');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});