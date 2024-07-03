import express from 'express';
import mysql from 'mysql'; 
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
const app = express();
const port = 3000;

app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
    host     : 'localhost',
    user     : 'me',
    password : 'secret',
    database : 'my_db'
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Connected to database');
});

// Secret key for JWT (replace with you key)
const secretKey = 'your_secret_key';
// key for admin api
const adminApiKey = 'your_admin_api_key';

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  // Check if Authorization header is present
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Token not provided' });
  }

  // Verify JWT token
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(401).json({ error: 'Failed to authenticate token' });
    }
    // If token is valid, save decoded token payload to request object
    req.user = decoded;
    next(); // Pass control to the next middleware or route handler
  });
};
//middleware for admin api key
const apiKeyVerification = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
  
    if ( apiKey !== adminApiKey) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
  
    next(); // Pass control to the next middleware or route handler
  };
  



// 1. Register
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
    const sql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    db.query(sql, [username, password, email], (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to register user' });
      } else {
        res.status(201).json({ message: 'User registered successfully' });
      }
    });
  });

// 2. Endpoint to login and generate JWT token
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
  
  db.query(sql, [username, password], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to authenticate' });
    }
    
    if (results.length > 0) {
      const user = results[0];
      // Generate JWT token with user information
      const token = jwt.sign({ userId: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
      res.status(200).json({ token: token });
    } else {
      res.status(401).json({ error: 'Incorrect username or password' });
    }
  });
});
// 3.ADD trains
app.post('/add-trains',apiKeyVerification, (req, res) => {
    const { source, destination } = req.body;
    const sql = 'INSERT INTO trains (source, destination) VALUES (?, ?)';
    db.query(sql, [source, destination], (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add train' });
      } else {
        res.status(201).json({ message: 'Train added successfully' });
      }
    });
  });


// 4. Get Seat Availability
app.get('/trains', (req, res) => {
    const { source, destination } = req.query;
    const sql = 'SELECT * FROM trains WHERE source = ? AND destination = ?';
    db.query(sql, [source, destination], (err, results) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch trains' });
      } else {
        res.status(200).json(results);
      }
    });
  });


// 5 . Endpoint to book a seat (Requires Authorization Token)
app.post('/bookings', verifyToken, (req, res) => {
  const { trainId, seatNumber } = req.body;
  const userId = req.user.userId; // Extract userId from decoded token

  const sql = 'INSERT INTO bookings (user_id, train_id, seat_number) VALUES (?, ?, ?)';
  db.query(sql, [userId, trainId, seatNumber], (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to book seat' });
    } else {
      res.status(201).json({ message: 'Seat booked successfully' });
    }
  });
});

// 6. Endpoint to get specific booking details (Requires Authorization Token)
app.get('/bookings/:bookingId', verifyToken, (req, res) => {
  const bookingId = req.params.bookingId;
  const userId = req.user.userId; // Extract userId from decoded token

  const sql = 'SELECT * FROM bookings WHERE id = ? AND user_id = ?';
  db.query(sql, [bookingId, userId], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to fetch booking details' });
    } else {
      if (results.length > 0) {
        res.status(200).json(results[0]);
      } else {
        res.status(404).json({ error: 'Booking not found' });
      }
    }
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
