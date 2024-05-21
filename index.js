const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());  // JSON body parsing middleware
app.use(bodyParser.urlencoded({ extended: true }));  // URL-encoded body parsing middleware

const secretKey = 'your_secret_key';

// Kullanıcı kayıt
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  console.log(username);  // Debug için kullanıcı adını yazdırma
  if (!username || !password || !email) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);  // bcrypt.hash fonksiyonunun doğru kullanımı
    const [rows] = await db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hashedPassword, email]);  // await ile db.execute kullanımı
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Kullanıcı giriş
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Middleware for token verification
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ message: 'Token required' });
  }
  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Sahip olunan araçları listeleme
app.get('/mycars', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM user_cars WHERE user_id = ?', [req.user.userId]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Araç exper yapma
app.post('/mycars/:carId/expert', authenticateToken, async (req, res) => {
  const { carId } = req.params;
  try {
    await db.execute('UPDATE user_cars SET expert_status = 100.00 WHERE user_id = ? AND car_id = ?', [req.user.userId, carId]);
    res.json({ message: 'Car expertized successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Araç bakım yapma
app.post('/mycars/:carId/maintenance', authenticateToken, async (req, res) => {
  const { carId } = req.params;
  try {
    await db.execute('UPDATE user_cars SET maintenance_status = 100.00 WHERE user_id = ? AND car_id = ?', [req.user.userId, carId]);
    res.json({ message: 'Car maintained successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Araç boya yapma
app.post('/mycars/:carId/paint', authenticateToken, async (req, res) => {
  const { carId } = req.params;
  try {
    await db.execute('UPDATE user_cars SET paint_status = 100.00 WHERE user_id = ? AND car_id = ?', [req.user.userId, carId]);
    res.json({ message: 'Car painted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Pazar yerine araç satma
app.post('/marketplace/sell', authenticateToken, async (req, res) => {
  const { carId, listed_price } = req.body;
  try {
    await db.execute('INSERT INTO marketplace (user_car_id, listed_price) VALUES (?, ?)', [carId, listed_price]);
    res.json({ message: 'Car listed on marketplace successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Pazar yerinden araç satın alma
app.post('/marketplace/buy', authenticateToken, async (req, res) => {
  const { carId } = req.body;
  try {
    const [carRows] = await db.execute('SELECT * FROM marketplace WHERE user_car_id = ?', [carId]);
    if (carRows.length === 0) {
      return res.status(404).json({ message: 'Car not found' });
    }
    const car = carRows[0];
    const [userRows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.user.userId]);
    const user = userRows[0];
    if (user.balance < car.listed_price) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }
    await db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [car.listed_price, req.user.userId]);
    await db.execute('DELETE FROM marketplace WHERE user_car_id = ?', [carId]);
    await db.execute('INSERT INTO user_cars (user_id, car_id, purchase_price) VALUES (?, ?, ?)', [req.user.userId, car.car_id, car.listed_price]);
    res.json({ message: 'Car purchased successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Hesaba para ekleme
app.post('/account/deposit', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  try {
    await db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, req.user.userId]);
    res.json({ message: 'Balance updated successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Hesaptan para eksiltme
app.post('/account/withdraw', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  try {
    await db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.userId]);
    res.json({ message: 'Balance updated successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
