const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const sharp = require('sharp');
const fs = require('fs');
const querystring = require('querystring');
const https = require('https');
const fetch = require('node-fetch');
const morgan = require('morgan');

const app = express();
const port = 8081;

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

async function copyFileToPublic(sourcePath, filename) {
    try {
        const targetPath = path.join(uploadsDir, filename);
        await fs.promises.copyFile(sourcePath, targetPath);
        return `/uploads/${filename}`;
    } catch (error) {
        console.error('Error copying file to public directory:', error);
        return `/uploads/${filename}`;
    }
}

app.use('/api/uploads', express.static(uploadsDir));
app.use('/uploads', express.static(uploadsDir));

process.env.JWT_SECRET = 'QOu77yG/6k0NjF3zlO7UJR8Aeyk8JmpnJ9P6VfkYgPo=';

app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(morgan('combined'));
app.use(cors({
    origin: ['https://s29.iems5718.ie.cuhk.edu.hk'],
    credentials: true
}));

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'myuser',
  password: 'mypassword',
  database: 'shop'
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to database');
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
        cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
        fileSize: 10 * 1024 * 1024 // 10MB
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});

function handleError(res, error, message) {
    console.error(`Error: ${message}`, error);
    res.status(500).json({ message });
}

const authenticateToken = (req, res, next) => {
    console.log('Cookies received:', req.cookies);
    console.log('Authorization header:', req.headers.authorization);
    
    const token = req.cookies.token;
    if (!token) {
        console.error('Authentication failed: No token provided');
        return res.status(401).json({ message: 'Authentication required' });
    }

    console.log('Token found:', token);
    console.log('JWT_SECRET:', process.env.JWT_SECRET);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Authentication failed: Invalid token', err);
            return res.status(401).json({ message: 'Invalid authentication token' });
        }
        console.log('Token verified successfully, user:', user);
        req.user = user;
        next();
    });
};

const checkAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        console.error('Admin check failed: User is not admin');
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

const csrfProtection = (req, res, next) => {
    const token = req.headers['x-csrf-token'];
    const cookieToken = req.cookies.csrfToken;

    if (!token || !cookieToken || token !== cookieToken) {
        console.error('CSRF check failed: Invalid or missing token');
        return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    next();
};

const validateInput = (req, res, next) => {
    const { email, password, name, price, description } = req.body;
    
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.error('Validation failed: Invalid email format');
        return res.status(400).json({ message: 'Invalid email format' });
    }
    
    if (password && password.length < 6) {
        console.error('Validation failed: Password too short');
        return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }
    
    if (name && (name.length < 2 || name.length > 100)) {
        console.error('Validation failed: Invalid name length');
        return res.status(400).json({ message: 'Name must be between 2 and 100 characters' });
    }
    
    if (price && (price < 0 || price > 1000000)) {
        console.error('Validation failed: Invalid price range');
        return res.status(400).json({ message: 'Price must be between 0 and 1,000,000' });
    }
    
    if (description && (description.length < 10 || description.length > 1000)) {
        console.error('Validation failed: Invalid description length');
        return res.status(400).json({ message: 'Description must be between 10 and 1000 characters' });
    }
    
    next();
};

function hashPassword(password, salt) {
    return crypto.createHash('sha256').update(password + salt).digest('hex');
}

function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function generateOrderDigest(orderData) {
    const dataToHash = JSON.stringify({
        currency: orderData.currency,
        merchantEmail: orderData.merchantEmail,
        salt: orderData.salt,
        items: orderData.items.map(item => ({
            pid: item.pid,
            quantity: item.quantity,
            price: item.price
        })),
        totalAmount: orderData.totalAmount
    });
    
    return crypto.createHash('sha256')
        .update(dataToHash)
        .digest('hex');
}

app.post('/api/auth/login', validateInput, async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [users] = await connection.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];
        
        if (!user) {
          console.error('Login failed: User not found');
          return res.status(401).json({ message: 'Invalid email or password' });
        }
      
        const hashedPassword = hashPassword(password, user.salt);
        
        console.log('Computed hashed password:', hashedPassword);
        console.log('Stored user password:', user.password);
        
        if (hashedPassword !== user.password) {
            console.error('Login failed: Invalid credentials');
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        
        const token = jwt.sign(
            { id: user.userid, email: user.email, isAdmin: user.is_admin },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        const sessionId = crypto.randomBytes(32).toString('hex');
        await connection.promise().query('UPDATE users SET session_id = ? WHERE userid = ?', [sessionId, user.userid]);
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        console.log('Login successful, setting cookies with domain:', '20.189.115.243');
        res.json({ message: 'Login successful', isAdmin: user.is_admin });
    } catch (error) {
        handleError(res, error, 'Login failed');
    }
});

app.get('/api/auth/csrf', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.cookie('csrfToken', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        domain: '20.189.115.243',
        path: '/'
    });
    res.json({ token });
});

app.get('/api/auth/check', authenticateToken, async (req, res) => {
    try {
        console.log('Checking auth for user:', req.user);
        console.log('Session ID from cookie:', req.cookies.sessionId);
        
        const [user] = await connection.promise().query(
            'SELECT email, is_admin FROM users WHERE userid = ? AND session_id = ?',
            [req.user.id, req.cookies.sessionId]
        );

        console.log('Auth check query result:', user);

        if (user.length === 0) {
            console.log('Auth check failed: No matching user found');
            return res.status(401).json({ message: '未认证' });
        }

        console.log('Auth check successful for user:', user[0]);
        res.json({
            email: user[0].email,
            isAdmin: user[0].is_admin
        });
    } catch (error) {
        console.error('Auth check error:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        await connection.promise().query(
            'UPDATE users SET session_id = NULL WHERE userid = ?',
            [req.user.userid]
        );
        res.clearCookie('token');
        res.clearCookie('csrfToken');
        res.json({ message: '已退出登录' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    try {
        const [user] = await connection.promise().query(
            'SELECT password, salt FROM users WHERE email = ?',
            [req.user.email]
        );
        const oldHashedPassword = hashPassword(currentPassword, user[0].salt);
        

        if (oldHashedPassword !== user[0].password) {
          console.log('oldHashedPassword:', oldHashedPassword);
          console.log('store password:', user[0].password);
            return res.status(401).json({ message: '当前密码错误' });
        }

        const newSalt = generateSalt();
        const hashedPassword = hashPassword(newPassword, newSalt);
        
        await connection.promise().query(
            'UPDATE users SET password = ?, salt = ? WHERE userid = ?',
            [hashedPassword, newSalt, user[0].userid]
        );

        // 清除会话
        await connection.promise().query(
            'UPDATE users SET session_id = NULL WHERE userid = ?',
            [req.user.userid]
        );

        res.clearCookie('token');
        res.clearCookie('csrfToken');
        res.json({ message: '密码已更新，请重新登录' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

app.get('/api/categories', async (req, res) => {
    try {
        const [categories] = await connection.promise().query('SELECT * FROM categories');
        res.json(categories);
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

app.post('/api/categories', authenticateToken, checkAdmin, csrfProtection, async (req, res) => {
    const { name } = req.body;
    
    try {
        const [result] = await connection.promise().query(
            'INSERT INTO categories (name) VALUES (?)',
            [name]
        );
        res.json({ catid: result.insertId, name });
    } catch (error) {
        console.error('Error adding category:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

app.put('/api/categories/:catid', authenticateToken, checkAdmin, csrfProtection, async (req, res) => {
  const { name } = req.body;
  if (!name) {
    res.status(400).json({ message: 'Category name is required' });
    return;
  }

  connection.query(
    'UPDATE categories SET name = ? WHERE catid = ?',
    [name, req.params.catid],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      if (results.affectedRows === 0) {
        res.status(404).json({ message: 'Category not found' });
        return;
      }
      res.json({ message: 'Category updated successfully' });
    }
  );
});

app.delete('/api/categories/:catid', (req, res) => {
  connection.query(
    'DELETE FROM categories WHERE catid = ?',
    [req.params.catid],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      if (results.affectedRows === 0) {
        res.status(404).json({ message: 'Category not found' });
        return;
      }
      res.json({ message: 'Category deleted successfully' });
    }
  );
});

app.get('/api/products/category/:catid', (req, res) => {
  connection.query(
    'SELECT * FROM products WHERE catid = ?',
    [req.params.catid],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      res.json(results);
    }
  );
});

app.get('/api/products/:pid', (req, res) => {
  connection.query(
    'SELECT * FROM products WHERE pid = ?',
    [req.params.pid],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      if (results.length === 0) {
        res.status(404).json({ message: 'Product not found' });
        return;
      }
      res.json(results[0]);
    }
  );
});

app.post('/api/products', upload.single('image'), async (req, res) => {
  try {
    const { catid, name, price, description } = req.body;
    
    if (!catid || !name || !price || !description) {
      res.status(400).json({ message: 'All fields are required' });
      return;
    }

    let imagePath = null;
    let thumbnailPath = null;

    if (req.file) {
      const filename = path.basename(req.file.path);
      const thumbFilename = 'thumb-' + filename;
      
      await sharp(req.file.path)
        .resize(200, 200, {
          fit: 'contain',
          background: { r: 255, g: 255, b: 255, alpha: 1 }
        })
        .toFile(path.join(uploadsDir, thumbFilename));
      
      imagePath = `/uploads/${filename}`;
      thumbnailPath = `/uploads/${thumbFilename}`;
    }

    connection.query(
      'INSERT INTO products (catid, name, price, description, image_path, thumbnail_path) VALUES (?, ?, ?, ?, ?, ?)',
      [catid, name, price, description, imagePath, thumbnailPath],
      (error, results) => {
        if (error) {
          res.status(500).json({ error: error.message });
          return;
        }
        res.status(201).json({
          message: 'Product added successfully',
          pid: results.insertId
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/products/:pid', upload.single('image'), async (req, res) => {
  try {
    const { catid, name, price, description } = req.body;
    const pid = req.params.pid;

    if (!catid || !name || !price || !description) {
      res.status(400).json({ message: 'All fields are required' });
      return;
    }

    let updateFields = { catid, name, price, description };

    if (req.file) {
      const filename = path.basename(req.file.path);
      const thumbFilename = 'thumb-' + filename;
      
      await sharp(req.file.path)
        .resize(200, 200, {
          fit: 'contain',
          background: { r: 255, g: 255, b: 255, alpha: 1 }
        })
        .toFile(path.join(uploadsDir, thumbFilename));
      
      updateFields.image_path = `/uploads/${filename}`;
      updateFields.thumbnail_path = `/uploads/${thumbFilename}`;
    }

    const query = 'UPDATE products SET ? WHERE pid = ?';
    connection.query(query, [updateFields, pid], (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      if (results.affectedRows === 0) {
        res.status(404).json({ message: 'Product not found' });
        return;
      }
      res.json({ message: 'Product updated successfully' });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/products/:pid', (req, res) => {
  connection.query(
    'DELETE FROM products WHERE pid = ?',
    [req.params.pid],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      if (results.affectedRows === 0) {
        res.status(404).json({ message: 'Product not found' });
        return;
      }
      res.json({ message: 'Product deleted successfully' });
    }
  );
});

app.get('/api/cart/products', (req, res) => {
  const pids = req.query.pids ? req.query.pids.split(',') : [];
  if (pids.length === 0) {
    res.json([]);
    return;
  }

  connection.query(
    'SELECT pid, name, price FROM products WHERE pid IN (?)',
    [pids],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      res.json(results);
    }
  );
});

app.get('/api/products', async (req, res) => {
    try {
        const [products] = await connection.promise().query(
            'SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.catid = c.catid'
        );
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

app.get('/api/products/category/:catid', async (req, res) => {
  connection.query(
    'SELECT * FROM products WHERE catid = ?',
    [req.params.catid],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      res.json(results);
    }
  );
});

// PayPal配置
const PAYPAL_CLIENT_ID = 'AQEQPg5KCTZk4rBaoiInzK7N4Iw4uCXmfyhIOlDBIPdv_zJI6fm_PUdMrTQS9ylR7J74h7jY3XxYSVid';
const PAYPAL_SECRET = 'EDbS5D69TgY1q2RW5gVRZLJzV7WBEWNu8Pcr1WU18ppf7TTECSo79iKTwGomNeBkYhkKgTMWfalslhc_';
const PAYPAL_API_BASE = 'https://api-m.sandbox.paypal.com';

// PayPal IPN webhook
app.post('/api/paypal-ipn', async (req, res) => {
    try {
        const webhookData = req.body;
        console.log('Received PayPal webhook:', webhookData);

        if (webhookData.event_type !== 'PAYMENT.CAPTURE.COMPLETED') {
            console.log('Ignoring non-capture event:', webhookData.event_type);
            return res.status(200).send('OK');
        }

        const captureId = webhookData.resource.id;
        const orderId = webhookData.resource.custom_id;

        if (!orderId) {
            console.error('No order ID found in webhook data');
            return res.status(400).send('No order ID found');
        }

        await connection.promise().query(
            'UPDATE orders SET payment_status = "completed" WHERE order_id = ?',
            [orderId]
        );

        console.log('Order processed successfully');
        res.send('OK');
    } catch (error) {
        console.error('Error processing PayPal webhook:', error);
        res.status(500).send('Error processing webhook');
    }
});

app.get('/api/admin/orders', authenticateToken, checkAdmin, async (req, res) => {
    try {
        const [orders] = await connection.promise().query(`
            SELECT order_id, user_id, user_email, total_amount, 
                   currency_code, digest, payment_status, 
                   JSON_UNQUOTE(items) as items,
                   created_at, updated_at
            FROM orders
            ORDER BY created_at DESC
        `);

        const processedOrders = orders.map(order => ({
            ...order,
            items: typeof order.items === 'string' ? JSON.parse(order.items) : order.items
        }));

        res.json(processedOrders);
    } catch (error) {
        console.error('Error fetching admin orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.get('/api/user/orders', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [orders] = await connection.promise().query(`
            SELECT order_id, user_id, user_email, total_amount, 
                   currency_code, digest, payment_status, 
                   JSON_UNQUOTE(items) as items,
                   created_at, updated_at
            FROM orders
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 5
        `, [userId]);

        // 确保items字段是有效的JSON对象
        const processedOrders = orders.map(order => ({
            ...order,
            items: typeof order.items === 'string' ? JSON.parse(order.items) : order.items
        }));

        res.json(processedOrders);
    } catch (error) {
        console.error('Error fetching user orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// 获取商品折扣信息
app.get('/api/discounts/:pid', async (req, res) => {
    try {
        const [discounts] = await connection.promise().query(
            'SELECT * FROM discounts WHERE product_id = ?',
            [req.params.pid]
        );
        res.json(discounts);
    } catch (error) {
        console.error('Error fetching discounts:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 计算折扣价格
function calculateDiscountedPrice(originalPrice, quantity, discounts) {
    if (!discounts || discounts.length === 0) {
        return originalPrice * quantity;
    }

    let bestPrice = originalPrice * quantity;
    
    for (const discount of discounts) {
        if (quantity >= discount.condition_quantity) {
            if (discount.discount_type === 'buy_x_get_y') {
                const sets = Math.floor(quantity / (discount.condition_quantity + discount.discount_quantity));
                const remaining = quantity % (discount.condition_quantity + discount.discount_quantity);
                const discountedPrice = (sets * discount.condition_quantity + remaining) * originalPrice;
                bestPrice = Math.min(bestPrice, discountedPrice);
            } else if (discount.discount_type === 'bulk_price') {
                const discountedPrice = quantity * discount.bulk_price;
                bestPrice = Math.min(bestPrice, discountedPrice);
            }
        }
    }

    return bestPrice;
}


app.post('/api/validate-order', authenticateToken, async (req, res) => {
    try {
        const { items } = req.body;
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'Invalid order items' });
        }

        // 从JWT token中获取用户信息
        const userEmail = req.user.email || 'guest';
        const userId = req.user.id || null;

        let totalAmount = 0;
        const orderItems = [];

        for (const item of items) {
            const [products] = await connection.promise().query('SELECT * FROM products WHERE pid = ?', [item.pid]);
            if (!products || products.length === 0) {
                return res.status(400).json({ error: `Product ${item.pid} not found` });
            }

            const [discounts] = await connection.promise().query(
                'SELECT * FROM discounts WHERE product_id = ?',
                [item.pid]
            );

            const price = parseFloat(products[0].price);
            const quantity = parseInt(item.quantity);
            const { finalPrice } = calculateDiscountedPrice(price, quantity, discounts);
            totalAmount += finalPrice;

            orderItems.push({
                pid: item.pid,
                name: products[0].name,
                quantity: quantity,
                price: price,
                finalPrice: finalPrice
            });
        }

        const orderData = {
            currency: 'USD',
            merchantEmail: userEmail,
            salt: Math.random().toString(36).substring(7),
            items: orderItems,
            totalAmount: totalAmount
        };
        const digest = generateOrderDigest(orderData);

        const [result] = await connection.promise().query(
            'INSERT INTO orders (user_id, user_email, total_amount, currency_code, digest, payment_status, items) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [userId, userEmail, totalAmount, 'USD', digest, 'pending', JSON.stringify(orderItems)]
        );

        res.json({
            orderId: result.insertId,
            digest: digest
        });
    } catch (error) {
        console.error('Error validating order:', error);
        res.status(500).json({ error: 'Failed to validate order' });
    }
});

app.get('/api/ping', (req, res) => {
    res.json({
        status: 'success',
        message: 'pong',
        timestamp: new Date().toISOString(),
        protocol: req.protocol,
        secure: req.secure
    });
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Internal server error' });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});