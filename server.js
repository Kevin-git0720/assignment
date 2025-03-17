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

const app = express();
const port = 8081;

// 使用项目本地的uploads目录
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// 复制文件的辅助函数
async function copyFileToPublic(sourcePath, filename) {
    try {
        const targetPath = path.join(uploadsDir, filename);
        await fs.promises.copyFile(sourcePath, targetPath);
        return `/uploads/${filename}`;
    } catch (error) {
        console.error('Error copying file to public directory:', error);
        // 如果无法复制到公共目录，返回不带/api的路径
        return `/uploads/${filename}`;
    }
}

app.use('/api/uploads', express.static(uploadsDir));
app.use('/uploads', express.static(uploadsDir));

// 直接设置 JWT_SECRET
process.env.JWT_SECRET = 'QOu77yG/6k0NjF3zlO7UJR8Aeyk8JmpnJ9P6VfkYgPo=';

// 中间件配置
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(cors({
    origin: ['http://20.189.115.243', 'https://20.189.115.243'],
    credentials: true
}));

// 数据库连接配置
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'myuser',
  password: 'mypassword',
  database: 'shop'
});

// 连接数据库
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to database');
});

// 文件上传配置
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

// 统一的错误处理函数
function handleError(res, error, message) {
    console.error(`Error: ${message}`, error);
    res.status(500).json({ message });
}

// 认证中间件
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

// 管理员检查中间件
const checkAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        console.error('Admin check failed: User is not admin');
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// CSRF 保护中间件
const csrfProtection = (req, res, next) => {
    const token = req.headers['x-csrf-token'];
    const cookieToken = req.cookies.csrfToken;

    if (!token || !cookieToken || token !== cookieToken) {
        console.error('CSRF check failed: Invalid or missing token');
        return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    next();
};

// 输入验证中间件
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

// 添加密码加密和验证函数
function hashPassword(password, salt) {
    return crypto.createHash('sha256').update(password + salt).digest('hex');
}

function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

// 认证路由
app.post('/api/auth/login', validateInput, async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [users] = await connection.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];
        
        if (!user) {
          console.error('Login failed: User not found');
          return res.status(401).json({ message: 'Invalid email or password' });
        }
      
        // 计算哈希密码
        const hashedPassword = hashPassword(password, user.salt);
        
        // 打印出哈希密码和存储的密码
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
            secure: false,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000,
            domain: '20.189.115.243',
            path: '/'
        });
        
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000,
            domain: '20.189.115.243',
            path: '/'
        });
        
        console.log('Login successful, setting cookies with domain:', '20.189.115.243');
        res.json({ message: 'Login successful', isAdmin: user.is_admin });
    } catch (error) {
        handleError(res, error, 'Login failed');
    }
});

// CSRF令牌路由
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

// 认证检查路由
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

// 退出登录路由
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

// 修改密码路由
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

// 修改现有的API路由，添加认证和CSRF保护
app.get('/api/categories', authenticateToken, checkAdmin, async (req, res) => {
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

app.put('/api/categories/:catid', (req, res) => {
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
      
      // 生成缩略图
      await sharp(req.file.path)
        .resize(200, 200, {
          fit: 'contain',
          background: { r: 255, g: 255, b: 255, alpha: 1 }
        })
        .toFile(path.join(uploadsDir, thumbFilename));
      
      // 保存不带/api前缀的路径
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
      
      // 生成缩略图
      await sharp(req.file.path)
        .resize(200, 200, {
          fit: 'contain',
          background: { r: 255, g: 255, b: 255, alpha: 1 }
        })
        .toFile(path.join(uploadsDir, thumbFilename));
      
      // 保存不带/api前缀的路径
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

// 获取所有产品
app.get('/api/products', authenticateToken, checkAdmin, async (req, res) => {
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

// 获取特定分类的产品
app.get('/api/products/category/:catid', authenticateToken, async (req, res) => {
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

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Internal server error' });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});