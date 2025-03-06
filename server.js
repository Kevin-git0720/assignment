const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const sharp = require('sharp');
const cors = require('cors');
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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use('/api/uploads', express.static(uploadsDir));
app.use('/uploads', express.static(uploadsDir));

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'myuser',
  password: 'mypassword',
  database: 'shop'
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const productName = req.body.name || 'product';
    const safeProductName = productName.toLowerCase().replace(/[^a-z0-9]/g, '-');
    const timestamp = Date.now();
    const filename = `${safeProductName}-${timestamp}${path.extname(file.originalname)}`;
    cb(null, filename);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only image files are supported!'));
  }
});

connection.connect(err => {
  if (err) {
    console.error('Database error:', err);
    return;
  }
  console.log('Database connected');
});

app.get('/api/categories', (req, res) => {
  connection.query('SELECT * FROM categories', (error, results) => {
    if (error) {
      res.status(500).json({ error: error.message });
      return;
    }
    res.json(results);
  });
});

app.post('/api/categories', (req, res) => {
  const { name } = req.body;
  if (!name) {
    res.status(400).json({ message: 'Category name is required' });
    return;
  }

  connection.query(
    'INSERT INTO categories (name) VALUES (?)',
    [name],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: error.message });
        return;
      }
      res.status(201).json({
        message: 'Category added successfully',
        catid: results.insertId
      });
    }
  );
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

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});