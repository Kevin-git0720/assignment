CREATE TABLE categories (
  catid INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL
);

INSERT INTO categories (catid, name) VALUES (1, 'Electronics');
INSERT INTO categories (catid, name) VALUES (2, 'Clothing');
INSERT INTO categories (catid, name) VALUES (5, 'Food');
INSERT INTO categories (catid, name) VALUES (6, 'Toy');

CREATE TABLE IF NOT EXISTS users (
    userid INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    session_id VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT INTO users (userid, email, password, salt, updated_at, created_at)
VALUES (
    5,
    'admin1@example.com',
    '18776968b612c7725a7c8d9e2d4a83677de7bba322f1dc4377aeab9da98',
    '8f7d3b2a1c9e6f4d5a8b7c2d1e3f4a5b',
    '2025-03-15 15:50:00',
    '2025-03-17 08:58:39'
);

CREATE TABLE `products` (
  `pid` INT NOT NULL AUTO_INCREMENT,
  `catid` INT DEFAULT NULL,
  `name` VARCHAR(100) NOT NULL,
  `price` DECIMAL(10,2) NOT NULL,
  `description` TEXT,
  `image_path` VARCHAR(255) DEFAULT NULL,
  `thumbnail_path` VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (`pid`),
  CONSTRAINT `products_ibfk_1` FOREIGN KEY (`catid`) REFERENCES `categories` (`catid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE IF NOT EXISTS orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    user_email VARCHAR(255),
    total_amount DECIMAL(10,2),
    currency_code VARCHAR(3) DEFAULT 'USD',
    digest VARCHAR(255),
    payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    items JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(userid)
);

    CREATE TABLE IF NOT EXISTS discounts (
        discount_id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        discount_type ENUM('buy_x_get_y', 'bulk_price') NOT NULL,
        condition_quantity INT NOT NULL,
        discount_quantity INT,
        bulk_price DECIMAL(10,2),
        FOREIGN KEY (product_id) REFERENCES products(pid)
    );


    INSERT INTO discounts (product_id, discount_type, condition_quantity, discount_quantity, bulk_price)
VALUES (14, 'buy_x_get_y', 2, 1, NULL);

INSERT INTO discounts (product_id, discount_type, condition_quantity, discount_quantity, bulk_price)
VALUES (15, 'bulk_price', 3, NULL, 6.00);