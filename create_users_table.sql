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