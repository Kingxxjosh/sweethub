-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    country TEXT,
    gender TEXT,
    age INTEGER,
    bio TEXT,
    profile_pic TEXT,
    is_premium BOOLEAN DEFAULT 0,
    sweetcoins INTEGER DEFAULT 0
);

-- Videos table
CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    thumbnail TEXT,
    category TEXT,
    version TEXT,
    country TEXT,
    views INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    is_premium BOOLEAN DEFAULT 0,
    username TEXT,
    embed_code TEXT,
    FOREIGN KEY (username) REFERENCES users(username)
);

-- Comments table
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER,
    username TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (video_id) REFERENCES videos(id),
    FOREIGN KEY (username) REFERENCES users(username)
);

-- Likes table
CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER,
    username TEXT,
    FOREIGN KEY (video_id) REFERENCES videos(id),
    FOREIGN KEY (username) REFERENCES users(username)
);

-- Wallet/Transactions table (for buying coins)
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    amount INTEGER,
    sweetcoins INTEGER,
    payment_ref TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);
