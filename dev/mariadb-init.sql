-- Runs once when the dev MariaDB volume is created.
-- The app user also owns the demo and test databases.
CREATE DATABASE IF NOT EXISTS mailwatch_demo CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS mailwatch_test CHARACTER SET utf8mb4;
GRANT ALL PRIVILEGES ON `mailwatch\_demo`.* TO 'mailwatch'@'%';
-- mailwatch_test and mailwatch_test_* (some tests use their own database).
GRANT ALL PRIVILEGES ON `mailwatch\_test%`.* TO 'mailwatch'@'%';
