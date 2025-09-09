# Common WordPress Directories & Files

## 🔑 Core Directories

-   `/wp-admin/` → WordPress admin dashboard.\
-   `/wp-includes/` → core WordPress files and libraries.\
-   `/wp-content/` → main content directory.

## 📂 Inside `/wp-content/`

-   `/wp-content/themes/` → installed themes.\
-   `/wp-content/plugins/` → installed plugins.\
-   `/wp-content/uploads/` → user-uploaded files (often browsable if
    directory listing is enabled).\
-   `/wp-content/cache/` → caching data (if enabled).\
-   `/wp-content/languages/` → language files.\
-   `/wp-content/mu-plugins/` → must-use plugins (autoloaded).

## 📄 Common Files

-   `/wp-config.php` → WordPress configuration (contains DB
    credentials).\
-   `/xmlrpc.php` → XML-RPC interface (can be abused for brute force or
    DDoS).\
-   `/readme.html` → reveals WordPress version.\
-   `/license.txt` → default license file.\
-   `/wp-cron.php` → handles scheduled tasks.\
-   `/wp-links-opml.php` → sometimes reveals version info.\
-   `/wp-activate.php` → used for multisite activation.\
-   `/wp-signup.php` → user registration page (if enabled).

## 🔒 Sensitive or Hidden Targets

-   `/wp-admin/install.php` → installer (should be deleted/disabled
    after setup).\
-   `/wp-admin/upgrade.php` → upgrade script.\
-   Backup files: `wp-config.php.bak`, `wp-config.old`, etc.\
-   Hidden files: `.htaccess`, `.user.ini`, `.env`.

------------------------------------------------------------------------

## ⚠️ Enumeration Tips

-   Always check if directory listing is enabled.\
-   Look for exposed backup or config files.\
-   Pay attention to plugin and theme directories: outdated or
    vulnerable code is common.
