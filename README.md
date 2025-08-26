# WordPress - Best Practice for .htaccess

## Default file

```
# BEGIN WordPress

RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]

# END WordPress
```

## Block access by path, for example: /scripts/ folder

```
# Block direct access to scripts folder - By CODETOT
# It returns 403 HTTP status code when accessing this path
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule ^scripts/ - [F,L]
</IfModule>
```

## Redirect HTTP to HTTPS

```
# BEGIN HTTPS Redirect
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
# END HTTPS Redirect
```

## Fix mixed content HTTPS

```
# BEGIN Fix mixed content warnings
<ifModule mod_headers.c>
Header always set Content-Security-Policy "upgrade-insecure-requests;"
</IfModule>
# END Fix mixed content warnings
```

## Block spam bots

```
# BEGIN Block Spam Bots
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "DotBot" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "CensysInspect" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "ZoominfoBot" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "Barkrowler" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "HomeNet" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "Custom-AsyncHttpClient" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "curl" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "zgrab" [NC]
RewriteRule .* - [R=410,L]
RewriteCond %{HTTP_USER_AGENT} "python-requests" [NC]
RewriteRule .* - [R=410,L]
</IfModule>
# END Block Spam Bots
```

## Hardening - wp-admin

```
# Block the include-only files.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>
# BEGIN WordPress
```

## Hardening - wp-config.php

```
<Files "wp-config.php">
Require all denied
</Files>
```
