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

## Hardening - wp-config.php, xmlrpc.php, .htaccess

```
<Files "wp-config.php">
Require all denied
</Files>

<Files xmlrpc.php>
order deny,allow
deny from all
</Files>

<Files .htaccess>
Order allow,deny
Deny from all
</Files>

<FilesMatch "^(README\.md|license\.txt)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

## Block author user pages

```
RewriteEngine On
RewriteBase /
RewriteCond %{REQUEST_URI} ^/author/(.*)$
RewriteRule .* - [R=403,L]
```

## Advanced - 6G Firewall

```
# 6G FIREWALL/BLACKLIST
# @ https://perishablepress.com/6g/

# 6G:[QUERY STRING]
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
	RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
	RewriteCond %{QUERY_STRING} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
	RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
	RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
	RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumb)?)\.php [NC,OR]
	RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|insert|md5|select|union) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REQUEST METHOD]
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} ^(connect|debug|move|put|trace|track) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REFERRER]
<IfModule mod_rewrite.c>
	RewriteCond %{HTTP_REFERER} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REQUEST STRING]
<IfModule mod_alias.c>
	RedirectMatch 403 (?i)([a-z0-9]{2000,})
	RedirectMatch 403 (?i)(https?|ftp|php):/
	RedirectMatch 403 (?i)(base64_encode)(.*)(\()
	RedirectMatch 403 (?i)(=\\\'|=\\%27|/\\\'/?)\.
	RedirectMatch 403 (?i)/(\$(\&)?|\*|\"|\.|,|&|&?)/?$
	RedirectMatch 403 (?i)(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")
	RedirectMatch 403 (?i)(~|`|<|>|:|;|,|%|\\|\{|\}|\[|\]|\|)
	RedirectMatch 403 (?i)/(=|\$&|_mm|cgi-|muieblack)
	RedirectMatch 403 (?i)(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)
	RedirectMatch 403 (?i)\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$
	RedirectMatch 403 (?i)/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php
</IfModule>

# 6G:[USER AGENT]
<IfModule mod_setenvif.c>
	SetEnvIfNoCase User-Agent ([a-z0-9]{2000,}) bad_bot
	SetEnvIfNoCase User-Agent (archive.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune) bad_bot
	
	# Apache < 2.3
	<IfModule !mod_authz_core.c>
		Order Allow,Deny
		Allow from all
		Deny from env=bad_bot
	</IfModule>

	# Apache >= 2.3
	<IfModule mod_authz_core.c>
		<RequireAll>
			Require all Granted
			Require not env bad_bot
		</RequireAll>
	</IfModule>
</IfModule>
```

## Advanced - Security Headers

```
# HTTP Strict Transport Security (HSTS)
Header set Strict-Transport-Security "max-age=31536000" env=HTTPS
# X-Content-Type-Options
Header set X-Content-Type-Options "nosniff"
# X-Frame-Options
Header set X-Frame-Options "SAMEORIGIN"
# X-XSS-Protection
Header set X-XSS-Protection "1; mode=block"
# Content Security Policy
Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; object-src 'none';"
```

## Advanced - Limit IP access to login

```
RewriteEngine on 
RewriteCond %{REQUEST_URI} ^(.*)?wp-login.php(.*)$ [OR] 
RewriteCond %{REQUEST_URI} ^(.*)?wp-admin$ 
RewriteCond %{REMOTE_ADDR} !^123.123.123.121$ 
RewriteCond %{REMOTE_ADDR} !^123.123.123.122$ 
RewriteCond %{REMOTE_ADDR} !^123.123.123.123$ 
RewriteRule ^(.*)$ - [R=403,L]
```

## Advanced - Dynamic IP Address Access, Limit by Referrer

```
RewriteEngine on 
RewriteCond %{REQUEST_METHOD} POST 
RewriteCond %{HTTP_REFERER} !^https://(.*)?example.com [NC] 
RewriteCond %{REQUEST_URI} ^(.*)?wp-login.php(.*)$ [OR] 
RewriteCond %{REQUEST_URI} ^(.*)?wp-admin$ 
RewriteRule ^(.*)$ - [F]
```
