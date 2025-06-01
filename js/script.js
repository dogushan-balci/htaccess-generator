// DOM Elements
const mobileMenuBtn = document.querySelector('.mobile-menu');
const nav = document.querySelector('.nav');
const optionsPanel = document.querySelector('.options-panel');
const previewContent = document.getElementById('htaccessPreview');
const copyBtn = document.getElementById('copyBtn');
const downloadBtn = document.getElementById('downloadBtn');

// Mobile Menu Toggle
mobileMenuBtn.addEventListener('click', () => {
    nav.classList.toggle('active');
    mobileMenuBtn.classList.toggle('active');
});

// .htaccess Rules Generator
class HtaccessGenerator {
    constructor() {
        this.rules = {
            templates: {
                wordpress: false,
                laravel: false,
                joomla: false,
                drupal: false,
                magento: false
            },
            redirects: {
                www: false,
                https: false,
                trailingSlash: false,
                oldUrls: false
            },
            security: {
                directoryListing: false,
                securityHeaders: false,
                ipBlocking: false,
                hotlinkProtection: false,
                fileAccess: false,
                xssProtection: false,
                sqlInjection: false,
                uploadRestrictions: false
            },
            performance: {
                browserCaching: false,
                gzipCompression: false,
                keepAlive: false,
                etags: false,
                varyHeader: false,
                cacheControl: false
            },
            errorPages: {
                error400: false,
                error401: false,
                error403: false,
                error404: false,
                error500: false,
                error503: false
            },
            php: {
                hideErrors: false,
                memoryLimit: false,
                uploadLimit: false,
                maxExecutionTime: false
            },
            file: {
                defaultIndex: false,
                directoryAccess: false,
                fileTypeRestrictions: false,
                directoryPassword: false
            },
            custom: {
                rewriteRules: false,
                headers: false,
                envVars: false,
                mimeTypes: false
            }
        };
    }

    // Template Rules Methods
    getWordPressRules() {
        let content = '# BEGIN WordPress\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteEngine On\n';
        content += 'RewriteBase /\n';
        content += 'RewriteRule ^index\\.php$ - [L]\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-f\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-d\n';
        content += 'RewriteRule . /index.php [L]\n';
        content += '</IfModule>\n\n';
        content += '# Protect wp-config.php\n';
        content += '<Files wp-config.php>\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Block WordPress xmlrpc.php requests\n';
        content += '<Files xmlrpc.php>\n';
        content += 'Order Deny,Allow\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Protect .htaccess file\n';
        content += '<Files .htaccess>\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Disable directory browsing\n';
        content += 'Options -Indexes\n\n';
        content += '# END WordPress\n\n';
        return content;
    }

    getLaravelRules() {
        let content = '# BEGIN Laravel\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteEngine On\n';
        content += 'RewriteBase /\n';
        content += 'RewriteRule ^(.*)/$ /$1 [L,R=301]\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-d\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-f\n';
        content += 'RewriteRule ^ index.php [L]\n';
        content += '</IfModule>\n\n';
        content += '# Protect .env file\n';
        content += '<Files .env>\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Protect composer files\n';
        content += '<FilesMatch "^(composer\\.json|composer\\.lock)">\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</FilesMatch>\n\n';
        content += '# Protect storage directory\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteRule ^(.*)/storage/.*$ - [F,L]\n';
        content += '</IfModule>\n\n';
        content += '# END Laravel\n\n';
        return content;
    }

    getJoomlaRules() {
        let content = '# BEGIN Joomla\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteEngine On\n';
        content += 'RewriteBase /\n';
        content += 'RewriteCond %{REQUEST_URI} !^/index\\.php\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-f\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-d\n';
        content += 'RewriteRule .* index.php [L]\n';
        content += '</IfModule>\n\n';
        content += '# Protect configuration.php\n';
        content += '<Files configuration.php>\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Protect administrator directory\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteRule ^administrator/?$ - [F,L]\n';
        content += '</IfModule>\n\n';
        content += '# Block access to sensitive files\n';
        content += '<FilesMatch "^\\.ht|configuration\\.php|php\\.ini|\\.env">\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</FilesMatch>\n\n';
        content += '# END Joomla\n\n';
        return content;
    }

    getDrupalRules() {
        let content = '# BEGIN Drupal\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteEngine On\n';
        content += 'RewriteBase /\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-f\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-d\n';
        content += 'RewriteRule ^(.*)$ index.php?q=$1 [L,QSA]\n';
        content += '</IfModule>\n\n';
        content += '# Protect settings.php\n';
        content += '<Files settings.php>\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Protect .htaccess\n';
        content += '<Files .htaccess>\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</Files>\n\n';
        content += '# Protect files directory\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteRule ^sites/.*/files/.*\\.(php|php3|php4|php5|php7|phtml|pl|py|jsp|asp|htm|html|shtml|sh|cgi)$ - [F]\n';
        content += '</IfModule>\n\n';
        content += '# Block access to sensitive files\n';
        content += '<FilesMatch "^\\.ht|composer\\.(json|lock)|package\\.json|yarn\\.lock|webpack\\.config\\.js|README\\.md|CHANGELOG\\.txt|COPYRIGHT\\.txt|INSTALL\\.(mysql|pgsql)\\.txt|LICENSE\\.txt|MAINTAINERS\\.txt|UPGRADE\\.txt|xmlrpc\\.php">\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</FilesMatch>\n\n';
        content += '# END Drupal\n\n';
        return content;
    }

    getMagentoRules() {
        let content = '# BEGIN Magento\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteEngine On\n';
        content += 'RewriteBase /\n';
        content += 'RewriteRule ^index\\.php$ - [L]\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-f\n';
        content += 'RewriteCond %{REQUEST_FILENAME} !-d\n';
        content += 'RewriteRule . /index.php [L]\n';
        content += '</IfModule>\n\n';
        content += '# Protect sensitive files\n';
        content += '<FilesMatch "^\\.ht|app/etc/local\\.xml|composer\\.(json|lock)|package\\.json|yarn\\.lock|webpack\\.config\\.js|README\\.md|CHANGELOG\\.txt|COPYRIGHT\\.txt|INSTALL\\.(mysql|pgsql)\\.txt|LICENSE\\.txt|MAINTAINERS\\.txt|UPGRADE\\.txt|xmlrpc\\.php">\n';
        content += 'Order Allow,Deny\n';
        content += 'Deny from all\n';
        content += '</FilesMatch>\n\n';
        content += '# Protect app directory\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteRule ^app/?$ - [F,L]\n';
        content += '</IfModule>\n\n';
        content += '# Protect var directory\n';
        content += '<IfModule mod_rewrite.c>\n';
        content += 'RewriteRule ^var/?$ - [F,L]\n';
        content += '</IfModule>\n\n';
        content += '# END Magento\n\n';
        return content;
    }

    // Generate .htaccess content
    generate() {
        let content = '# Generated by htaccess-generator\n';
        content += '# Created: ' + new Date().toLocaleString() + '\n';
        content += '# Author: Dogushan BALCI\n\n';

        // Template rules
        if (this.rules.templates.wordpress) {
            content += this.getWordPressRules();
        } else if (this.rules.templates.laravel) {
            content += this.getLaravelRules();
        } else if (this.rules.templates.joomla) {
            content += this.getJoomlaRules();
        } else if (this.rules.templates.drupal) {
            content += this.getDrupalRules();
        } else if (this.rules.templates.magento) {
            content += this.getMagentoRules();
        }

        // Redirects
        if (this.rules.redirects.www || this.rules.redirects.https || 
            this.rules.redirects.trailingSlash || this.rules.redirects.oldUrls) {
            content += '\n# Redirects\n';
            content += '<IfModule mod_rewrite.c>\n';
            content += 'RewriteEngine On\n';
            
            // Force www and HTTPS
            if (this.rules.redirects.www || this.rules.redirects.https) {
                content += '\n# Force www and HTTPS\n';
                
                // www checked, https unchecked
                if (this.rules.redirects.www && !this.rules.redirects.https) {
                    content += 'RewriteCond %{HTTP_HOST} !^www\\. [NC]\n';
                    content += 'RewriteRule ^ http://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n';
                }
                
                // www checked, https checked
                if (this.rules.redirects.www && this.rules.redirects.https) {
                    content += 'RewriteCond %{HTTP_HOST} !^www\\. [NC]\n';
                    content += 'RewriteCond %{HTTPS} off\n';
                    content += 'RewriteRule ^ https://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n';
                }
                
                // www unchecked, https unchecked
                if (!this.rules.redirects.www && !this.rules.redirects.https) {
                    content += 'RewriteCond %{HTTP_HOST} ^www\\. [NC]\n';
                    content += 'RewriteRule ^ http://%{HTTP_HOST#www.}%{REQUEST_URI} [L,R=301]\n';
                }
                
                // www unchecked, https checked
                if (!this.rules.redirects.www && this.rules.redirects.https) {
                    content += 'RewriteCond %{HTTPS} off\n';
                    content += 'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n';
                }
            }
            
            if (this.rules.redirects.trailingSlash) {
                content += '\n# Remove trailing slash\n';
                content += 'RewriteCond %{REQUEST_FILENAME} !-d\n';
                content += 'RewriteRule ^(.*)/$ /$1 [L,R=301]\n';
            }
            
            if (this.rules.redirects.oldUrls) {
                content += '\n# Old URL redirects\n';
                content += '# Add your old URL redirects here\n';
            }
            
            content += '</IfModule>\n';
        }

        // Security
        if (this.rules.security.directoryListing || this.rules.security.securityHeaders || 
            this.rules.security.ipBlocking || this.rules.security.hotlinkProtection || 
            this.rules.security.fileAccess || this.rules.security.xssProtection || 
            this.rules.security.sqlInjection || this.rules.security.uploadRestrictions) {
            content += '\n# Security\n';
            
            if (this.rules.security.directoryListing) {
                content += '\n# Disable directory listing\n';
                content += 'Options -Indexes\n';
            }
            
            if (this.rules.security.securityHeaders) {
                content += '\n# Security headers\n';
                content += '<IfModule mod_headers.c>\n';
                content += 'Header set X-Content-Type-Options "nosniff"\n';
                content += 'Header set X-XSS-Protection "1; mode=block"\n';
                content += 'Header set X-Frame-Options "SAMEORIGIN"\n';
                content += 'Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n';
                content += 'Header set Referrer-Policy "strict-origin-when-cross-origin"\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.security.ipBlocking) {
                content += '\n# IP blocking\n';
                content += '<IfModule mod_rewrite.c>\n';
                content += 'RewriteEngine On\n';
                content += 'RewriteCond %{REMOTE_ADDR} ^(123\.456\.789\.0|987\.654\.321\.0)$ [OR]\n';
                content += 'RewriteCond %{REMOTE_ADDR} ^(111\.222\.333\.0)$\n';
                content += 'RewriteRule .* - [F,L]\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.security.hotlinkProtection) {
                content += '\n# Hotlink protection\n';
                content += '<IfModule mod_rewrite.c>\n';
                content += 'RewriteEngine On\n';
                content += 'RewriteCond %{HTTP_REFERER} !^$\n';
                content += 'RewriteCond %{HTTP_REFERER} !^http(s)?://(www\\.)?yourdomain.com [NC]\n';
                content += 'RewriteRule \\.(jpg|jpeg|png|gif)$ - [NC,F,L]\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.security.fileAccess) {
                content += '\n# File access restrictions\n';
                content += '<FilesMatch "^\\.ht|wp-config\\.php|php\\.ini|\\.env">\n';
                content += 'Order Allow,Deny\n';
                content += 'Deny from all\n';
                content += '</FilesMatch>\n';
            }
            
            if (this.rules.security.xssProtection) {
                content += '\n# XSS protection\n';
                content += '<IfModule mod_headers.c>\n';
                content += 'Header set X-XSS-Protection "1; mode=block"\n';
                content += 'Header set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\';\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.security.sqlInjection) {
                content += '\n# SQL injection protection\n';
                content += '<IfModule mod_rewrite.c>\n';
                content += 'RewriteEngine On\n';
                content += 'RewriteCond %{QUERY_STRING} (\\<|%3C).*script.*(\\>|%3E) [NC,OR]\n';
                content += 'RewriteCond %{QUERY_STRING} GLOBALS(=|\\[|\\%[0-9A-Z]{0,2}) [OR]\n';
                content += 'RewriteCond %{QUERY_STRING} _REQUEST(=|\\[|\\%[0-9A-Z]{0,2})\n';
                content += 'RewriteRule .* index.php [F,L]\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.security.uploadRestrictions) {
                content += '\n# Upload restrictions\n';
                content += '<IfModule mod_rewrite.c>\n';
                content += 'RewriteEngine On\n';
                content += 'RewriteCond %{REQUEST_METHOD} POST\n';
                content += 'RewriteCond %{REQUEST_URI} \\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|htm|html|shtml|sh|cgi)$ [NC]\n';
                content += 'RewriteCond %{CONTENT_TYPE} !^multipart/form-data\n';
                content += 'RewriteRule .* - [F,L]\n';
                content += '</IfModule>\n';
            }
        }

        // Performance
        if (this.rules.performance.browserCaching || this.rules.performance.gzipCompression || 
            this.rules.performance.keepAlive || this.rules.performance.etags || 
            this.rules.performance.varyHeader || this.rules.performance.cacheControl) {
            content += '\n# Performance\n';
            
            if (this.rules.performance.browserCaching) {
                content += '\n# Browser caching\n';
                content += '<IfModule mod_expires.c>\n';
                content += 'ExpiresActive On\n';
                content += 'ExpiresByType image/jpg "access plus 1 year"\n';
                content += 'ExpiresByType image/jpeg "access plus 1 year"\n';
                content += 'ExpiresByType image/gif "access plus 1 year"\n';
                content += 'ExpiresByType image/png "access plus 1 year"\n';
                content += 'ExpiresByType text/css "access plus 1 month"\n';
                content += 'ExpiresByType application/pdf "access plus 1 month"\n';
                content += 'ExpiresByType text/javascript "access plus 1 month"\n';
                content += 'ExpiresByType application/javascript "access plus 1 month"\n';
                content += 'ExpiresByType application/x-javascript "access plus 1 month"\n';
                content += 'ExpiresByType application/x-shockwave-flash "access plus 1 month"\n';
                content += 'ExpiresByType image/x-icon "access plus 1 year"\n';
                content += 'ExpiresDefault "access plus 2 days"\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.performance.gzipCompression) {
                content += '\n# Gzip compression\n';
                content += '<IfModule mod_deflate.c>\n';
                content += 'AddOutputFilterByType DEFLATE text/plain\n';
                content += 'AddOutputFilterByType DEFLATE text/html\n';
                content += 'AddOutputFilterByType DEFLATE text/xml\n';
                content += 'AddOutputFilterByType DEFLATE text/css\n';
                content += 'AddOutputFilterByType DEFLATE application/xml\n';
                content += 'AddOutputFilterByType DEFLATE application/xhtml+xml\n';
                content += 'AddOutputFilterByType DEFLATE application/rss+xml\n';
                content += 'AddOutputFilterByType DEFLATE application/javascript\n';
                content += 'AddOutputFilterByType DEFLATE application/x-javascript\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.performance.keepAlive) {
                content += '\n# Keep-Alive\n';
                content += '<IfModule mod_headers.c>\n';
                content += 'Header set Connection keep-alive\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.performance.etags) {
                content += '\n# ETags\n';
                content += 'FileETag None\n';
            }
            
            if (this.rules.performance.varyHeader) {
                content += '\n# Vary header\n';
                content += '<IfModule mod_headers.c>\n';
                content += 'Header append Vary User-Agent\n';
                content += '</IfModule>\n';
            }
            
            if (this.rules.performance.cacheControl) {
                content += '\n# Cache control\n';
                content += '<IfModule mod_headers.c>\n';
                content += '<FilesMatch "\\.(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">\n';
                content += 'Header set Cache-Control "max-age=31536000, public"\n';
                content += '</FilesMatch>\n';
                content += '</IfModule>\n';
            }
        }

        // Error Pages
        if (this.rules.errorPages.error400 || this.rules.errorPages.error401 || 
            this.rules.errorPages.error403 || this.rules.errorPages.error404 || 
            this.rules.errorPages.error500 || this.rules.errorPages.error503) {
            content += '\n# Error Pages\n';
            
            if (this.rules.errorPages.error400) {
                content += 'ErrorDocument 400 /errors/400.html\n';
            }
            if (this.rules.errorPages.error401) {
                content += 'ErrorDocument 401 /errors/401.html\n';
            }
            if (this.rules.errorPages.error403) {
                content += 'ErrorDocument 403 /errors/403.html\n';
            }
            if (this.rules.errorPages.error404) {
                content += 'ErrorDocument 404 /errors/404.html\n';
            }
            if (this.rules.errorPages.error500) {
                content += 'ErrorDocument 500 /errors/500.html\n';
            }
            if (this.rules.errorPages.error503) {
                content += 'ErrorDocument 503 /errors/503.html\n';
            }
        }

        // PHP Settings
        if (this.rules.php.hideErrors || this.rules.php.memoryLimit || 
            this.rules.php.uploadLimit || this.rules.php.maxExecutionTime) {
            content += '\n# PHP Settings\n';
            
            if (this.rules.php.hideErrors) {
                content += 'php_flag display_errors off\n';
                content += 'php_value error_reporting 0\n';
            }
            
            if (this.rules.php.memoryLimit) {
                content += 'php_value memory_limit 256M\n';
            }
            
            if (this.rules.php.uploadLimit) {
                content += 'php_value upload_max_filesize 64M\n';
                content += 'php_value post_max_size 64M\n';
            }
            
            if (this.rules.php.maxExecutionTime) {
                content += 'php_value max_execution_time 300\n';
            }
        }

        // File & Directory
        if (this.rules.file.defaultIndex || this.rules.file.directoryAccess || 
            this.rules.file.fileTypeRestrictions || this.rules.file.directoryPassword) {
            content += '\n# File & Directory\n';
            
            if (this.rules.file.defaultIndex) {
                content += 'DirectoryIndex index.php index.html index.htm\n';
            }
            
            if (this.rules.file.directoryAccess) {
                content += '<Directory "/var/www/html">\n';
                content += '    Options -Indexes +FollowSymLinks\n';
                content += '    AllowOverride All\n';
                content += '    Require all granted\n';
                content += '</Directory>\n';
            }
            
            if (this.rules.file.fileTypeRestrictions) {
                content += '<FilesMatch "\\.(htaccess|htpasswd|ini|log|sh|inc|bak)$">\n';
                content += '    Order Allow,Deny\n';
                content += '    Deny from all\n';
                content += '</FilesMatch>\n';
            }
            
            if (this.rules.file.directoryPassword) {
                content += 'AuthType Basic\n';
                content += 'AuthName "Restricted Area"\n';
                content += 'AuthUserFile /path/to/.htpasswd\n';
                content += 'Require valid-user\n';
            }
        }

        // Custom Rules
        if (this.rules.custom.rewriteRules || this.rules.custom.headers || 
            this.rules.custom.envVars || this.rules.custom.mimeTypes) {
            content += '\n# Custom Rules\n';
            
            if (this.rules.custom.rewriteRules) {
                content += '\n# Custom Rewrite Rules\n';
                content += 'RewriteEngine On\n';
                content += '# Add your custom rewrite rules here\n';
            }
            
            if (this.rules.custom.headers) {
                content += '\n# Custom Headers\n';
                content += '# Add your custom headers here\n';
            }
            
            if (this.rules.custom.envVars) {
                content += '\n# Environment Variables\n';
                content += 'SetEnv APPLICATION_ENV production\n';
                content += 'SetEnv DB_HOST localhost\n';
                content += 'SetEnv DB_NAME database\n';
                content += 'SetEnv DB_USER username\n';
                content += 'SetEnv DB_PASS password\n';
            }
            
            if (this.rules.custom.mimeTypes) {
                content += '\n# Custom MIME Types\n';
                content += 'AddType application/javascript .js\n';
                content += 'AddType text/css .css\n';
                content += 'AddType image/svg+xml .svg\n';
            }
        }

        return content;
    }

    // Update rules based on checkbox changes
    updateRule(checkbox) {
        const [category, rule] = checkbox.id.split('-');
        
        // Template seçimi kontrolü
        if (category === 'templates' && checkbox.checked) {
            // Diğer template checkbox'larını kapat
            document.querySelectorAll(`input[id^="templates-"]`).forEach(otherCheckbox => {
                if (otherCheckbox !== checkbox) {
                    otherCheckbox.checked = false;
                    this.rules.templates[otherCheckbox.id.split('-')[1]] = false;
                }
            });
        }

        // Seçilen checkbox'ın değerini rules objesine aktar
        if (this.rules[category]) {
            this.rules[category][rule] = checkbox.checked;
        }

        // Preview'ı güncelle
        this.updatePreview();
    }

    // Update preview content
    updatePreview() {
        previewContent.textContent = this.generate();
    }

    download() {
        const content = this.generate();
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = '.htaccess';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }
}

// Initialize generator
const generator = new HtaccessGenerator();

// Event Listeners for checkboxes
document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', (e) => {
        const [category, rule] = e.target.id.split('-');
        if (category && rule) {
            generator.updateRule(e.target);
        }
    });
});

// Copy to clipboard
copyBtn.addEventListener('click', () => {
    const content = previewContent.textContent;
    navigator.clipboard.writeText(content).then(() => {
        showToast('Copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('Failed to copy to clipboard', 'error');
    });
});

// Download .htaccess file
downloadBtn.addEventListener('click', () => {
    generator.download();
    showToast('File downloaded successfully!');
});

// Toast notification
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
    }, 100);

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

// Initialize preview
generator.updatePreview(); 