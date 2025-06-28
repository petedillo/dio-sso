const { URL } = require('url');
const config = require('../config/config');

/**
 * Validates if a redirect URI is allowed based on the whitelist
 * @param {string} redirectUri - The redirect URI to validate
 * @returns {{isValid: boolean, error?: string}} - Validation result
 */
function validateRedirectUri(redirectUri) {
    if (!redirectUri) {
        return { 
            isValid: false, 
            error: 'Redirect URI is required' 
        };
    }

    try {
        const url = new URL(redirectUri);
        
        // Check if the domain is in the whitelist
        const domain = url.hostname + (url.port ? `:${url.port}` : '');
        const isAllowed = config.allowedRedirectDomains.some(allowedDomain => {
            // Support for wildcard subdomains
            if (allowedDomain.startsWith('.')) {
                return domain.endsWith(allowedDomain) || 
                       domain === allowedDomain.substring(1);
            }
            return domain === allowedDomain;
        });

        if (!isAllowed) {
            return { 
                isValid: false, 
                error: `Redirect URI domain not allowed: ${domain}` 
            };
        }

        // Additional security checks
        if (url.protocol !== 'https:' && process.env.NODE_ENV === 'production') {
            return { 
                isValid: false, 
                error: 'Redirect URI must use HTTPS in production' 
            };
        }

        return { isValid: true };
    } catch (error) {
        return { 
            isValid: false, 
            error: `Invalid redirect URI: ${error.message}` 
        };
    }
}

/**
 * Gets a safe redirect URL, falling back to a default if needed
 * @param {string} redirectUri - The requested redirect URI
 * @param {string} defaultUri - Default URI to use if validation fails
 * @returns {string} - Validated redirect URI or default
 */
function getSafeRedirect(redirectUri, defaultUri) {
    if (!redirectUri) return defaultUri;
    
    const { isValid } = validateRedirectUri(redirectUri);
    return isValid ? redirectUri : defaultUri;
}

module.exports = {
    validateRedirectUri,
    getSafeRedirect
};
