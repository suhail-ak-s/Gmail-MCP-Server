#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');
const AUTH_SERVER_PORT = parseInt(process.env.GMAIL_AUTH_SERVER_PORT || '443', 10);
const AUTH_SERVER_HOST = process.env.GMAIL_AUTH_SERVER_HOST || 'gmail-mcp-auth.syia.ai';
const AUTH_SERVER_TYPE = process.env.GMAIL_AUTH_SERVER_TYPE || 'https';  
const REDIRECT_URL = `${AUTH_SERVER_TYPE}://${AUTH_SERVER_HOST}:${AUTH_SERVER_PORT}/oauth2callback`;

// Type definitions for Gmail API responses
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration
let oauth2Client: OAuth2Client;

// Global reference to the auth server
let authServer: http.Server | null = null;
let authServerTimeout: NodeJS.Timeout | null = null;

// New function to get an OAuth client for a userId
async function getOAuthClientForUser(userId: string): Promise<OAuth2Client | null> {
    console.log(`\n======== getOAuthClientForUser START (userId: ${userId}) ========`);
    
    try {
        // Create config directory if it doesn't exist
        if (!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        console.log(`CONFIG_DIR: ${CONFIG_DIR}`);
        
        // Get path to credentials file
        const userCredentialsPath = path.join(CONFIG_DIR, `credentials_${userId}.json`);
        console.log(`Looking for credentials at: ${userCredentialsPath}`);
        
        // Check if credentials file exists
        const fileExists = fs.existsSync(userCredentialsPath);
        console.log(`Credentials file exists: ${fileExists}`);
        
        // If file doesn't exist, return null immediately
        if (!fileExists) {
            console.log(`No credentials file found for user ${userId}, returning null`);
            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - NO FILE ========\n`);
            return null;
        }

        // Read the credentials file content
        let credentialsRaw: string;
        try {
            credentialsRaw = fs.readFileSync(userCredentialsPath, 'utf8');
            console.log(`Read credentials file, size: ${credentialsRaw.length} bytes`);
        } catch (readError) {
            console.error(`Error reading credentials file: ${readError}`);
            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - READ ERROR ========\n`);
            return null;
        }
        
        // Parse credentials JSON
        let credentials: any;
        try {
            credentials = JSON.parse(credentialsRaw);
            console.log(`Parsed credentials successfully`);
            console.log(`Refresh token exists: ${Boolean(credentials.refresh_token)}`);
            console.log(`Access token exists: ${Boolean(credentials.access_token)}`);
            if (credentials.expiry_date) {
                console.log(`Token expiry: ${new Date(credentials.expiry_date).toISOString()}`);
            }
        } catch (parseError) {
            console.error(`Failed to parse credentials JSON: ${parseError}`);
            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - PARSE ERROR ========\n`);
            return null;
        }

        // Check if credentials are provided via environment variables
        const envClientId = process.env.GMAIL_CLIENT_ID;
        const envClientSecret = process.env.GMAIL_CLIENT_SECRET;

        let oauthClient: OAuth2Client;

        // If client ID and secret are provided via environment variables
        if (envClientId && envClientSecret) {
            console.log('Using OAuth client credentials from environment variables');
            
            oauthClient = new OAuth2Client(
                envClientId,
                envClientSecret,
                REDIRECT_URL
            );
        } else {
            // Fall back to file-based credentials
            if (!fs.existsSync(OAUTH_PATH)) {
                console.error(`OAuth keys file not found at: ${OAUTH_PATH}`);
                console.log(`======== getOAuthClientForUser END (userId: ${userId}) - NO OAUTH KEYS ========\n`);
                return null;
            }

            console.log(`Loading OAuth keys from: ${OAUTH_PATH}`);
            try {
                const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
                const keys = keysContent.installed || keysContent.web;
                
                if (!keys) {
                    console.error('Invalid OAuth keys format - missing installed or web property');
                    console.log(`======== getOAuthClientForUser END (userId: ${userId}) - INVALID KEYS ========\n`);
                    return null;
                }

                oauthClient = new OAuth2Client(
                    keys.client_id,
                    keys.client_secret,
                    REDIRECT_URL
                );
            } catch (error) {
                console.error(`Error loading OAuth keys: ${error}`);
                console.log(`======== getOAuthClientForUser END (userId: ${userId}) - OAUTH KEY ERROR ========\n`);
                return null;
            }
        }
        
        // Set the credentials on the OAuth client
        console.log('Setting credentials on OAuth client');
        oauthClient.setCredentials(credentials);
        
        // Check if we have what we need
        if (!credentials.refresh_token && !credentials.access_token) {
            console.error('No refresh token or access token available');
            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - NO TOKENS ========\n`);
            return null;
        }
        
        // If we have an access token, try to validate it
        if (credentials.access_token) {
            console.log('Validating access token...');
            try {
                const tokenInfo = await oauthClient.getTokenInfo(credentials.access_token);
                console.log(`Token is valid: ${!!tokenInfo}`);
                // Token is valid, return the client
                console.log(`Successfully created OAuth client for user ${userId}`);
                console.log(`======== getOAuthClientForUser END (userId: ${userId}) - SUCCESS WITH VALID TOKEN ========\n`);
                return oauthClient;
            } catch (tokenError) {
                console.warn('Access token is invalid, will attempt to refresh');
                console.log(`Token error: ${tokenError}`);
                
                // Check for refresh token more carefully
                if (!credentials.refresh_token) {
                    console.error('No refresh token available, cannot refresh access token');
                    console.log(`======== getOAuthClientForUser END (userId: ${userId}) - NO REFRESH TOKEN ========\n`);
                    return null;
                }
                
                // Log refresh token info (partial, for security)
                const refreshTokenPreview = credentials.refresh_token.substring(0, 5) + '...';
                console.log(`Found refresh token (starts with: ${refreshTokenPreview})`);
                
                try {
                    console.log('Refreshing token using refresh_token...');
                    
                    // Try direct refresh with more detailed logging
                    try {
                        console.log('Calling refreshAccessToken()...');
                        const refreshResponse = await oauthClient.refreshAccessToken();
                        console.log('Successfully refreshed token');
                        console.log(`New access token received: ${!!refreshResponse.credentials.access_token}`);
                        if (refreshResponse.credentials.expiry_date) {
                            console.log(`New token expiry: ${new Date(refreshResponse.credentials.expiry_date).toISOString()}`);
                        }
                        
                        // Save the refreshed credentials
                        fs.writeFileSync(userCredentialsPath, JSON.stringify(oauthClient.credentials));
                        console.log('Updated credentials saved to disk');
                        console.log(`======== getOAuthClientForUser END (userId: ${userId}) - SUCCESS AFTER REFRESH ========\n`);
                        return oauthClient;
                    } catch (refreshError) {
                        // More detailed error logging
                        console.error('Failed to refresh token. Error details:');
                        console.error(refreshError);
                        
                        if (typeof refreshError === 'object' && refreshError !== null && 
                            'toString' in refreshError && refreshError.toString().includes('invalid_grant')) {
                            console.error('Invalid grant error detected. This usually means the refresh token has expired or been revoked.');
                            console.error('Will need re-authentication.');
                            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - INVALID GRANT ========\n`);
                            return null;
                        }
                        
                        // Last resort attempt - force the client to try an auto-refresh
                        console.log('Attempting alternative refresh method...');
                        try {
                            // Reset the client with just the refresh token
                            oauthClient.setCredentials({
                                refresh_token: credentials.refresh_token
                            });
                            
                            // Make a test request to force an auto-refresh
                            console.log('Calling getAccessToken() to force refresh...');
                            const tokenResult = await oauthClient.getAccessToken();
                            console.log(`Alternative refresh result: ${!!tokenResult.token}`);
                            console.log('Alternative refresh successful');
                            
                            // Save the refreshed credentials
                            fs.writeFileSync(userCredentialsPath, JSON.stringify(oauthClient.credentials));
                            console.log('Updated credentials saved to disk from alternative method');
                            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - SUCCESS AFTER ALT REFRESH ========\n`);
                            return oauthClient;
                        } catch (altRefreshError) {
                            console.error('Alternative refresh also failed:');
                            console.error(altRefreshError);
                            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - ALL REFRESH FAILED ========\n`);
                            return null;
                        }
                    }
                } catch (generalError) {
                    console.error('General error during refresh attempt:');
                    console.error(generalError);
                    console.log(`======== getOAuthClientForUser END (userId: ${userId}) - GENERAL ERROR ========\n`);
                    return null;
                }
            }
        } else if (credentials.refresh_token) {
            // If we don't have an access token but do have a refresh token, try to refresh
            console.log('No access token, but have refresh token. Trying to refresh...');
            try {
                // Reset the client with just the refresh token to ensure clean state
                oauthClient.setCredentials({
                    refresh_token: credentials.refresh_token
                });
                
                // Force a refresh by getting access token
                console.log('Calling getAccessToken() to get a new token...');
                const tokenResult = await oauthClient.getAccessToken();
                console.log(`Refresh result: ${!!tokenResult.token}`);
                
                // Save the refreshed credentials
                fs.writeFileSync(userCredentialsPath, JSON.stringify(oauthClient.credentials));
                console.log('Updated credentials saved to disk after refresh');
                console.log(`======== getOAuthClientForUser END (userId: ${userId}) - SUCCESS WITH REFRESH TOKEN ONLY ========\n`);
                return oauthClient;
            } catch (refreshError) {
                console.error('Failed to get new access token:');
                console.error(refreshError);
                console.log(`======== getOAuthClientForUser END (userId: ${userId}) - REFRESH FAILED ========\n`);
                return null;
            }
        } else {
            console.error('No refresh token available, cannot refresh access token');
            console.log(`======== getOAuthClientForUser END (userId: ${userId}) - NO TOKEN ========\n`);
            return null;
        }
    } catch (error) {
        console.error('Unexpected error in getOAuthClientForUser:');
        console.error(error);
        console.log(`======== getOAuthClientForUser END (userId: ${userId}) - UNEXPECTED ERROR ========\n`);
        return null;
    }
}

// Modified function to start/stop the authentication server
async function startAuthServer(): Promise<http.Server> {
    // If there's already a server running, return it
    if (authServer) {
        console.log(`[DEBUG] Auth server already running on port ${AUTH_SERVER_PORT}`);
        resetAuthServerTimeout();
        return authServer;
    }

    console.log(`[DEBUG] Starting authentication server on port ${AUTH_SERVER_PORT}`);
    authServer = http.createServer();
    
    // Set socket options to allow port reuse
    authServer.on('listening', () => {
        const server = authServer as http.Server;
        if (server && server.address()) {
            // Force close connections when server closes
            server.keepAliveTimeout = 1000;
            server.headersTimeout = 2000;
            console.log(`[DEBUG] Auth server socket options configured for quick release`);
        }
    });
    
    // Set up a timeout to close the server if not used
    resetAuthServerTimeout();
    
    return new Promise<http.Server>((resolve, reject) => {
        if (!authServer) {
            reject(new Error('Failed to create auth server'));
            return;
        }
        
        authServer.listen(AUTH_SERVER_PORT, () => {
            console.log(`Authentication server started on port ${AUTH_SERVER_PORT}`);
            
            if (authServer) {
                authServer.on('request', async (req, res) => {
                    if (!req.url?.startsWith('/oauth2callback')) return;
                    
                    // Reset the timeout since we received a request
                    resetAuthServerTimeout();
        
                    const url = new URL(req.url, REDIRECT_URL);
                    const code = url.searchParams.get('code');
                    const state = url.searchParams.get('state'); // This contains our user ID
        
                    if (!code || !state) {
                        res.writeHead(400);
                        res.end('No code or user ID provided');
                        return;
                    }
        
                    // Create a temporary OAuth client for this authentication
                    let oauthClient: OAuth2Client;
                    
                    // Check if credentials are provided via environment variables
                    const envClientId = process.env.GMAIL_CLIENT_ID;
                    const envClientSecret = process.env.GMAIL_CLIENT_SECRET;
        
                    // If client ID and secret are provided via environment variables
                    if (envClientId && envClientSecret) {
                        oauthClient = new OAuth2Client(
                            envClientId,
                            envClientSecret,
                            REDIRECT_URL
                        );
                    } else {
                        // Fall back to file-based credentials
                        if (!fs.existsSync(OAUTH_PATH)) {
                            res.writeHead(500);
                            res.end('Server configuration error: OAuth keys not found');
                            return;
                        }
        
                        try {
                            const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
                            const keys = keysContent.installed || keysContent.web;
                            
                            if (!keys) {
                                res.writeHead(500);
                                res.end('Server configuration error: Invalid OAuth keys format');
                                return;
                            }
        
                            oauthClient = new OAuth2Client(
                                keys.client_id,
                                keys.client_secret,
                                REDIRECT_URL
                            );
                        } catch (error) {
                            res.writeHead(500);
                            res.end('Server configuration error: Failed to load OAuth keys');
                            return;
                        }
                    }
        
                    try {
                        const { tokens } = await oauthClient.getToken(code);
                        
                        // Validate that we received a refresh token
                        if (!tokens.refresh_token) {
                            console.error('[DEBUG] No refresh token received! This will cause future authentication problems.');
                            
                            // If running in development, we'll still continue, but in production this would be a problem
                            console.warn('[DEBUG] Continuing anyway for testing, but this user will need to re-authenticate frequently.');
                        } else {
                            console.log('[DEBUG] Successfully received refresh token!');
                        }
                        
                        // Save credentials to file with user ID
                        const userCredentialsPath = path.join(CONFIG_DIR, `credentials_${state}.json`);
                        
                        // Log what we're saving
                        console.log(`[DEBUG] Saving credentials with:
                        - Access Token: ${!!tokens.access_token}
                        - Refresh Token: ${!!tokens.refresh_token}
                        - Expiry Date: ${tokens.expiry_date}
                        - Token Type: ${tokens.token_type}`);
                        
                        fs.writeFileSync(userCredentialsPath, JSON.stringify(tokens));
                        console.log(`[DEBUG] Credentials saved successfully to: ${userCredentialsPath}`);
        
                        res.writeHead(200);
                        res.end('Authentication successful! You can close this window and return to Claude.');
                        console.log(`User ${state} authenticated successfully`);
                        
                        // After handling a successful auth, we can close the server after a delay
                        // This ensures the response is fully sent to the browser
                        setTimeout(() => {
                            closeAuthServer();
                        }, 2000);
                    } catch (error) {
                        console.error('Error authenticating user:', error);
                        res.writeHead(500);
                        res.end('Authentication failed');
                    }
                });
                
                resolve(authServer);
            } else {
                reject(new Error('Server closed during initialization'));
            }
        });
        
        authServer.on('error', (err) => {
            console.error('[DEBUG] Auth server error:', err);
            authServer = null;
            reject(err);
        });
    });
}

// Function to reset the auth server timeout
function resetAuthServerTimeout() {
    // Clear existing timeout if any
    if (authServerTimeout) {
        clearTimeout(authServerTimeout);
        authServerTimeout = null;
    }
    
    // Set a new timeout - close server after 5 minutes of inactivity
    if (authServer) {
        console.log('[DEBUG] Setting auth server timeout for 5 minutes');
        authServerTimeout = setTimeout(() => {
            closeAuthServer();
        }, 5 * 60 * 1000); // 5 minutes
    }
}

// Function to gracefully close the auth server
function closeAuthServer() {
    if (authServer) {
        console.log('[DEBUG] Closing authentication server');
        try {
            // Force close all existing connections
            if (authServer instanceof http.Server) {
                // Destroy all sockets to prevent TIME_WAIT state
                const socketMap = new Map();
                
                // Track new connections
                authServer.on('connection', (socket) => {
                    const socketId = `${socket.remoteAddress}:${socket.remotePort}`;
                    socketMap.set(socketId, socket);
                    socket.on('close', () => {
                        socketMap.delete(socketId);
                    });
                });
                
                // Close existing connections
                for (const socket of socketMap.values()) {
                    socket.destroy();
                }
            }
            
            // Close the server with a short timeout
            const closePromise = new Promise<void>((resolve) => {
                authServer?.close(() => {
                    console.log('[DEBUG] Auth server closed successfully');
                    resolve();
                });
                
                // Force timeout after 1 second in case connections hang
                setTimeout(() => {
                    console.log('[DEBUG] Auth server close timed out, forcing close');
                    resolve();
                }, 1000);
            });
            
            // Wait for server to close or timeout
            closePromise.then(() => {
                authServer = null;
            });
        } catch (err) {
            console.error('[DEBUG] Error closing auth server:', err);
            authServer = null;
        }
    }
    
    if (authServerTimeout) {
        clearTimeout(authServerTimeout);
        authServerTimeout = null;
    }
}

// Check if a user is authenticated
async function isAuthenticated(userId: string): Promise<boolean> {
    console.log(`[DEBUG] Checking if user ${userId} is authenticated`);
    
    // First, explicitly check if the user-specific credentials file exists
    const userCredentialsPath = path.join(CONFIG_DIR, `credentials_${userId}.json`);
    const fileExists = fs.existsSync(userCredentialsPath);
    
    console.log(`[DEBUG] User credentials file at ${userCredentialsPath} exists: ${fileExists}`);
    
    // If file doesn't exist, user is definitely not authenticated
    if (!fileExists) {
        console.log(`[DEBUG] No credentials file found for user ${userId}, returning false`);
        return false;
    }
    
    // Try to get the OAuth client
    try {
        console.log(`[DEBUG] Attempting to get OAuth client for user ${userId}`);
        const oauthClient = await getOAuthClientForUser(userId);
        console.log(`[DEBUG] OAuth client result: ${oauthClient ? 'Successfully created' : 'Failed to create'}`);
        return oauthClient !== null;
    } catch (error) {
        // If anything goes wrong, log it and return false (not authenticated)
        console.error(`[DEBUG] Error checking authentication for user ${userId}:`, error);
        return false;
    }
}

// Schema for checking authentication status - now requires userId
const CheckAuthStatusSchema = z.object({
    userId: z.string().describe("User ID to check authentication status for"),
});

/**
 * Helper function to encode email headers containing non-ASCII characters
 * according to RFC 2047 MIME specification
 */
function encodeEmailHeader(text: string): string {
    // Only encode if the text contains non-ASCII characters
    if (/[^\x00-\x7F]/.test(text)) {
        // Use MIME Words encoding (RFC 2047)
        return '=?UTF-8?B?' + Buffer.from(text).toString('base64') + '?=';
    }
    return text;
}

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';
    
    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');
        
        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }
    
    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }
    
    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

async function loadCredentials() {
    try {
        // Create config directory if it doesn't exist
        if (!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        // Check if credentials are provided via environment variables
        const envClientId = process.env.GMAIL_CLIENT_ID;
        const envClientSecret = process.env.GMAIL_CLIENT_SECRET;
        const envAccessToken = process.env.GMAIL_ACCESS_TOKEN;
        const envRefreshToken = process.env.GMAIL_REFRESH_TOKEN;
        const envTokenExpiry = process.env.GMAIL_TOKEN_EXPIRY;

        // If client ID and secret are provided via environment variables
        if (envClientId && envClientSecret) {
            console.log('Using OAuth client credentials from environment variables.');
            
            oauth2Client = new OAuth2Client(
                envClientId,
                envClientSecret,
                REDIRECT_URL
            );

            // If OAuth tokens are also provided via environment variables
            if (envAccessToken && envRefreshToken) {
                console.log('Using OAuth tokens from environment variables.');
                
                const credentials: {
                    access_token: string;
                    refresh_token: string;
                    token_type: string;
                    expiry_date?: number;
                } = {
                    access_token: envAccessToken,
                    refresh_token: envRefreshToken,
                    token_type: 'Bearer',
                };
                
                // Add token expiry if provided
                if (envTokenExpiry) {
                    credentials.expiry_date = parseInt(envTokenExpiry, 10);
                }
                
                oauth2Client.setCredentials(credentials);
                return; // Skip file-based credential loading
            }
        } else {
            // Fall back to file-based credentials
            // Check for OAuth keys in current directory first, then in config directory
            const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
            let oauthPath = OAUTH_PATH;
            
            if (fs.existsSync(localOAuthPath)) {
                // If found in current directory, copy to config directory
                fs.copyFileSync(localOAuthPath, OAUTH_PATH);
                console.log('OAuth keys found in current directory, copied to global config.');
            }

            if (!fs.existsSync(OAUTH_PATH)) {
                console.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
                process.exit(1);
            }

            const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
            const keys = keysContent.installed || keysContent.web;
            
            if (!keys) {
                console.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
                process.exit(1);
            }

            oauth2Client = new OAuth2Client(
                keys.client_id,
                keys.client_secret,
                REDIRECT_URL
            );

            if (fs.existsSync(CREDENTIALS_PATH)) {
                const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
                oauth2Client.setCredentials(credentials);
            }
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

async function authenticate() {
    const server = http.createServer();
    
    // Set socket options for fast release
    server.keepAliveTimeout = 1000;
    server.headersTimeout = 2000;
    
    // Track all sockets for forceful cleanup
    const socketMap = new Map();
    server.on('connection', (socket) => {
        const socketId = `${socket.remoteAddress}:${socket.remotePort}`;
        socketMap.set(socketId, socket);
        socket.on('close', () => {
            socketMap.delete(socketId);
        });
    });
    
    // Function to clean up the server
    const cleanupServer = () => {
        try {
            // Close all open connections
            for (const socket of socketMap.values()) {
                socket.destroy();
            }
            
            // Close the server
            server.close();
            console.log('[DEBUG] Authentication one-time server closed successfully');
        } catch (err) {
            console.error('[DEBUG] Error closing authentication server:', err);
        }
    };
    
    server.listen(AUTH_SERVER_PORT);
    console.log(`[DEBUG] Authentication one-time server started on port ${AUTH_SERVER_PORT}`);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: ['https://www.googleapis.com/auth/gmail.modify'],
        });

        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        // Set a timeout to close the server if authentication doesn't complete
        const timeoutId = setTimeout(() => {
            console.log('[DEBUG] Authentication timed out after 5 minutes');
            cleanupServer();
            reject(new Error('Authentication timed out'));
        }, 5 * 60 * 1000); // 5 minutes timeout

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, REDIRECT_URL);
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                clearTimeout(timeoutId);
                cleanupServer();
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens));

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                
                // Clear timeout and cleanup
                clearTimeout(timeoutId);
                cleanupServer();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                clearTimeout(timeoutId);
                cleanupServer();
                reject(error);
            }
        });
    });
}

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).describe("List of label IDs to apply"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

// Define an extended type for the request that includes sessionId
interface ExtendedRequest {
    params: {
        name: string;
        arguments?: Record<string, any>;
    };
    method: string;
    sessionId?: string; // Add optional sessionId property
    userId?: string; // Add optional userId property
}

// Enhanced authentication function that returns auth URL
async function getAuthenticationUrl(userId: string): Promise<string> {
    console.log(`[DEBUG] Generating auth URL for user: ${userId}`);
    
    // Make sure auth server is running
    await startAuthServer();
    
    // Get a temporary OAuth client for generating the URL
    let oauthClient: OAuth2Client;
    
    // Check if credentials are provided via environment variables
    const envClientId = process.env.GMAIL_CLIENT_ID;
    const envClientSecret = process.env.GMAIL_CLIENT_SECRET;

    // If client ID and secret are provided via environment variables
    if (envClientId && envClientSecret) {
        oauthClient = new OAuth2Client(
            envClientId,
            envClientSecret,
            REDIRECT_URL
        );
    } else {
        // Fall back to file-based credentials
        if (!fs.existsSync(OAUTH_PATH)) {
            throw new Error('OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or ' + CONFIG_DIR);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;
        
        if (!keys) {
            throw new Error('Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
        }

        oauthClient = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            REDIRECT_URL
        );
    }
    
    // Generate auth URL for this specific user - ensure we get a refresh token with these settings
    const authUrl = oauthClient.generateAuthUrl({
        access_type: 'offline', // This is critical for getting a refresh token
        prompt: 'consent', // Force re-consent to ensure we get a refresh token
        scope: ['https://www.googleapis.com/auth/gmail.modify'],
        // Store the user ID as state parameter to match during callback
        state: userId
    });
    
    console.log(`[DEBUG] Generated auth URL with access_type=offline and prompt=consent`);
    
    return authUrl;
}

// Main function
async function main() {
    // Start with basic credential loading for backward compatibility
    await loadCredentials();

    // Special case for manual auth command
    if (process.argv[2] === 'auth') {
        await authenticate();
        console.log('Authentication completed successfully');
        process.exit(0);
    }
    
    // Special test case for debugging specific user ID
    if (process.argv[2] === 'test') {
        const testUserId = process.argv[3] || '63c6ac14fffcca1dec835575';
        console.log('='.repeat(80));
        console.log(`TESTING AUTHENTICATION FOR USER: ${testUserId}`);
        console.log('='.repeat(80));
        
        // Check credentials file
        const userCredentialsPath = path.join(CONFIG_DIR, `credentials_${testUserId}.json`);
        const fileExists = fs.existsSync(userCredentialsPath);
        console.log(`Credentials file exists: ${fileExists ? 'YES' : 'NO'} at ${userCredentialsPath}`);
        
        if (fileExists) {
            // Read and display file contents (partial)
            try {
                const fileContent = fs.readFileSync(userCredentialsPath, 'utf8');
                const credentials = JSON.parse(fileContent);
                console.log('Credentials file parsed successfully');
                console.log(`Contains refresh token: ${!!credentials.refresh_token ? 'YES' : 'NO'}`);
                console.log(`Contains access token: ${!!credentials.access_token ? 'YES' : 'NO'}`);
                if (credentials.expiry_date) {
                    const expiryDate = new Date(credentials.expiry_date);
                    const now = new Date();
                    console.log(`Token expiry: ${expiryDate.toISOString()}`);
                    console.log(`Expired: ${expiryDate < now ? 'YES' : 'NO'}`);
                }
            } catch (error) {
                console.log('Error reading credentials file:', error);
            }
        }
        
        // Try to get OAuth client
        console.log('\nTesting OAuth client creation...');
        try {
            console.log('Calling getOAuthClientForUser...');
            const oauthClient = await getOAuthClientForUser(testUserId);
            console.log(`OAuth client created: ${oauthClient ? 'SUCCESS' : 'FAILED'}`);
            
            if (oauthClient) {
                console.log('Testing a simple API call...');
                try {
                    const gmail = google.gmail({ version: 'v1', auth: oauthClient });
                    const profileResponse = await gmail.users.getProfile({ userId: 'me' });
                    console.log('API call successful!');
                    console.log(`Email address: ${profileResponse.data.emailAddress}`);
                } catch (apiError) {
                    console.log('API call failed:', apiError);
                }
            }
        } catch (error) {
            console.log('Error during OAuth client test:', error);
        }
        
        console.log('='.repeat(80));
        console.log('TEST COMPLETE');
        console.log('='.repeat(80));
        process.exit(0);
    }

    // Initialize but don't start the authentication server yet
    // It will be started on-demand when needed
    console.log('[DEBUG] Auth server will start on-demand when needed');

    // Initialize Gmail API for backward compatibility
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Set up cleanup for graceful shutdown
    process.on('SIGINT', () => {
        console.log('[DEBUG] SIGINT received, shutting down');
        closeAuthServer();
        // Allow some time for cleanup before exiting
        setTimeout(() => {
            process.exit(0);
        }, 500);
    });

    process.on('SIGTERM', () => {
        console.log('[DEBUG] SIGTERM received, shutting down');
        closeAuthServer();
        // Allow some time for cleanup before exiting
        setTimeout(() => {
            process.exit(0);
        }, 500);
    });

    // Handle MCP server disconnection
    process.on('disconnect', () => {
        console.log('[DEBUG] Parent process disconnected, shutting down');
        closeAuthServer();
        // Allow some time for cleanup before exiting
        setTimeout(() => {
            process.exit(0);
        }, 500);
    });
    
    // Handle uncaught exceptions to ensure cleanup
    process.on('uncaughtException', (error) => {
        console.error('[DEBUG] Uncaught exception:', error);
        closeAuthServer();
        // Allow some time for cleanup before exiting
        setTimeout(() => {
            process.exit(1);
        }, 500);
    });
    
    // Server implementation
    const server = new Server({
        name: "gmail",
        version: "1.0.0",
        capabilities: {
            tools: {},
        },
    });

    // Tool handlers
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: "check_auth_status",
                description: "Checks if user is authenticated and generates login URL if needed",
                inputSchema: zodToJsonSchema(CheckAuthStatusSchema),
            },
            {
                name: "send_email",
                description: "Sends a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "read_email",
                description: "Retrieves the content of a specific email",
                inputSchema: zodToJsonSchema(ReadEmailSchema),
            },
            {
                name: "search_emails",
                description: "Searches for emails using Gmail search syntax",
                inputSchema: zodToJsonSchema(SearchEmailsSchema),
            },
            {
                name: "modify_email",
                description: "Modifies email labels (move to different folders)",
                inputSchema: zodToJsonSchema(ModifyEmailSchema),
            },
            {
                name: "delete_email",
                description: "Permanently deletes an email",
                inputSchema: zodToJsonSchema(DeleteEmailSchema),
            },
            {
                name: "list_email_labels",
                description: "Retrieves all available Gmail labels",
                inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
            },
        ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        // Extract the basic parameters
        const { name, arguments: args } = request.params;

        // Extract userId directly from the arguments
        const userId = args?.userId as string;
        console.log(`Received request for tool: ${name}, userId from args: ${userId}`);
        
        try {
            switch (name) {
                case "check_auth_status": {
                    const validatedArgs = CheckAuthStatusSchema.parse(args);
                    
                    // Use the userId provided in the arguments
                    const userIdToCheck = validatedArgs.userId || userId;
                    
                    if (!userIdToCheck) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please provide a userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    console.log(`[DEBUG] Checking authentication status for user: ${userIdToCheck}`);
                    
                    // Check if credentials file exists
                    const userCredentialsPath = path.join(CONFIG_DIR, `credentials_${userIdToCheck}.json`);
                    const credentialsFileExists = fs.existsSync(userCredentialsPath);
                    
                    console.log(`[DEBUG] Credentials file at ${userCredentialsPath} exists: ${credentialsFileExists}`);
                    if (credentialsFileExists) {
                        try {
                            const fileContents = fs.readFileSync(userCredentialsPath, 'utf8');
                            console.log(`[DEBUG] Credentials file size: ${fileContents.length} bytes`);
                            console.log(`[DEBUG] File contents preview: ${fileContents.substring(0, 50)}...`);
                        } catch (error) {
                            console.error(`[DEBUG] Error reading credentials file:`, error);
                        }
                    }
                    
                    // Check if the user is authenticated
                    console.log(`[DEBUG] Calling isAuthenticated for user: ${userIdToCheck}`);
                    const authenticated = await isAuthenticated(userIdToCheck);
                    console.log(`[DEBUG] isAuthenticated result: ${authenticated}`);
                    
                    if (authenticated) {
                        console.log(`[DEBUG] User ${userIdToCheck} is authenticated, returning success response`);
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `User ${userIdToCheck} is already authenticated. You can proceed with Gmail operations.`,
                                },
                            ]
                        };
                    } else {
                        // Generate authentication URL
                        console.log(`[DEBUG] User ${userIdToCheck} is not authenticated, generating auth URL`);
                        const authUrl = await getAuthenticationUrl(userIdToCheck);
                        console.log(`[DEBUG] Generated auth URL: ${authUrl.substring(0, 50)}...`);
                        
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `User ${userIdToCheck} is not authenticated. Please visit this URL to authenticate with Gmail:\n\n${authUrl}\n\nAfter completing authentication in your browser, return here and let me know to continue with Gmail operations.`,
                                    authUrl: authUrl,
                                },
                            ]
                        };
                    }
                }
                
                case "send_email": {
                    // Check if args exists
                    if (!args) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing arguments for send_email tool.`,
                                },
                            ],
                        };
                    }

                    const validatedArgs = SendEmailSchema.parse({
                        to: args.to || [],
                        subject: args.subject || "",
                        body: args.body || "",
                        cc: args.cc,
                        bcc: args.bcc
                    });
                    
                    // Get userId from the arguments
                    if (!userId) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please include userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    // Ensure user is authenticated
                    const userOauth = await getOAuthClientForUser(userId);
                    if (!userOauth) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `You need to authenticate first. Use the check_auth_status tool to get started.`,
                                },
                            ],
                        };
                    }
                    
                    // Use the user-specific OAuth client
                    const userGmail = google.gmail({ version: 'v1', auth: userOauth });
                    
                    // Encode subject and other potential headers that might contain non-ASCII characters
                    const encodedSubject = encodeEmailHeader(validatedArgs.subject);
                    
                    const message = [
                        'From: me',
                        `To: ${validatedArgs.to.join(', ')}`,
                        validatedArgs.cc ? `Cc: ${validatedArgs.cc.join(', ')}` : '',
                        validatedArgs.bcc ? `Bcc: ${validatedArgs.bcc.join(', ')}` : '',
                        `Subject: ${encodedSubject}`,
                        'MIME-Version: 1.0',
                        'Content-Type: text/plain; charset=UTF-8',
                        'Content-Transfer-Encoding: 7bit',
                        '',
                        validatedArgs.body
                    ].filter(Boolean).join('\r\n');

                    const encodedMessage = Buffer.from(message).toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');

                    const response = await userGmail.users.messages.send({
                        userId: 'me',
                        requestBody: {
                            raw: encodedMessage,
                        },
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email sent successfully with ID: ${response.data.id}`,
                            },
                        ],
                    };
                }

                case "read_email": {
                    // Check if args exists
                    if (!args) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing arguments for read_email tool.`,
                                },
                            ],
                        };
                    }
                    
                    const validatedArgs = ReadEmailSchema.parse(args);
                    
                    // Get userId from the arguments
                    if (!userId) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please include userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    // Ensure user is authenticated
                    const userOauth = await getOAuthClientForUser(userId);
                    if (!userOauth) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `You need to authenticate first. Use the check_auth_status tool to get started.`,
                                },
                            ],
                        };
                    }
                    
                    // Use the user-specific OAuth client
                    const userGmail = google.gmail({ version: 'v1', auth: userOauth });
                    
                    const response = await userGmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const headers = response.data.payload?.headers || [];
                    const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';

                    // Extract email content using the recursive function
                    const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});
                    
                    // Use plain text content if available, otherwise use HTML content
                    // (optionally, you could implement HTML-to-text conversion here)
                    let body = text || html || '';
                    
                    // If we only have HTML content, add a note for the user
                    const contentTypeNote = !text && html ? 
                        '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';
                    
                    // Get attachment information
                    const attachments: EmailAttachment[] = [];
                    const processAttachmentParts = (part: GmailMessagePart, path: string = '') => {
                        if (part.body && part.body.attachmentId) {
                            const filename = part.filename || `attachment-${part.body.attachmentId}`;
                            attachments.push({
                                id: part.body.attachmentId,
                                filename: filename,
                                mimeType: part.mimeType || 'application/octet-stream',
                                size: part.body.size || 0
                            });
                        }
                        
                        if (part.parts) {
                            part.parts.forEach((subpart: GmailMessagePart) => 
                                processAttachmentParts(subpart, `${path}/parts`)
                            );
                        }
                    };
                    
                    if (response.data.payload) {
                        processAttachmentParts(response.data.payload as GmailMessagePart);
                    }
                    
                    // Add attachment info to output if any are present
                    const attachmentInfo = attachments.length > 0 ? 
                        `\n\nAttachments (${attachments.length}):\n` + 
                        attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size/1024)} KB)`).join('\n') : '';

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Subject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                            },
                        ],
                    };
                }

                case "search_emails": {
                    // Check if args exists
                    if (!args) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing arguments for search_emails tool.`,
                                },
                            ],
                        };
                    }
                    
                    const validatedArgs = SearchEmailsSchema.parse(args);
                    
                    // Get userId from the arguments
                    if (!userId) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please include userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    // Ensure user is authenticated
                    const userOauth = await getOAuthClientForUser(userId);
                    if (!userOauth) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `You need to authenticate first. Use the check_auth_status tool to get started.`,
                                },
                            ],
                        };
                    }
                    
                    // Use the user-specific OAuth client
                    const userGmail = google.gmail({ version: 'v1', auth: userOauth });
                    
                    const response = await userGmail.users.messages.list({
                        userId: 'me',
                        q: validatedArgs.query,
                        maxResults: validatedArgs.maxResults || 10,
                    });

                    const messages = response.data.messages || [];
                    const results = await Promise.all(
                        messages.map(async (msg) => {
                            const detail = await userGmail.users.messages.get({
                                userId: 'me',
                                id: msg.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date'],
                            });
                            const headers = detail.data.payload?.headers || [];
                            return {
                                id: msg.id,
                                subject: headers.find(h => h.name === 'Subject')?.value || '',
                                from: headers.find(h => h.name === 'From')?.value || '',
                                date: headers.find(h => h.name === 'Date')?.value || '',
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: results.map(r => 
                                    `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                                ).join('\n'),
                            },
                        ],
                    };
                }

                case "modify_email": {
                    // Check if args exists
                    if (!args) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing arguments for modify_email tool.`,
                                },
                            ],
                        };
                    }
                    
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    
                    // Get userId from the arguments
                    if (!userId) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please include userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    // Ensure user is authenticated
                    const userOauth = await getOAuthClientForUser(userId);
                    if (!userOauth) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `You need to authenticate first. Use the check_auth_status tool to get started.`,
                                },
                            ],
                        };
                    }
                    
                    // Use the user-specific OAuth client
                    const userGmail = google.gmail({ version: 'v1', auth: userOauth });
                    
                    await userGmail.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: {
                            addLabelIds: validatedArgs.labelIds,
                        },
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} labels updated successfully`,
                            },
                        ],
                    };
                }

                case "delete_email": {
                    // Check if args exists
                    if (!args) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing arguments for delete_email tool.`,
                                },
                            ],
                        };
                    }
                    
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    
                    // Get userId from the arguments
                    if (!userId) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please include userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    // Ensure user is authenticated
                    const userOauth = await getOAuthClientForUser(userId);
                    if (!userOauth) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `You need to authenticate first. Use the check_auth_status tool to get started.`,
                                },
                            ],
                        };
                    }
                    
                    // Use the user-specific OAuth client
                    const userGmail = google.gmail({ version: 'v1', auth: userOauth });
                    
                    await userGmail.users.messages.delete({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} deleted successfully`,
                            },
                        ],
                    };
                }
                
                case "list_email_labels": {
                    // Get userId from the arguments
                    if (!userId) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Missing userId. Please include userId in your request.`,
                                },
                            ],
                        };
                    }
                    
                    // Ensure user is authenticated
                    const userOauth = await getOAuthClientForUser(userId);
                    if (!userOauth) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `You need to authenticate first. Use the check_auth_status tool to get started.`,
                                },
                            ],
                        };
                    }
                    
                    // Use the user-specific OAuth client
                    const userGmail = google.gmail({ version: 'v1', auth: userOauth });
                    
                    const response = await userGmail.users.labels.list({
                        userId: 'me',
                    });

                    const labels = response.data.labels || [];
                    const formattedLabels = labels.map(label => ({
                        id: label.id,
                        name: label.name,
                        type: label.type,
                        // Include additional useful information about each label
                        messageListVisibility: label.messageListVisibility,
                        labelListVisibility: label.labelListVisibility,
                        // Only include count if it's a system label (as custom labels don't typically have counts)
                        messagesTotal: label.messagesTotal,
                        messagesUnread: label.messagesUnread,
                        color: label.color
                    }));

                    // Group labels by type (system vs user) for better organization
                    const systemLabels = formattedLabels.filter(label => label.type === 'system');
                    const userLabels = formattedLabels.filter(label => label.type === 'user');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${labels.length} labels (${systemLabels.length} system, ${userLabels.length} user):\n\n` +
                                    "System Labels:\n" +
                                    systemLabels.map(l => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                                    "\nUser Labels:\n" +
                                    userLabels.map(l => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
                            },
                        ],
                    };
                }

                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: ${error.message}`,
                    },
                ],
            };
        }
    });

    const transport = new StdioServerTransport();
    server.connect(transport);
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});