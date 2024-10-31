import fido2 from '../../lib/fido2';
import { PrismaClient } from '@prisma/client';
import { getCookies } from '../../lib/cookies';
import { verifyJwtToken } from '../../lib/jwt';
import coseToJwk from 'cose-to-jwk';
import jwkToPem from 'jwk-to-pem';

const prisma = new PrismaClient();

// Helper function to convert COSE public key to PEM format
const coseToPem = async (cosePublicKey) => {
    const coseBuffer = Buffer.isBuffer(cosePublicKey) ? cosePublicKey : Buffer.from(cosePublicKey, 'base64');
    const jwk = coseToJwk(coseBuffer);
    return jwkToPem(jwk); // Return the PEM format
};

// Function to handle different input data formats and convert them to ArrayBuffer
function toBuffer(data) {
    if (Array.isArray(data)) return new Uint8Array(data).buffer;
    if (typeof data === 'string') return Uint8Array.from(Buffer.from(data, 'base64')).buffer;
    if (data instanceof Uint8Array) return data.buffer;
    if (data instanceof ArrayBuffer) return data;
    if (typeof data === 'object' && Object.keys(data).every(key => !isNaN(key))) {
        return new Uint8Array(Object.values(data)).buffer;
    }
    console.error("Unexpected data type:", data);
    throw new Error("Invalid input type: expected an array, base64 string, Uint8Array, or ArrayBuffer");
}

// Main authentication handler
export default async function handler(req, res) {
    try {
        // Retrieve JWT token from cookies
        const cookies = getCookies(req);
        const token = cookies.authToken;
        if (!token) return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });

        // Decode and verify JWT token to get the challenge
        const tokenData = verifyJwtToken(token);
        if (!tokenData || !tokenData.challenge) return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });

        // Convert challenge to base64url format
        const challenge = Buffer.from(tokenData.challenge, 'base64').toString('base64url');

        // Extract credential data from request body
        const { id, rawId, authenticatorData, clientDataJSON, signature, userHandle } = req.body;
        if (!clientDataJSON || !authenticatorData || !signature) {
            return res.status(400).json({ success: false, error: 'Incomplete authentication data' });
        }

        // Retrieve stored credential information from database
        const credential = await prisma.webauthnCredential.findUnique({ where: { credId: id } });
        if (!credential) {
            return res.status(404).json({ success: false, error: 'Credential not found.' });
        }

        // Convert COSE to PEM for public key verification
        const pemPublicKey = await coseToPem(credential.credPublicKey);

        // Verify the assertion result using FIDO2 library
        const verification = await fido2.assertionResult(
            {
                id: toBuffer(id),
                rawId: toBuffer(rawId),
                response: {
                    clientDataJSON: toBuffer(clientDataJSON),
                    authenticatorData: toBuffer(authenticatorData),
                    signature: toBuffer(signature),
                    userHandle: toBuffer(credential.userId),
                }
            },
            {
                challenge,
                origin: process.env.EXPECTED_ORIGIN || 'http://localhost:3000',
                factor: 'first',
                prevCounter: credential.counter, // Use the stored counter if supported
                publicKey: pemPublicKey,
                userHandle: toBuffer(credential.userId),
            }
        );

        // Ensure the request and expectations were validated correctly
        if (!verification.audit.validRequest) {
            return res.status(400).json({ success: false, error: 'Authentication verification failed' });
        }

        // Determine if the authenticator supports the built-in counter
        const counterSupported = verification.audit.info.get('counter-supported') === 'true';
        const newCounter = verification.authnrData.get('counter');

        if (counterSupported) {
            // Handle built-in counter check if supported by the authenticator
            // This checks for cloned credentials by comparing counters
            if (newCounter <= credential.counter) {
                return res.status(403).json({
                    success: false,
                    error: 'Security alert: Possible cloned credential detected',
                });
            }
            // Update the built-in counter in the database if authentication is successful
            await prisma.webauthnCredential.update({
                where: { credId: id },
                data: { counter: newCounter, lastUsed: new Date() },
            });
        } else {
            // If built-in counter is not supported, use custom counter as a fallback
            const savedCustomCounter = credential.loginCounter || 0;
            const updatedCustomCounter = savedCustomCounter + 1;

            // Custom counter check for cloned credentials
            if (updatedCustomCounter <= savedCustomCounter) {
                return res.status(403).json({
                    success: false,
                    error: 'Security alert: Possible cloned credential detected',
                });
            }

            // Update custom counter in the database for devices without built-in counter support
            await prisma.webauthnCredential.update({
                where: { credId: id },
                data: { loginCounter: updatedCustomCounter, lastUsed: new Date() },
            });
        }

        // Update user's last login timestamp
        await prisma.user.update({
            where: { id: credential.userId },
            data: { lastUsed: new Date() },
        });

        // Successful authentication response
        res.status(200).json({ success: true, message: 'Authentication successful!' });
    } catch (error) {
        console.error('Error during authentication verification:', error);
        res.status(400).json({ success: false, error: 'An error occurred during verification' });
    }
}
