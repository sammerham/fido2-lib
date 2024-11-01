import fido2 from '../../lib/fido2';
import { PrismaClient } from '@prisma/client';
import { getCookies } from '../../lib/cookies';
import { verifyJwtToken } from '../../lib/jwt';
import { PublicKey} from 'fido2-lib';

const prisma = new PrismaClient();
const FidoPublicKey = new PublicKey();

// Convert COSE public key to PEM for cryptographic operations
const coseToPem = async (cosePublicKey) => {
    const coseBuffer = Buffer.isBuffer(cosePublicKey) ? cosePublicKey : Buffer.from(cosePublicKey, 'base64');
    const publicKeyJwk = await FidoPublicKey.fromCose(coseBuffer); // Converts COSE to JWK
    const publicKeyPem = await FidoPublicKey.toPem(publicKeyJwk); // Converts JWK to PEM
    return publicKeyPem; 
};

// Convert different input types to ArrayBuffer format
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

export default async function handler(req, res) {
    try {
        // Get and verify JWT for user authentication
        const cookies = getCookies(req);
        const token = cookies.authToken;
        if (!token) return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });

        const tokenData = verifyJwtToken(token);
        if (!tokenData || !tokenData.challenge) return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });

        const challenge = Buffer.from(tokenData.challenge, 'base64').toString('base64url');

        // Parse the WebAuthn response
        const { id, rawId, authenticatorData, clientDataJSON, signature, userHandle } = req.body;
        if (!clientDataJSON || !authenticatorData || !signature) {
            return res.status(400).json({ success: false, error: 'Incomplete authentication data' });
        }

        // Fetch credential from the database for verification
        const credential = await prisma.webauthnCredential.findUnique({ where: { credId: id } });
        if (!credential) return res.status(404).json({ success: false, error: 'Credential not found.' });

        // Convert COSE to PEM for verification with FIDO2 library
        const pemPublicKey = await coseToPem(credential.credPublicKey);

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
                prevCounter: credential.counter,
                publicKey: pemPublicKey,
                userHandle: toBuffer(credential.userId),
            }
        );

        if (!verification.audit.validRequest) {
            return res.status(400).json({ success: false, error: 'Authentication verification failed' });
        }

        const counterSupported = verification.audit.info.get('counter-supported') === 'true';
        const newCounter = verification.authnrData.get('counter');

        if (counterSupported) {
            if (newCounter <= credential.counter) {
                return res.status(403).json({
                    success: false,
                    error: 'Security alert: Possible cloned credential detected',
                });
            }
            await prisma.webauthnCredential.update({
                where: { credId: id },
                data: { counter: newCounter, lastUsed: new Date() },
            });
        } else {
            const savedCustomCounter = credential.loginCounter || 0;
            const updatedCustomCounter = savedCustomCounter + 1;
            if (updatedCustomCounter <= savedCustomCounter) {
                return res.status(403).json({
                    success: false,
                    error: 'Security alert: Possible cloned credential detected',
                });
            }
            await prisma.webauthnCredential.update({
                where: { credId: id },
                data: { loginCounter: updatedCustomCounter, lastUsed: new Date() },
            });
        }

        await prisma.user.update({
            where: { id: credential.userId },
            data: { lastUsed: new Date() },
        });

        res.status(200).json({ success: true, message: 'Authentication successful!' });
    } catch (error) {
        console.error('Error during authentication verification:', error);
        res.status(400).json({ success: false, error: 'An error occurred during verification' });
    }
}
