import fido2 from '../../lib/fido2';
import { PrismaClient } from '@prisma/client';
import { getCookies } from '../../lib/cookies';
import { verifyJwtToken } from '../../lib/jwt';
import coseToJwk from 'cose-to-jwk';
import jwkToPem from 'jwk-to-pem';

const prisma = new PrismaClient();

const coseToPem = (cosePublicKey) => {
    // Convert the COSE key to a Buffer if it's not already
    const coseBuffer = Buffer.isBuffer(cosePublicKey) ? cosePublicKey : Buffer.from(cosePublicKey, 'base64');
    
    // Convert COSE to JWK
    const jwk = coseToJwk(coseBuffer);
    
    // Convert JWK to PEM
    return jwkToPem(jwk);
};

function toBuffer(data) {
    if (Array.isArray(data)) {
        return new Uint8Array(data).buffer;
    } else if (typeof data === 'string') {
        return Uint8Array.from(Buffer.from(data, 'base64')).buffer;
    } else if (data instanceof Uint8Array) {
        return data.buffer;
    } else if (data instanceof ArrayBuffer) {
        return data;
    } else if (typeof data === 'object' && Object.keys(data).every(key => !isNaN(key))) {
        // Convert numeric-keyed object to array
        return new Uint8Array(Object.values(data)).buffer;
    } else {
        console.error("Unexpected data type:", data);
        throw new Error("Invalid input type: expected an array, base64 string, Uint8Array, or ArrayBuffer");
    }
}

export default async function handler(req, res) {
    try {
        const cookies = getCookies(req);
        const token = cookies.authToken;
        if (!token) {
            return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });
        }

        const tokenData = verifyJwtToken(token);
        if (!tokenData || !tokenData.challenge) {
            return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });
        }

        // Transform the challenge to base64url
        const challenge = Buffer.from(tokenData.challenge, 'base64').toString('base64url');

        const { id, rawId, authenticatorData, clientDataJSON, signature, userHandle } = req.body;
        if (!clientDataJSON || !authenticatorData || !signature) {
            return res.status(400).json({ success: false, error: 'Incomplete authentication data' });
        }

        const credential = await prisma.webauthnCredential.findUnique({ where: { credId: id } });
        if (!credential) {
            return res.status(404).json({ success: false, error: 'Credential not found.' });
        }
        
        const pemPublicKey = await coseToPem(credential.credPublicKey); // Convert COSE to PEM

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
        const newCounter = verification.authnrData.counter;
        if (newCounter <= credential.counter) {
            return res.status(403).json({
                success: false,
                error: 'Security alert: Possible cloned credential detected',
            });
        }

        await prisma.webauthnCredential.update({
            where: { credId: id },
            data: { counter: newCounter },
        });

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
