import { PrismaClient } from '@prisma/client';
import { getCookies, setCookie } from '../../lib/cookies';
import { verifyJwtToken } from '../../lib/jwt';
import fido2 from '../../lib/fido2';
import { nanoid } from 'nanoid';

const prisma = new PrismaClient();

export default async function handler(req, res) {
    try {
        const cookies = getCookies(req);
        const token = cookies.authToken;
        if (!token) {
            return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });
        }

        const tokenData = verifyJwtToken(token);
        if (!tokenData) {
            return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });
        }

        const { userId, challenge } = tokenData;
        const { id, rawId, clientDataJSON, attestationObject } = req.body;

        // Attempt to parse and validate the attestation result
        const verification = await fido2.attestationResult(
            {
                id,
                rawId: Uint8Array.from(rawId).buffer,
                response: {
                    clientDataJSON: Uint8Array.from(clientDataJSON).buffer,
                    attestationObject: Uint8Array.from(attestationObject).buffer,
                },
            },
            {
                challenge,
                origin: process.env.EXPECTED_ORIGIN || 'http://localhost:3000',
                factor: 'either',
            }
        );

        // Ensure verification has the necessary data
        if (!verification || !verification.authnrData || !verification.clientData) {
            throw new Error('Verification failed: required data missing.');
        }
        console.log("verification--->", verification);

        // Verification successful: Create user and credential in the database
        const credentialId = Buffer.from(verification.authnrData.get('credId')).toString('base64url');
        const publicKeyBase64URL = Buffer.from(verification.authnrData.get('credentialPublicKeyCose')).toString('base64url');

        await prisma.user.create({
            data:{
                id: userId, 
                createdAt: new Date(),
                lastUsed: new Date(),
                webauthnCredentials: {
                    create: {
                        id: nanoid(), 
                        credId: credentialId,
                        credPublicKey: publicKeyBase64URL, 
                        counter: verification.authnrData.get('counter'),
                        deviceType: 'platform', 
                        backEligible: false, 
                        backStatus: false, 
                        createdAt: new Date(),
                        lastUsed: new Date(),
                    },
                },
            },
        });


        // Clear JWT cookie after successful registration and respond with success
        setCookie(res, 'authToken', '', { maxAge: 0 });
        return res.status(200).json({ success: true });

    } catch (error) {
        console.error('Error during registration verification:', error);
        return res.status(400).json({ success: false, error: 'An error occurred during verification' });
    }
}
