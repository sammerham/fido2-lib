import { useState } from 'react';

export default function Home() {
    const [message, setMessage] = useState('');

    // Helper function to decode base64 URL to Uint8Array
    function base64UrlToUint8Array(base64Url) {
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(base64);
        const outputArray = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            outputArray[i] = raw.charCodeAt(i);
        }
        return outputArray;
    }

    // Check if a credential already exists using the Credential Management API
    const checkIfRegistered = async () => {
        try {
            const credential = await navigator.credentials.get({
                publicKey: { challenge: new Uint8Array(32) }
            });
            if (credential) {
                setMessage(`You are already registered.`);
                return credential.id;
            }
            return null;
        } catch (error) {
            if (error.name === "NotAllowedError") {
                setMessage("User interaction required.");
            } else {
                console.error('Error checking credentials:', error);
                setMessage(`Error checking registration: ${error.message}`);
            }
            return null;
        }
    };

    // Main registration handler
    const handleRegister = async () => {
        let publicKeyCredential;
        try {
            const existingUserId = await checkIfRegistered();
            if (existingUserId) {
                setMessage(`User already registered. Please log in.`);
                return;
            }

            const optionsResponse = await fetch('/api/generate-registration-options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });

            if (!optionsResponse.ok) {
                throw new Error('Failed to fetch registration options.');
            }

            const options = await optionsResponse.json();
            options.challenge = base64UrlToUint8Array(options.challenge).buffer;
            options.user.id = base64UrlToUint8Array(options.user.id).buffer;

            publicKeyCredential = await navigator.credentials.create({ publicKey: options });

            const verificationResponse = await fetch('/api/verify-registration', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    id: publicKeyCredential.id,
                    rawId: Array.from(new Uint8Array(publicKeyCredential.rawId)),
                    clientDataJSON: Array.from(new Uint8Array(publicKeyCredential.response.clientDataJSON)),
                    attestationObject: Array.from(new Uint8Array(publicKeyCredential.response.attestationObject)),
                }),
            });

            const verificationResult = await verificationResponse.json();
            if (verificationResult.success) {
                setMessage('Registration successful!');
            } else {
                // Verification failed - inform the user about manual deletion
                setMessage('Registration verification failed. Please manually delete any passkey from your device settings.');
            }
        } catch (error) {
            // Explicit message for manual deletion if an error occurs
            console.error('Registration error:', error);
            if (publicKeyCredential) {
                setMessage('Registration failed. Please manually delete any unverified passkey from your device settings.');
            } else {
                setMessage(`Error: ${error.message}`);
            }
        }
    };

    return (
        <div style={{ padding: '2rem' }}>
            <h1>Usernameless, Passwordless Registration</h1>
            {message && <p>{message}</p>}
            <button onClick={handleRegister}>Register</button>
        </div>
    );
}
