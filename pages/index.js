import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';


export default function Home() {
    const [message, setMessage] = useState('');
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const router = useRouter(); // Initialize the router

    function base64UrlToUint8Array(base64Url) {
        if (typeof base64Url !== 'string') {
            console.error('Expected base64Url to be a string but got:', typeof base64Url);
            return new Uint8Array();
        }
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(base64);
        const outputArray = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            outputArray[i] = raw.charCodeAt(i);
        }
        return outputArray;
    }

    // // Helper function to encode ArrayBuffer to base64url
    // function toBase64Url(buffer) {
    //     return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
    //         .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    // }

    useEffect(() => {
        if (message) {
            const timer = setTimeout(() => setMessage(''), 3000); // Clear message after 3 seconds
            return () => clearTimeout(timer); // Cleanup on unmount or if message changes
        }
    }, [message]);

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
                setIsLoggedIn(true); // Automatically set the user as logged in after successful registration
            } else {
                setMessage('Registration verification failed. Please manually delete any passkey from your device settings.');
            }
        } catch (error) {
            console.error('Registration error:', error);
            setMessage(`Error: ${error.message}`);
        }
    };

    const handleLogin = async () => {
        try {
            const optionsResponse = await fetch('/api/generate-authentication-options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });

            if (!optionsResponse.ok) {
                throw new Error('Failed to fetch authentication options.');
            }

            const options = await optionsResponse.json();
            options.challenge = base64UrlToUint8Array(options.challenge).buffer;
            const assertion = await navigator.credentials.get({
                publicKey: options,
            });
            const verificationResponse = await fetch('/api/verify-authentication', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    id: assertion.id,
                    rawId: Array.from(new Uint8Array(assertion.rawId)),
                    clientDataJSON: Array.from(new Uint8Array(assertion.response.clientDataJSON)),
                    authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
                    signature: Array.from(new Uint8Array(assertion.response.signature)),
                    userHandle: assertion.response.userHandle ?  new Uint8Array(assertion.response.userHandle) : null,
                }),
            });

            const verificationResult = await verificationResponse.json();
            if (verificationResult.success) {
                setMessage('Login successful!');
                setIsLoggedIn(true); // Set isLoggedIn to true after successful login
            } else {
                setMessage('Login failed. Please try again.');
            }
        } catch (error) {
            if (error.name === "NotAllowedError") {
                setMessage("No passkey found. You are not registered. Please register.");
            } else {
                console.error('Login error:', error);
                setMessage(`Error during login: ${error.message}`);
            }
        }
    };

    const handleLogout = async () => {
        try {
            const response = await fetch('/api/logout', { method: 'POST' });
            const result = await response.json();
            if (result.success) {
                setIsLoggedIn(false); // Set isLoggedIn to false after logout
                setMessage(result.message);
                // Use router.push to navigate without a hard refresh
                router.push('/');
            } else {
                setMessage('Logout failed. Please try again.');
            }
        } catch (error) {
            console.error('Logout error:', error);
            setMessage(`Error during logout: ${error.message}`);
        }
    };

    return (
        <div style={{ padding: '2rem' }}>
            <h1>Iden2 Usernameless, Passwordless Authentication</h1>
            {isLoggedIn ? (
                <button onClick={handleLogout}>Logout</button>
            ) : (
                <>
                    <button onClick={handleRegister}>Register</button>
                    &nbsp;&nbsp;
                    <button onClick={handleLogin}>Login</button>
                </>
            )}
            {message && <p>{message}</p>}
        </div>
    );
}
