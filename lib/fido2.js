import { Fido2Lib } from 'fido2-lib';
const fido2 = new Fido2Lib({
    rpName: process.env.RP_NAME || 'Iden2_passKey',
    rpId: process.env.RP_ID || 'localhost',
    challengeSize: 128,
    timeout: 60000,
    attestation: "direct",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: true,
    authenticatorUserVerification: "required"
});
export default fido2;