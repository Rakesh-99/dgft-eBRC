import axios from "axios";
import dotenv from 'dotenv';
dotenv.config();
import crypto from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const baseUrl = process.env.DGFT_SANDBOX_URL;
const apiKey = process.env.X_API_KEY;
const clientId = process.env.CLIENT_ID;
const userPrivateKey = process.env.USER_PRIVATE_KEY;
const dgftPublicKey = process.env.DGFT_PUBLIC_KEY?.replace(/\\n/g, '\n');




// 🔹 helper fn() to get current public IP of system : --> 
const getCurrentIP = async () => {
    try {
        const response = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
        return response.data.ip;
    } catch (error) {
        console.log("Could not detect public IP:", error.message);
        return "Unknown";
    }
};

//  fetching Sandbox Token : ---> 
export const getSandboxToken = async () => {
    try {
        const salt = crypto.randomBytes(32);
        const derivedKey = crypto.pbkdf2Sync(clientSecret, salt, 65536, 32, "sha256");
        const finalSecret = Buffer.concat([salt, derivedKey]).toString("base64");

        const response = await axios.post(
            "https://apiservices.dgft.gov.in/genebrc/getAccessToken",
            {
                client_id: clientId,
                client_secret: finalSecret,
            },
            {
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": apiKey,
                },
                timeout: 15000
            }
        );
        return response.data.accessToken;
    } catch (error) {
        console.error("Authentication failed:", error.response?.data || error.message);
        throw new Error("Authentication failed with DGFT Sandbox");
    }
};

// --- helper: printable 32-char secret (keyboard characters) ---
function generatePrintableSecret32() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const rnd = crypto.randomBytes(32);
    let s = '';
    for (let i = 0; i < 32; i++) s += chars[rnd[i] % chars.length];
    return s;
}

//  helper fn() to generate dynamic AES key and encrypt payload : --> 
function encryptPayload(payload) {
    try {
        const payloadJson = JSON.stringify(payload);

        // Step 2 (spec): base64-encode the JSON
        const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64');

        // Generate a 32-char printable secret (spec prefers keyboard chars)
        const secretPlain = generatePrintableSecret32(); // <-- we'll encrypt this for secretVal

        // 32-byte random salt per spec
        const salt = crypto.randomBytes(32);

        // 12-byte IV for AES-GCM
        const iv = crypto.randomBytes(12);

        // saltedKey = SHA256(secretPlain || salt)
        const saltedKey = crypto.createHash('sha256')
            .update(Buffer.concat([Buffer.from(secretPlain, 'utf8'), salt]))
            .digest(); // 32 bytes

        const cipher = crypto.createCipheriv('aes-256-gcm', saltedKey, iv);
        const encrypted = Buffer.concat([
            cipher.update(payloadBase64, 'utf8'),
            cipher.final()
        ]);
        const authTag = cipher.getAuthTag();

        // Combine iv + salt + ciphertext + authTag (same order as examples in spec)
        const combined = Buffer.concat([iv, salt, encrypted, authTag]);
        const encodedData = combined.toString('base64');

        return {
            secretPlain,        // important: encrypt this with DGFT public key (secretVal)
            encodedData,        // to go into request.data
            payloadBase64       // for signing (sign this)
        };
    } catch (encryptError) {
        console.error("Encryption error:", encryptError);
        throw new Error(`Payload encryption failed: ${encryptError.message}`);
    }
}


// helper fn() to create digital signature : --> 

// --- createDigitalSignature: keep, but ensure we sign payloadBase64 (not encrypted blob) ---
function createDigitalSignature(dataToSign) {
    try {
        if (!userPrivateKey) {
            throw new Error("USER_PRIVATE_KEY not found in environment variables");
        }
        let privateKey = userPrivateKey.trim();

        if (!privateKey.startsWith('-----BEGIN')) {
            const lines = [];
            for (let i = 0; i < privateKey.length; i += 64) {
                lines.push(privateKey.substring(i, i + 64));
            }
            privateKey = [
                '-----BEGIN PRIVATE KEY-----',
                ...lines,
                '-----END PRIVATE KEY-----'
            ].join('\n');
        }

        const signer = crypto.createSign("RSA-SHA256");
        signer.update(dataToSign);
        // optionally .end() but not required
        const signature = signer.sign(privateKey, "base64");
        return signature;
    } catch (signError) {
        console.error("Signature error:", signError);
        throw new Error(`Digital signature failed: ${signError.message}`);
    }
}


// --- encryptAESKey: encrypt the plain-secret with DGFT public key using OAEP-SHA256 ---
function encryptAESKey(secretPlain) {
    try {
        if (!dgftPublicKey) throw new Error("DGFT_PUBLIC_KEY not found in environment variables");

        const encryptedKey = crypto.publicEncrypt(
            {
                key: dgftPublicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'      // IMPORTANT: match spec OAEP-SHA256
            },
            Buffer.from(secretPlain, 'utf8')
        ).toString('base64');

        return encryptedKey;
    } catch (keyError) {
        console.error("AES key encryption error:", keyError);
        throw new Error(`AES key encryption failed: ${keyError.message}`);
    }
}

//   Step 2. fn() to fill/submit data on eBRC dgft in sandbox envirenment with IP detection : --> 
export const fileEbrcService = async (payload) => {
    let currentIP = "Unknown";

    try {
        currentIP = await getCurrentIP();
        console.log(" Current public IP:", currentIP);

        const token = await getSandboxToken();
        console.log(" Token obtained successfully");

        //  sandbox endpoint
        const endpoint = `${baseUrl}/pushIRMToGenEBRC`;


        // Encrypt payload using AES-256-GCM
        const encryptionResult = encryptPayload(payload);


        // Create RSA digital signature

        const signature = createDigitalSignature(encryptionResult.payloadBase64);

        // Encrypt AES key with DGFT's public key

        const encryptedAESKey = encryptAESKey(encryptionResult.secretPlain);

        // Prepare the request body as per DGFT spec
        const requestBody = {
            data: encryptionResult.encodedData, // base64(iv+salt+cipher+authTag)
            sign: signature
        };

        //  headers as per DGFT specification
        const headers = {
            "Content-Type": "application/json",
            "accessToken": token,
            "client_id": clientId,
            "secretVal": encryptedAESKey,
            "x-api-key": apiKey,
            "requestId": payload.requestId || `REQ_${Date.now()}`
        };
        // Make the request
        const response = await axios.post(endpoint, requestBody, {
            headers: headers,
            timeout: 30000
        });

        console.log("eBRC data filed successfully!");
        return response.data;

    } catch (error) {
        console.error("DGFT Filing Error:", error.response?.status, error.response?.data || error.message);

        if (error.response?.status === 403) {
            // useful actionable message for IP-whitelisting
            console.error(`IP Whitelisting Required! Add ${currentIP} to DGFT sandbox portal`);
            throw new Error(`IP Whitelisting Required: Add ${currentIP} to DGFT sandbox portal`);
        }

        const errMsg = error.response?.data?.message || error.message || 'Filing failed';
        throw new Error(`DGFT API Error: ${errMsg}`);
    }
};