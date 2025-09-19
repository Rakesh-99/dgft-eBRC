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
const accessTokenBaseUrl = process.env.ACCESS_TOKEN_URL;
const currentIP = process.env.CURRENT_IP;



//  generating  Sandbox Token : ---> 
export const getSandboxToken = async () => {
    try {
        const salt = crypto.randomBytes(32);
        const derivedKey = crypto.pbkdf2Sync(clientSecret, salt, 65536, 32, "sha256");
        const finalSecret = Buffer.concat([salt, derivedKey]).toString("base64");

        const response = await axios.post(
            `${accessTokenBaseUrl}/getAccessToken`,
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
        return response;
    } catch (error) {

        throw new Error("Authentication failed with DGFT Sandbox", error);
    }
};

// --- helper: printable 32-char secret (keyboard characters) ---
function generatePrintableSecret32() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
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
        const secretPlain = generatePrintableSecret32();

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
            secretPlain,        //  encrypt this with DGFT public key (secretVal)
            encodedData,        // to go into request.data
            payloadBase64       // for signing 
        };
    } catch (encryptError) {
        console.error("Encryption error:", encryptError);
        throw new Error(`Payload encryption failed: ${encryptError.message}`);
    }
}


// helper fn() to create digital signature : --> 

// --- createDigitalSignature: 
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
                oaepHash: 'sha256'
            },
            Buffer.from(secretPlain, 'utf8')
        ).toString('base64');

        return encryptedKey;
    } catch (keyError) {
        console.error("AES key encryption error:", keyError);
        throw new Error(`AES key encryption failed: ${keyError.message}`);
    }
}

// --- decryptResponse: decrypt and verify DGFT response using same secret and dgftPublicKey ---
function decryptResponse(responseBody, secretPlain) {
    try {
        const combined = Buffer.from(responseBody.data, 'base64');
        const iv = combined.slice(0, 12);
        const salt = combined.slice(12, 44);
        const authTag = combined.slice(combined.length - 16);
        const ciphertext = combined.slice(44, combined.length - 16);

        const saltedKey = crypto.createHash('sha256')
            .update(Buffer.from(secretPlain, 'utf8'))
            .update(salt)
            .digest(); // 32 bytes

        const decipher = crypto.createDecipheriv('aes-256-gcm', saltedKey, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        const payloadBase64 = decrypted.toString('utf8');

        // Verify signature
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(payloadBase64);
        const isVerified = verifier.verify(dgftPublicKey, responseBody.sign, 'base64');
        if (!isVerified) {
            throw new Error('Response signature verification failed');
        }

        // Decode base64 to JSON string and parse
        const payloadJson = Buffer.from(payloadBase64, 'base64').toString('utf8');
        return JSON.parse(payloadJson);
    } catch (decryptError) {
        console.error("Decryption error:", decryptError);
        throw new Error(`Response decryption failed: ${decryptError.message}`);
    }
}

//   Step 2. fn() to fill/submit data on eBRC dgft in sandbox envirenment with IP detection : --> 
export const fileEbrcService = async (payload) => {
    try {
        console.log("=== REQUEST DEBUG ===");
        console.log("Current public IP:", currentIP);
        console.log("Client ID:", clientId);
        console.log("Base URL:", baseUrl);

        const tokenResponse = await getSandboxToken();
        const accessToken = tokenResponse.data.accessToken;
        try {
            const tokenPayload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
            console.log("=== TOKEN PAYLOAD ===");
            console.log(tokenPayload);
        } catch (e) {
            console.error("Failed to decode access token:", e.message);
        }
        console.log("Access token obtained successfully");
        console.log("Token length:", accessToken.length);

        const endpoint = `${baseUrl}/pushIRMToGenEBRC`;
        console.log("Endpoint:", endpoint);

        // Encrypt payload using AES-256-GCM
        const encryptionResult = encryptPayload(payload);
        console.log("Payload encrypted successfully");

        // Create RSA digital signature - FIX: Sign the encrypted data
        const signature = createDigitalSignature(encryptionResult.encodedData);
        console.log("Signature created successfully");

        // Encrypt AES key with DGFT's public key
        const encryptedAESKey = encryptAESKey(encryptionResult.secretPlain);
        console.log("AES key encrypted successfully");

        // Prepare the request body as per DGFT spec
        const requestBody = {
            data: encryptionResult.encodedData,
            sign: signature
        };

        const headers = {
            "Content-Type": "application/json",
            "accessToken": accessToken,
            "client_id": clientId,
            "secretVal": encryptedAESKey,
            "x-api-key": apiKey
        };

        console.log("=== SENDING REQUEST ===");
        console.log("Headers:", JSON.stringify(headers, null, 2));
        console.log("Request body size:", JSON.stringify(requestBody).length);

        // Make the request
        const response = await axios.post(endpoint, requestBody, {
            headers: headers,
            timeout: 30000
        });

        // Decrypt and verify the response
        const decryptedData = decryptResponse(response.data, encryptionResult.secretPlain);

        console.log("eBRC data filed successfully!");
        return decryptedData;

    } catch (error) {
        console.error("=== ERROR ANALYSIS ===");
        console.error("Error type:", error.constructor.name);
        console.error("Error message:", error.message);

        if (error.response) {
            console.error("Response status:", error.response.status);
            console.error("Response data:", error.response.data);
            console.error("Response headers:", JSON.stringify(error.response.headers, null, 2));
        } else if (error.request) {
            console.error("No response received:", error.request);
        } else {
            console.error("Request setup error:", error.message);
        }

        if (error.response?.status === 401) {
            throw new Error('Authentication failed, please verify the client Id and client secret');
        }
        if (error.response?.status === 403) {
            throw new Error(`IP Whitelisting Required: Add ${currentIP} to DGFT sandbox portal`);
        }

        throw new Error(`Request failed: ${error.message}`);
    }
};