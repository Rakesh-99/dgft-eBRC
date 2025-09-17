import axios from "axios";
import dotenv from 'dotenv';
dotenv.config();
import crypto from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const baseUrl = process.env.DGFT_SANDBOX_URL;
const apiKey = process.env.X_API_KEY;
const clientId = process.env.CLIENT_ID;
const userPrivateKey = process.env.USER_PRIVATE_KEY; // Your RSA private key from DGFT
const dgftPublicKey = process.env.DGFT_PUBLIC_KEY;



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

//  helper fn() to generate dynamic AES key and encrypt payload : --> 
function encryptPayload(payload) {
    try {
        // Generate 32-byte dynamic AES key
        const aesKey = crypto.randomBytes(32);

        // Generate 32-byte salt (DGFT requirement)
        const salt = crypto.randomBytes(32);

        // Generate 12-byte IV for AES-GCM
        const iv = crypto.randomBytes(12);

        // Convert payload to string
        const payloadString = JSON.stringify(payload);

        // Create AES key with salt using SHA256 (as per DGFT spec)
        const saltedKey = crypto.createHash('sha256').update(Buffer.concat([aesKey, salt])).digest();

        // Use AES-256-GCM 
        const cipher = crypto.createCipheriv('aes-256-gcm', saltedKey, iv);

        let encrypted = cipher.update(payloadString, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // Get the GCM authentication tag (16 bytes)
        const authTag = cipher.getAuthTag();

        // Combine IV + salt + encrypted data (as per DGFT spec)
        const combined = Buffer.concat([
            iv,           // 12 bytes
            salt,         // 32 bytes (REQUIRED by DGFT)
            encrypted     // variable length
        ]);

        const encodedData = combined.toString('base64');

        return {
            aesKey,
            encodedData,
            rawPayload: payloadString
        };

    } catch (encryptError) {
        console.error("Encryption error:", encryptError.message);
        throw new Error(`Payload encryption failed: ${encryptError.message}`);
    }
}

// helper fn() to create digital signature : --> 

function createDigitalSignature(data) {
    try {
        if (!userPrivateKey) {
            throw new Error("USER_PRIVATE_KEY not found in environment variables");
        }
        // Format the private key properly
        let privateKey = userPrivateKey.trim();

        // Add PEM headers if missing
        if (!privateKey.startsWith('-----BEGIN')) {
            // Split the key into 64-character lines
            const keyLines = [];
            for (let i = 0; i < privateKey.length; i += 64) {
                keyLines.push(privateKey.substring(i, i + 64));
            }

            privateKey = [
                '-----BEGIN PRIVATE KEY-----',
                ...keyLines,
                '-----END PRIVATE KEY-----'
            ].join('\n');
        }

        // Create RSA-SHA256 signature using your private key
        const signer = crypto.createSign("RSA-SHA256");
        signer.update(data);
        const signature = signer.sign(privateKey, "base64");

        return signature;

    } catch (signError) {
        console.error(" Signature error:", signError.message);
        throw new Error(`Digital signature failed: ${signError.message}`);
    }
}

//  helper fn() to encrypt AES key with DGFT public key
function encryptAESKey(aesKey) {
    try {
        if (!dgftPublicKey) {
            throw new Error("DGFT_PUBLIC_KEY not found in environment variables");
        }

        // DGFT_PUBLIC_KEY is already a certificate with proper headers - use it directly
        const encryptedKey = crypto.publicEncrypt(
            {
                key: dgftPublicKey, // Use the certificate directly
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
            },
            aesKey
        ).toString("base64");

        return encryptedKey;

    } catch (keyError) {
        console.error("AES key encryption error:", keyError.message);
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
        const signature = createDigitalSignature(encryptionResult.rawPayload);

        // Encrypt AES key with DGFT's public key
        const encryptedAESKey = encryptAESKey(encryptionResult.aesKey);

        // Prepare the request body as per DGFT spec
        const requestBody = {
            data: encryptionResult.encodedData,  // Base64 encrypted payload
            sign: signature                      // RSA-SHA256 signature
        };

        //  headers as per DGFT specification
        const headers = {
            "Content-Type": "application/json",
            "accessToken": token,                // bearer token from getAccessToken
            "client_id": clientId,
            "secretVal": encryptedAESKey,       // RSA-encrypted AES key
            "x-api-key": apiKey
        };

        // Make the request
        const response = await axios.post(endpoint, requestBody, {
            headers: headers,
            timeout: 30000
        });

        console.log("eBRC data filed successfully!");
        return response.data;

    } catch (error) {
        console.error(" DGFT Filing Error:", error);

        if (error.response) {
            console.error("Status:", error.response.status);
            console.error("Response Data:", JSON.stringify(error.response.data, null, 2));

            if (error.response.status === 403) {
                console.error(" IP Whitelisting Required!");
                console.error(`Add ${currentIP} to DGFT sandbox portal`);
                throw new Error(`IP Whitelisting Required: Add ${currentIP} to DGFT sandbox portal`);
            }

            const errorMessage = error.response.data?.message || error.response.data?.error || 'Unknown API error';
            throw new Error(`DGFT API Error (${error.response.status}): ${errorMessage}`);
        }

        if (error.message.includes('USER_PRIVATE_KEY') || error.message.includes('DGFT_PUBLIC_KEY')) {
            throw new Error(`Configuration Error: ${error.message}. Please check your .env file.`);
        }

        console.error(error.message);
        throw new Error(`Filing failed: ${error.message}`);
    }
};