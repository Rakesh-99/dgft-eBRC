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

// KEEP YOUR WORKING TOKEN GENERATION (encrypted client_secret)
export const getSandboxToken = async () => {
    try {
        // Your working method - keep this!
        const salt = crypto.randomBytes(32);
        const derivedKey = crypto.pbkdf2Sync(clientSecret, salt, 65536, 32, "sha256");
        const finalSecret = Buffer.concat([salt, derivedKey]).toString("base64");

        const response = await axios.post(
            `${accessTokenBaseUrl}/getAccessToken`,
            {
                client_id: clientId,
                client_secret: finalSecret,  // Use encrypted secret - this works!
            },
            {
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": apiKey,
                },
            }
        );
        console.log("Token generated successfully");
        return response;
    } catch (error) {
        console.error("Token generation failed:", error.response?.data || error.message);
        throw error;
    }
};

// FIXED: Correct 32-character key generation matching Java example
function generateDynamic32CharSecretKey() {
    const appName = "dgft";
    const ip = "54.206.54.110";  
    const timestamp = Date.now().toString();

    // Match Java example pattern exactly
    const secretKey = `${appName}-${ip}${timestamp}`.substring(0, 32);
    const salt = `${appName}-${ip}${timestamp}5`.substring(0, 32);  // Append '5' like Java example

    // Ensure exactly 32 characters
    const paddedSecret = secretKey.padEnd(32, '0');
    const paddedSalt = salt.padEnd(32, '5');

    console.log("Generated secret key:", paddedSecret);
    console.log("Generated salt:", paddedSalt);

    return { secretKey: paddedSecret, salt: paddedSalt };
}

//  Encryption process 
async function encryptPayload(payload) {
    try {
        console.log("=== ENCRYPTION PROCESS (Following Java Implementation) ===");

        // Step 1: Create JSON message
        const jsonData = JSON.stringify(payload, Object.keys(payload).sort(), 0).replace(/\s+/g, '');
        console.log("Step 1: JSON message created");

        // Step 2: Base64 encode the JSON
        const encodedVal = Buffer.from(jsonData, 'utf8').toString('base64');
        console.log("Step 2: JSON Base64 encoded");

        // Step 3: Generate dynamic 32-character secret key 
        const { secretKey, salt } = generateDynamic32CharSecretKey();

        // Step 4: Generate AES key using PBKDF2 
        const saltBytes = Buffer.from(salt, 'utf8');
        const aesKey = crypto.pbkdf2Sync(secretKey, saltBytes, 65536, 32, 'sha256');
        console.log("Step 4: AES key generated using PBKDF2WithHmacSHA256");

        // Generate random 12-byte IV (as in Java)
        const iv = crypto.randomBytes(12);

        // AES-GCM encryption
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        let encrypted = cipher.update(encodedVal, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const authTag = cipher.getAuthTag();

        // Combine encrypted data + authTag
        const cipherText = Buffer.concat([encrypted, authTag]);

        // Step 4 continuation: Append IV + Salt + EncryptedText (as per Java ByteBuffer)
        const combinedData = Buffer.concat([
            iv,          // 12 bytes
            saltBytes,   // 32 bytes  
            cipherText   // encrypted + authTag
        ]);

        const encryptedData = combinedData.toString('base64');
        console.log("Step 4: Combined data (IV + Salt + Encrypted) encoded");

        return {
            secretKey,
            salt,
            encryptedData,
            encodedVal,  // This is what we sign in Step 5
            iv,
            aesKey
        };
    } catch (error) {
        console.error("Encryption failed:", error);
        throw error;
    }
}

//  Sign the Base64 encoded JSON (Step 2)
function createDigitalSignature(dataToSign) {
    try {
        console.log("=== DIGITAL SIGNATURE (Step 5) ===");
        console.log("Signing data (should be Step 4's Base64 output)");

        if (!userPrivateKey) {
            throw new Error("USER_PRIVATE_KEY not found");
        }

        const signer = crypto.createSign("RSA-SHA256");
        signer.update(Buffer.from(dataToSign, 'utf8'));
        const signature = signer.sign(userPrivateKey, "base64");

        console.log("Digital signature created successfully");
        return signature;
    } catch (error) {
        console.error("Digital signature failed:", error);
        throw error;
    }
}

//  RSA encryption with proper padding 
function encryptSecretKey(secretKey) {
    try {
        console.log("=== SECRET KEY ENCRYPTION (Step 6) ===");

        if (!dgftPublicKey) {
            throw new Error("DGFT_PUBLIC_KEY not found");
        }

        // Use RSA-OAEP with SHA-256 as per Java specification
        const encryptedKey = crypto.publicEncrypt(
            {
                key: dgftPublicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(secretKey, 'utf8')
        ).toString('base64');

        console.log("Secret key encrypted using RSA-OAEP-SHA256");
        return encryptedKey;
    } catch (error) {
        console.error("Secret key encryption failed:", error);
        throw error;
    }
}

//  Complete eBRC filing process
export const fileEbrcService = async (payload) => {
    try {
        console.log("=== STARTING eBRC FILING PROCESS ===");

        // Get access token
        const tokenResponse = await getSandboxToken();
        const accessToken = tokenResponse.data.accessToken;
        console.log("Access token obtained");

        // Encryption process (Steps 1-4)
        const encryptionResult = await encryptPayload(payload);

        // Digital signature (Step 5) - Sign the Base64 encoded JSON
     const digitalSignature = createDigitalSignature(encryptionResult.encryptedData);

        // Encrypt secret key (Step 6)
        const encryptedSecretKey = encryptSecretKey(encryptionResult.secretKey);

        // Prepare request body as per DGFT format
        const requestBody = {
            data: encryptionResult.encryptedData,
            sign: digitalSignature
        };

        // Generate messageID
        const messageID = payload.requestId || crypto.randomUUID().substring(0, 50);

        // Headers as per DGFT specification
        const headers = {
            "Content-Type": "application/json",
            "accessToken": accessToken,
            "client_id": clientId,
            "secretVal": encryptedSecretKey,
            "x-api-key": apiKey,
            "messageID": messageID
        };

        console.log("=== REQUEST DETAILS ===");
        console.log("URL:", `${baseUrl}/pushIRMToGenEBRC`);
        console.log("Headers:", { ...headers, accessToken: '[HIDDEN]', secretVal: '[HIDDEN]' });
        console.log("Body structure:", { data: '[ENCRYPTED]', sign: '[SIGNATURE]' });

        // Make API call
        const response = await axios.post(`${baseUrl}/pushIRMToGenEBRC`,
            requestBody,
            { headers, timeout: 30000 }
        );

        console.log("=== eBRC FILING SUCCESSFUL ===");
        return {
            success: true,
            messageID: messageID,
            data: response.data,
            message: "eBRC data filed successfully with DGFT"
        };

    } catch (error) {
        console.error("=== eBRC FILING FAILED ===");
        console.error("Error:", error.response?.data || error.message);
        console.error("Status:", error.response?.status);

        return {
            success: false,
            error: error.response?.data || error.message,
            status: error.response?.status
        };
    }
};

