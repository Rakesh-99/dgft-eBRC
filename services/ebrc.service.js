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

// Valid purpose codes from PDF (Annexure 6.1 and 6.2)
const VALID_PURPOSE_CODES = [
    // Inward Remittance
    'P0101', 'P0102', 'P0103', 'P0104', 'P0108', 'P0109',
    'P0201', 'P0202', 'P0205', 'P0207', 'P0208', 'P0211', 'P0214', 'P0215', 'P0216', 'P0217', 'P0218', 'P0219', 'P0220', 'P0221', 'P0222', 'P0223', 'P0224', 'P0225', 'P0226',
    'P0301', 'P0302', 'P0304', 'P0305', 'P0306', 'P0308',
    'P0501', 'P0502',
    'P0601', 'P0602', 'P0603', 'P0605', 'P0607', 'P0608', 'P0609', 'P0610', 'P0611', 'P0612',
    'P0701', 'P0702', 'P0703',
    'P0801', 'P0802', 'P0803', 'P0804', 'P0805', 'P0806', 'P0807', 'P0808', 'P0809',
    'P0901',
    'P1001', 'P1002', 'P1003', 'P1004', 'P1005', 'P1006', 'P1007', 'P1008', 'P1009', 'P1010', 'P1011', 'P1013', 'P1014', 'P1015', 'P1016', 'P1017', 'P1018', 'P1019', 'P1020', 'P1021', 'P1022', 'P1099',
    'P1101', 'P1103', 'P1104', 'P1105', 'P1106', 'P1107', 'P1108', 'P1109',
    'P1201', 'P1203',
    'P1505',
    'P1601', 'P1602',
    'P1701',
    // Outward Remittance
    'S1501', 'S1502', 'S1504'
];

// Valid currency codes from PDF (Annexure 6.4)
const VALID_CURRENCY_CODES = [
    'USD', 'DEM', 'SGD', 'CHF', 'GBP', 'JPY', 'HKD', 'EUR', 'ITL', 'FRF', 'AUD', 'SEK', 'CAD', 'BEF', 'DKK', 'FIM', 'NOK', 'ATS', 'INR', 'NLG', 'ACU', 'NZD', 'BHD', 'SAR', 'ZAR', 'AED', 'KES', 'KWD', 'THB', 'CNY', 'EGP', 'IDR', 'KRW', 'MYR', 'OMR', 'QAR', 'RUB', 'AFA', 'ALL', 'DZD', 'AON', 'ARS', 'AMD', 'ILS', 'JMD', 'JOD', 'KZT', 'KPW', 'LAK', 'LBP', 'LSL', 'LRD', 'LYD', 'LTL', 'MGF', 'MWK', 'MVR', 'MRO', 'MUR', 'MXN', 'MNT', 'MAD', 'BSD', 'BDT', 'BBD', 'BYB', 'BZD', 'XOF', 'BMD', 'BOB', 'BWP', 'BRL', 'BND', 'BGL', 'MMK', 'BIF', 'KHR', 'CLP', 'COP', 'XAF', 'ZRN', 'CRC', 'SVC', 'ETB', 'FKP', 'FJD', 'GMD', 'GHC', 'GIP', 'GTQ', 'GNF', 'GYD', 'HTG', 'HNL', 'HUF', 'ISK', 'IRR', 'IQD', 'NPR', 'NIO', 'NGN', 'PKR', 'PAB', 'PYG', 'PEN', 'PHP', 'PLN', 'ROL', 'RWF', 'SHP', 'XCD', 'SLL', 'SOS', 'LKR', 'SDD', 'SRG', 'SZL', 'SYP', 'TWD', 'TZS', 'TOP', 'TTD', 'TND', 'TRL', 'UGX', 'UAH', 'UYU', 'UZS', 'VEB', 'VND', 'WST', 'YER', 'ZMK', 'ZWD', 'RUR', 'TRY', 'KGS'
];

// Error codes from PDF (Annexure 6.3)
const ERROR_CODES = {
    '401': 'Unauthorized. Client Id and client secret not matched.',
    '403': 'Access forbidden, please verify the IP, client Id and client secret',
    'ERR01': 'Invalid client_Id and client_secret.',
    'ERR02': 'Invalid header parameters, mandatory {param name} parameter is missing',
    'ERR03': 'Invalid JSON.',
    'ERR04': 'Invalid secret val.',
    'ERR05': 'Invalid encryption key, not able to decrypt using the encryption key shared.',
    'ERR06': 'Digital signature mismatch in record verification.',
    'ERR07': 'Invalid messageId, its length shall not be greater than 50.',
    'ERR08': 'Count mismatches. Total number of record in header and data shared not match.',
    'ERR09': 'Duplicate message ID, messageID already shared earlier.',
    'ERR10': 'Invalid serial number.',
    'ERR11': 'Duplicate serial number in same message.',
    'ERR12': 'Invalid clubID',
    'ERR13': 'Duplicate clubID in same request message.',
    'ERR14': 'Invalid IFSC code, its length shall be 11 digit.',
    'ERR15': 'IFSC code doesn\'t match with the IFSC in IRM',
    'ERR16': 'Invalid AD Code.',
    'ERR17': 'Invalid IRM Date. Date shall be in ddMMYYYY format',
    'ERR18': 'Invalid IRM Number.',
    'ERR19': 'Invalid IRM number and date combination.',
    'ERR20': 'Invalid IRM FCC, it shall match the FCC value in IRM shared by bank.',
    'ERR21': 'Invalid purpose code',
    'ERR22': 'Purpose code doesn\'t match with detail as per Bank data.',
    'ERR23': 'IRM Available amount doesn\'t match with IRM available amount in DGFT system.',
    'ERR24': 'Invalid paymentDate field in request JSON. Field is null or not in format ddMMyyyy.',
    'ERR25': 'Invalid shipping bill number. It cannot be greater than 7 digit',
    'ERR26': 'Invalid Softex number in the application.',
    'ERR27': 'Invalid invoice number mentioned.',
    'ERR28': 'Invalid shipping bill/ SOFTEX or invoice date field',
    'ERR29': 'Invalid port code mentioned. Port code cannot be greater than 6 digit in length',
    'ERR30': 'Port code doesn\'t exists in DGFT system.',
    'ERR31': 'Invalid billNo its values cannot be greater than 20 digit length.',
    'ERR32': 'Invalid values for isVostro flag. Allowed values are Y/N.',
    'ERR33': 'Invalid vostro type specified. Allowed values are SVRA/NVRA.',
    'ERR34': 'Invalid 3rd party export flag. Allowed values are Y/N.',
    'ERR35': 'Invalid ORM amount specified.',
    'ERR36': 'Declaration flag is missing.',
    'ERR37': 'Invalid values specified for declaration flag.',
    'ERR38': 'Total IRM mapped is more than available amount. Please check the calculation.',
    'ERR39': 'Invoice and purpose code mapping is not correct.'
};

// Generating Sandbox Token: --->
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

// Helper fn() to generate dynamic AES key and encrypt payload: -->
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
            secretPlain,        // encrypt this with DGFT public key (secretVal)
            encodedData,        // to go into request.data
            payloadBase64       // for signing
        };
    } catch (encryptError) {
        console.error("Encryption error:", encryptError);
        throw new Error(`Payload encryption failed: ${encryptError.message}`);
    }
}

// Helper fn() to create digital signature: -->
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

// Helper to validate payload against PDF specs
function validatePayload(payload) {
    if (!payload.purposeCode || !VALID_PURPOSE_CODES.includes(payload.purposeCode)) {
        throw new Error('ERR21: Invalid purpose code');
    }
    if (payload.currencyCode && !VALID_CURRENCY_CODES.includes(payload.currencyCode)) {
        throw new Error('Invalid currency code');
    }
    // Add more validations as per PDF (e.g., date formats, lengths)
}

// Step 2. fn() to fill/submit data on eBRC dgft in sandbox environment with IP detection: -->
export const fileEbrcService = async (payload) => {
    try {
        console.log("=== REQUEST DEBUG ===");
        console.log("Current public IP:", currentIP);
        console.log("Client ID:", clientId);
        console.log("Base URL:", baseUrl);

        // Validate payload against PDF specs
        validatePayload(payload);

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
            "x-api-key": apiKey,  // Added as per spec for API authentication
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

            // Map to PDF error codes
            const status = error.response.status;
            const errorMsg = ERROR_CODES[status] || ERROR_CODES[error.response.data?.errorCode] || error.message;
            throw new Error(errorMsg);
        } else if (error.request) {
            console.error("No response received:", error.request);
        } else {
            console.error("Request setup error:", error.message);
        }

        throw new Error(`Request failed: ${error.message}`);
    }
};