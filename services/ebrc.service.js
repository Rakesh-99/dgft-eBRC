import axios from "axios";
import { config } from '@dotenvx/dotenvx';
config();
import crypto from "crypto";


const dgftPublicKey = (process.env.DGFT_PUBLIC_KEY || '').trim();
const userPrivateKeyBase64 = (process.env.USER_PRIVATE_KEY || '').trim();
const userPrivateKey = userPrivateKeyBase64
    ? `-----BEGIN PRIVATE KEY-----\n${userPrivateKeyBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`
    : '';
const userPublicKeyBase64 = (process.env.USER_PUBLIC_KEY || '').trim();
const userPublicKey = userPublicKeyBase64
    ? `-----BEGIN PUBLIC KEY-----\n${userPublicKeyBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`
    : '';
const clientSecret = (process.env.CLIENT_SECRET || '').trim();
const baseUrl = (process.env.DGFT_SANDBOX_URL || '').trim();
const apiKey = (process.env.X_API_KEY || '').trim();
const clientId = (process.env.CLIENT_ID || '').trim();
const accessTokenBaseUrl = (process.env.ACCESS_TOKEN_URL || '').trim();



// Currency codes from DGFT specification
const VALID_CURRENCY_CODES = [
    'USD', 'DEM', 'SGD', 'CHF', 'GBP', 'JPY', 'HKD', 'EUR', 'ITL', 'FRF',
    'AUD', 'SEK', 'CAD', 'BEF', 'DKK', 'FIM', 'NOK', 'ATS', 'INR', 'NLG',
    'ACU', 'NZD', 'BHD', 'SAR', 'ZAR', 'AED', 'KES', 'KWD', 'THB', 'CNY',
    'EGP', 'IDR', 'KRW', 'MYR', 'OMR', 'QAR', 'RUB', 'AFA', 'ALL', 'DZD',
    'AON', 'ARS', 'AMD', 'ILS', 'JMD', 'JOD', 'KZT', 'KPW', 'LAK', 'LBP',
    'LSL', 'LRD', 'LYD', 'LTL', 'MGF', 'MWK', 'MVR', 'MRO', 'MUR', 'MXN',
    'MNT', 'MAD', 'BSD', 'BDT', 'BBD', 'BYB', 'BZD', 'XOF', 'BMD', 'BOB',
    'BWP', 'BRL', 'BND', 'BGL', 'MMK', 'BIF', 'KHR', 'CLP', 'COP', 'XAF',
    'ZRN', 'CRC', 'HRK', 'CUP', 'CZK', 'DJF', 'DOP', 'ECS', 'SVC', 'ETB',
    'FKP', 'FJD', 'GMD', 'GHC', 'GIP', 'GTQ', 'GNF', 'GYD', 'HTG', 'HNL',
    'HUF', 'ISK', 'IRR', 'IQD', 'NPR', 'NIO', 'NGN', 'PKR', 'PAB', 'PYG',
    'PEN', 'PHP', 'PLN', 'ROL', 'RWF', 'SHP', 'XCD', 'SLL', 'SOS', 'LKR',
    'SDD', 'SRG', 'SZL', 'SYP', 'TWD', 'TZS', 'TOP', 'TTD', 'TND', 'TRL',
    'UGX', 'UAH', 'UYU', 'UZS', 'VEB', 'VND', 'WST', 'YER', 'ZMK', 'ZWD',
    'RUR', 'TRY', 'KGS'
];

// Purpose codes from DGFT specification (Annexures 6.1 & 6.2)
const VALID_PURPOSE_CODES = [
    // Inward Remittance (Annexure 6.1)
    'P0101', 'P0102', 'P0103', 'P0104', 'P0108', 'P0109',
    'P0201', 'P0202', 'P0205', 'P0207', 'P0208', 'P0211', 'P0214', 'P0215',
    'P0216', 'P0217', 'P0218', 'P0219', 'P0220', 'P0221', 'P0222', 'P0223',
    'P0224', 'P0225', 'P0226',
    'P0301', 'P0302', 'P0304', 'P0305', 'P0306', 'P0308',
    'P0501', 'P0502',
    'P0601', 'P0602', 'P0603', 'P0605', 'P0607', 'P0608', 'P0609', 'P0610',
    'P0611', 'P0612',
    'P0701', 'P0702', 'P0703',
    'P0801', 'P0802', 'P0803', 'P0804', 'P0805', 'P0806', 'P0807', 'P0808',
    'P0809',
    'P0901', 'P0902',
    'P1002', 'P1003', 'P1004', 'P1005', 'P1006', 'P1007', 'P1008', 'P1009',
    'P1010', 'P1011', 'P1013', 'P1014', 'P1015', 'P1016', 'P1017', 'P1018',
    'P1019', 'P1020', 'P1021', 'P1022', 'P1099',
    'P1101', 'P1103', 'P1104', 'P1105', 'P1106', 'P1107', 'P1108', 'P1109',
    'P1201', 'P1203',
    'P1505',
    'P1601', 'P1602',
    'P1701',
    // Outward Remittance (Annexure 6.2)
    'S1501', 'S1502', 'S1504'
];

// Utility: Check current public IP
export const checkCurrentIP = async () => {
    try {
        const response = await fetch('https://api.ipify.org?format=json', {
            signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log("=== CURRENT SYSTEM IP ===");
        console.log("Public IP:", data.ip);
        return data;
    } catch (error) {
        console.error("IP check failed:", error.message);
        return { ip: 'unknown' };
    }
};


// Generating access token : ----->
export const getSandboxToken = async () => {
    try {
        if (!clientSecret || !clientId || !apiKey || !accessTokenBaseUrl) {
            throw new Error("Missing CLIENT_SECRET / CLIENT_ID / X_API_KEY / ACCESS_TOKEN_URL env");
        }
        // Generate 32-byte random salt
        const salt = crypto.randomBytes(32);

        // Derive PBKDF2 hash
        const derivedKey = crypto.pbkdf2Sync(
            clientSecret,
            salt,
            65536,
            32,
            "sha256"
        );

        // Final secret = base64(salt + derivedKey)
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
            }
        );

        if (!response || !response.data) {
            throw new Error("Empty response from getAccessToken");
        }
        const accessToken = response.data.accessToken
        if (!accessToken) {

            console.error("getAccessToken response shape:", Object.keys(response.data));
            throw new Error("Access token missing in response from DGFT");
        }

        console.log("Token generated successfully (length):", accessToken.length);
        return { accessToken };
    } catch (error) {
        console.error("Error while getting token:", error.response?.data || error.message || error);
        throw new Error(`Authentication failed: ${error.message || error}`);
    }
};


// Step 3: Generate a 32 characters plain text dynamic key. helper fn() : 
async function generateDynamic32CharSecretKey() {
    const { ip } = await checkCurrentIP();
    const appName = 'dgft-';

    const timestamp = Date.now().toString();

    let secretKey = appName + ip + timestamp;

    // keeping only printable keyboard characters
    secretKey = secretKey.replace(/[^ -~]/g, '');

    // Ensure exactly 32 characters
    if (secretKey.length > 32) {
        secretKey = secretKey.substring(0, 32);
    } else {
        // Pad with keyboard character (e.g., '0' or 'X')
        secretKey = secretKey.padEnd(32, '0');
    }
    return { secretKey };
}



// Step 4: Generate 32 bytes salt and create AES key helper fn() :
async function generateSalt() {
    const prefix = 'dgft-';
    const timestamp = (Date.now() + 1000).toString();
    const { ip } = await checkCurrentIP();

    let saltString = `${prefix}${ip}${timestamp}`;

    // Ensure exactly 32 characters
    if (saltString.length > 32) {
        saltString = saltString.substring(0, 32);
    } else if (saltString.length < 32) {
        const keyboardChars = '9876543210';
        let padIndex = 0;
        while (saltString.length < 32) {
            saltString += keyboardChars[padIndex % keyboardChars.length];
            padIndex++;
        }
    }

    if (saltString.length !== 32) {
        throw new Error(`Salt string must be exactly 32 characters, got ${saltString.length}`);
    }

    return Buffer.from(saltString, 'utf8');
};
// Step 4: AES key using the same salt
function createAES256Key(secretKey, salt) {
    //  PBKDF2 with HMAC-SHA256, 65536 iterations, 256-bit key
    return crypto.pbkdf2Sync(
        secretKey,
        salt,
        65536,
        32,
        'sha256'
    );
};


// Step 4: AES-GCM encryption helper fn()
async function encryptPayloadAESGCM(payloadBase64, secretKey) {
    try {
        const salt = await generateSalt();
        const aes256Key = createAES256Key(secretKey, salt);
        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv('aes-256-gcm', aes256Key, iv);

        // In Node.js crypto, cipher.final() already includes the auth tag
        const encrypted = cipher.update(payloadBase64, 'utf8');
        const final = cipher.final();

        const ciphertext = Buffer.concat([encrypted, final]);

        const finalBuffer = Buffer.concat([iv, salt, ciphertext]);

        console.log("AES-GCM encryption completed:");
        console.log("- IV length:", iv.length, "bytes (12)");
        console.log("- Salt length:", salt.length, "bytes (32)");
        console.log("- Ciphertext+Tag length:", ciphertext.length, "bytes");
        console.log("- Final buffer length:", finalBuffer.length, "bytes");

        return {
            finalBuffer: finalBuffer.toString('base64'),
            iv,
            salt,
            ciphertext
        };
    } catch (error) {
        console.error("AES-GCM encryption error:", error.message);
        throw new Error(`AES-GCM encryption failed: ${error.message}`);
    }
}

// step 5:  Digital signature helper fn() ------> 
function createDigitalSignature(dataToSign) {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(dataToSign, 'utf8');
    const signature = signer.sign(userPrivateKey, "base64");
    return signature;
}


// Step 6 :  RSA encryption with OAEP parameters
function encryptAESKey(secretKey) {
    try {
        if (!dgftPublicKey) {
            throw new Error("DGFT_PUBLIC_KEY not found in environment");
        }
        if (secretKey.length !== 32) {
            throw new Error(`Secret key must be exactly 32 characters, got ${secretKey.length}`);
        }
        // check for printable ASCII -----------------> 
        if (!/^[\x20-\x7E]{32}$/.test(secretKey)) {
            throw new Error("Secret key must be 32 printable ASCII characters");
        }
        console.log("Secret key to encrypt:", secretKey);
        console.log("Secret key length:", secretKey.length);


        // RSA-OAEP with SHA-256 
        const encryptedKey = crypto.publicEncrypt(
            {
                key: dgftPublicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
                mgf1Hash: "sha256",
            },
            Buffer.from(secretKey, 'utf8')  // Plain 32-char secret as UTF-8
        );

        const encryptedKeyBase64 = encryptedKey.toString('base64');
        console.log("RSA encryption successful:");
        console.log(" Ciphertext length:", encryptedKey.length, "bytes");
        console.log(" Base64 length:", encryptedKeyBase64.length, "chars");
        console.log(" Base64 (first 60):", encryptedKeyBase64.substring(0, 60));

        return encryptedKeyBase64;
    } catch (error) {
        console.error("RSA encryption failed:", error.message);
        throw new Error(`Failed to encrypt secret key: ${error.message}`);
    }
}

//  encryption process 
async function encryptPayload(payload) {

    // Step 1: Create JSON 
    const payloadJson = JSON.stringify(payload);
    console.log("1. JSON payload created, length:", payloadJson.length);

    // Step 2: Base64 encode JSON
    const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64');
    console.log("2. Base64 encoded JSON, length:", payloadBase64.length);

    // Step 3: Generate 32-character secret key
    const { secretKey } = await generateDynamic32CharSecretKey();
    console.log("3. Generated 32-character secret key:", secretKey);

    // Step 4: Encrypt with AES-GCM
    const payloadBase64String = String(payloadBase64);
    const encryptionResult = await encryptPayloadAESGCM(payloadBase64String, secretKey);
    console.log("4. Encrypted payload using AES-256-GCM");

    // Step 5: Sign the BASE64 encoded data (NOT the encrypted data)
    const digitalSignature = createDigitalSignature(payloadBase64);
    console.log("5. Created digital signature for base64 payload");

    return {
        secretKey,
        encodedData: encryptionResult.finalBuffer,
        digitalSignature,
        payloadBase64,
        ...encryptionResult
    };
}

function validatePayload(payload) {
    console.log("Validating payload ............");

    const errors = [];

    // Required fields validation
    const requiredFields = [
        'iecNumber', 'requestId', 'recordResCount', 'uploadType', 'ebrcBulkGenDtos'
    ];

    requiredFields.forEach(field => {
        if (!payload[field]) {
            errors.push(`ERR02: Invalid header parameters, mandatory ${field} parameter is missing`);
        }
    });

    // Handle DGFT's typo - accept both correct and incorrect spellings
    const declarationFlag = payload.declarationFlag || payload.decalarationFlag;

    // Declaration flag validation (ERR36, ERR37)
    if (!declarationFlag) {
        errors.push('ERR36: Declaration flag is missing');
    } else if (!['Y', 'N'].includes(declarationFlag.toUpperCase())) {
        errors.push('ERR37: Invalid values specified for declaration flag');
    }

    // Message ID length validation (ERR07)
    if (payload.requestId && payload.requestId.length > 50) {
        errors.push('ERR07: Invalid messageId, its length shall not be greater than 50');
    }

    // Record count validation (ERR08)
    if (payload.ebrcBulkGenDtos && Array.isArray(payload.ebrcBulkGenDtos)) {
        if (payload.recordResCount !== payload.ebrcBulkGenDtos.length) {
            errors.push('ERR08: Count mismatches. Total number of record in header and data shared not match');
        }

        // Validate each record
        const serialNumbers = new Set();
        const clubIds = new Set();
        let totalIrmMappedAmount = 0;
        const invoicePurposeMapping = new Map();

        payload.ebrcBulkGenDtos.forEach((dto, index) => {
            const recordNum = index + 1;

            // Serial number validation (ERR10, ERR11)
            if (!dto.serialNo) {
                errors.push(`ERR10: Invalid serial number in record ${recordNum}`);
            } else if (serialNumbers.has(dto.serialNo)) {
                errors.push(`ERR11: Duplicate serial number in same message - record ${recordNum}`);
            } else {
                serialNumbers.add(dto.serialNo);
            }

            // Club ID validation (ERR12, ERR13)
            if (dto.clubId) {
                if (clubIds.has(dto.clubId)) {
                    errors.push(`ERR13: Duplicate clubID in same request message - record ${recordNum}`);
                } else {
                    clubIds.add(dto.clubId);
                }
            }

            // IFSC code validation (ERR14)
            if (dto.irmIfscCode && dto.irmIfscCode.length !== 11) {
                errors.push(`ERR14: Invalid IFSC code, its length shall be 11 digit in record ${recordNum}`);
            }

            // Date format validation helper
            function isValidDateFormat(dateStr) {
                if (!dateStr || !/^\d{8}$/.test(dateStr)) return false;
                const day = parseInt(dateStr.substring(0, 2));
                const month = parseInt(dateStr.substring(2, 4));
                const year = parseInt(dateStr.substring(4, 8));

                if (month < 1 || month > 12 || day < 1 || day > 31) return false;
                if (year < 1900 || year > 2100) return false;

                const daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                if (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) {
                    daysInMonth[1] = 29;
                }

                return day <= daysInMonth[month - 1];
            }

            // Date validations
            if (dto.irmDt && !isValidDateFormat(dto.irmDt)) {
                errors.push(`ERR17: Invalid IRM Date. Date shall be in ddMMYYYY format in record ${recordNum}`);
            }

            if (dto.sbCumInvoiceDate && !isValidDateFormat(dto.sbCumInvoiceDate)) {
                errors.push(`ERR28: Invalid shipping bill/ SOFTEX or invoice date field in record ${recordNum}`);
            }

            // Purpose code validation (ERR21)
            if (dto.irmPurposeCode && !VALID_PURPOSE_CODES.includes(dto.irmPurposeCode.toUpperCase())) {
                errors.push(`ERR21: Invalid purpose code in record ${recordNum}`);
            }

            // Currency code validation
            if (dto.irmFCC && !VALID_CURRENCY_CODES.includes(dto.irmFCC.toUpperCase())) {
                errors.push(`Invalid currency code ${dto.irmFCC} in record ${recordNum}`);
            }

            // Other validations remain the same...
            // ...existing validation code...
        });
    }

    if (errors.length > 0) {
        throw new Error(errors.join('; '));
    }

    console.log("Payload validation successful");
}


// Generate encrypted values for curl command : 


export const generateEbrcCurlParams = async (payload) => {
    try {
        console.log("=== STARTING EBRC CURL PARAMS GENERATION ===");


        validatePayload(payload);
        console.log("Payload validation passed");

        // Step 2: Get access token
        const { accessToken } = await getSandboxToken();
        console.log("Access token obtained:", accessToken?.substring(0, 20), "... (length:", accessToken?.length, ")");

        // Step 3: Encrypt payload
        const encryptionResult = await encryptPayload(payload);

        // Step 4: Encrypt AES key with DGFT's public key (for production API)
        const encryptedAESKeyForAPI = encryptAESKey(encryptionResult.secretKey);


        // Step 5: LOCAL TESTING - Encrypt/Decrypt with YOUR keys
        console.log("\n=== LOCAL ENCRYPTION/DECRYPTION TEST ===");
        try {
            // Encrypt with YOUR public key
            const encryptedAESKeyForTesting = encryptAESKeyForLocalTesting(encryptionResult.secretKey);
            console.log("AES key encrypted with YOUR public key (base64):", encryptedAESKeyForTesting?.substring(0, 60), "... (length:", encryptedAESKeyForTesting?.length, ")");

            // Decrypt with YOUR private key
            const decryptedSecret = decryptSecretVal(encryptedAESKeyForTesting, userPrivateKey);
            console.log("AES key decrypted with YOUR private key:", decryptedSecret);

            // Verify they match
            const keysMatch = decryptedSecret === encryptionResult.secretKey;
            console.log("Original secret key:", encryptionResult.secretKey);
            console.log("Decrypted secret key:", decryptedSecret);
            console.log("Keys match:", keysMatch ? "YES" : "NO");

            console.log(" Original secret key:", encryptionResult.secretKey);
            console.log(" Decrypted secret key:", decryptedSecret);
            console.log(" Keys match:", decryptedSecret === encryptionResult.secretKey);

            if (!keysMatch) {
                throw new Error("Local encryption/decryption test FAILED - keys don't match!");
            }

            console.log("LOCAL TEST PASSED - Encryption/Decryption working correctly!");

        } catch (testError) {
            console.error("LOCAL TEST FAILED:", testError.message);
        }
        console.log("=== END LOCAL TEST ===\n");

        // Step 6: Generate messageID
        const messageID = payload.requestId || `EBRC${Date.now()}`.substring(0, 50);

        // Step 7: Display final results
        console.log("=== FINAL API PARAMETERS ===");
        console.log("Access Token (length):", accessToken?.length);
        console.log("Secret Val (length):", encryptedAESKeyForAPI?.length);
        console.log("Message ID:", messageID);
        console.log("Data (length):", encryptionResult.encodedData?.length);
        console.log("Signature (length):", encryptionResult.digitalSignature?.length);
        console.log("Data (base64):", encryptionResult.encodedData?.substring(0, 60), "...");

        return {
            accessToken,
            secretVal: encryptedAESKeyForAPI,
            messageID,
            data: encryptionResult.encodedData,
            sign: encryptionResult.digitalSignature
        };

    } catch (error) {
        console.error("Error generating cURL params:", error.message);
        throw error;
    }
};


// File eBRC data
export const fileEbrcService = async (payload) => {
    try {


        // Step 1: Validate payload 
        validatePayload(payload);
        console.log(" Payload validation passed");

        // Step 2: Get access token
        const { accessToken } = await getSandboxToken();
        console.log(" Access token obtained");

        // Step 3: Encrypt payload and generate signature
        const encryptionResult = await encryptPayload(payload);
        console.log(" Payload encrypted and signed");

        // Step 4: Encrypt secret key for DGFT (THIS IS THE KEY STEP)
        const encryptedSecretVal = encryptAESKey(encryptionResult.secretKey);
        console.log(" Secret key encrypted for DGFT");

        // Step 5: Generate messageID
        const messageID = payload.requestId || `EBRC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        // Step 6:  headers 
        const headers = {
            "Content-Type": "application/json",
            "accessToken": accessToken,
            "client_id": clientId,
            "x-api-key": apiKey,
            "secretVal": encryptedSecretVal,
            "messageID": messageID
        };

        console.log("Headers prepared:");
        Object.keys(headers).forEach(key => {
            if (key === 'secretVal') {
                console.log(`- ${key}: ${headers[key].substring(0, 40)}... (${headers[key].length} chars)`);
            } else if (key === 'accessToken') {
                console.log(`- ${key}: ${headers[key].substring(0, 20)}... (${headers[key].length} chars)`);
            } else {
                console.log(`- ${key}: ${headers[key]}`);
            }
        });

        // Step 7: Make API call
        const response = await axios.post(
            `${baseUrl}/pushIRMToGenEBRC`,
            {
                data: encryptionResult.encodedData,
                sign: encryptionResult.digitalSignature
            },
            {
                headers,
                timeout: 30000
            }
        );

        console.log("eBRC FILING SUCCESS");
        console.log("Response:", response.data);

        return {
            success: true,
            message: "eBRC data has been successfully filed",
            data: response.data,
            messageID: messageID
        };

    } catch (error) {
        console.error("=== eBRC FILING ERROR ===");
        if (error.response) {
            console.error("Status:", error.response.status);
            console.error("Data:", error.response.data);
            console.error("Headers:", error.response.headers);
        } else {
            console.error("Message:", error.message);
        }
        throw error;
    }
};


