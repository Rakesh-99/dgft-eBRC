import axios from "axios";
import { config } from '@dotenvx/dotenvx';
config();
import crypto from "crypto";
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Dgft public key : 
const dgftPublicKey = fs.readFileSync(path.join(__dirname, '../keys/dgft_extracted_public_key.pem'), 'utf8');

console.log("DGFT public key --> ", dgftPublicKey);


// userPrivate key : 
const userPrivateKeyBase64 = (process.env.USER_PRIVATE_KEY || '').trim();
const userPrivateKey = userPrivateKeyBase64
    ? `-----BEGIN PRIVATE KEY-----\n${userPrivateKeyBase64.replace(/\s/g, '').match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`
    : '';

// user public key : 
const userPublicKeyBase64 = (process.env.USER_PUBLIC_KEY || '').trim();
const userPublicKey = userPublicKeyBase64
    ? `-----BEGIN PUBLIC KEY-----\n${userPublicKeyBase64.replace(/\s/g, '').match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`
    : '';


// Client secret : 
const clientSecret = (process.env.CLIENT_SECRET || '').trim();
const baseUrl = (process.env.DGFT_SANDBOX_URL || '').trim();

// X-API key : 
const apiKey = (process.env.X_API_KEY || '').trim();

// Client ID : 
const clientId = (process.env.CLIENT_ID || '').trim();

// URL for generating access token : 
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

// utility: Check current public IP
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

// fn() to check the system IP : 
async function getPublicIPv4() {
    try {
        // Using ipify.org API (free, reliable, no rate limiting for basic usage)
        const response = await fetch('https://api.ipify.org?format=json');

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data.ip;
    } catch (error) {
        console.error('Error fetching public IP:', error);
        return null;
    }
}

// Step 3: Generate 32-char secret key 
async function generateDynamic32CharSecretKey() {
    const appName = "shipzy";
    const ip = await getPublicIPv4();
    const timestamp = Date.now().toString().slice(-10);

    let base = `${appName}-${ip}-${timestamp}`;

    // Pad or truncate to exactly 32
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    if (base.length < 32) {
        while (base.length < 32) {
            base += chars.charAt(Math.floor(Math.random() * chars.length));
        }
    } else if (base.length > 32) {
        base = base.substring(0, 32);
    }

    // Final safety check
    if (base.length !== 32 || !/^[\x20-\x7E]{32}$/.test(base)) {
        throw new Error("Failed to generate valid 32-char key");
    }

    return base;
}
async function generateSalt32ASCII() {
    const appName = "shipzy";
    const ip = await getPublicIPv4();
    const timestamp = (Date.now() + 1000).toString().slice(-10);

    let salt = `${appName}-${ip}-${timestamp}`;
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    if (salt.length < 32) {
        while (salt.length < 32) {
            salt += chars.charAt(Math.floor(Math.random() * chars.length));
        }
    } else if (salt.length > 32) {
        salt = salt.substring(0, 32);
    }

    if (salt.length !== 32 || !/^[\x20-\x7E]{32}$/.test(salt)) {
        throw new Error(`Invalid salt generated: ${salt}`);
    }

    return salt;
}

// Step 4: AES-GCM encryption helper fn()
async function encryptPayloadAESGCM(payloadBase64, secretKey) {
    const salt = await generateSalt32ASCII();
    const saltBuffer = Buffer.from(salt, 'ascii');
    const aes256Key = createAES256Key(secretKey, salt);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', aes256Key, iv);
    const payloadBuffer = Buffer.from(payloadBase64, 'utf8');
    const encrypted = cipher.update(payloadBuffer);
    const final = cipher.final();
    const authTag = cipher.getAuthTag();

    const ciphertextWithTag = Buffer.concat([encrypted, final, authTag]);
    const finalBuffer = Buffer.concat([iv, saltBuffer, ciphertextWithTag]);

    return {
        finalBuffer: finalBuffer.toString('base64'),
        iv,
        salt,
        ciphertext: ciphertextWithTag
    };
}


// Step 4: AES 256 bits key 
function createAES256Key(secretKey, salt) {
    // salt can be string (ASCII) or Buffer
    const saltBuffer = typeof salt === 'string' ? Buffer.from(salt, 'ascii') : salt;
    return crypto.pbkdf2Sync(
        secretKey,
        saltBuffer,
        65536,
        32,
        'sha256'
    );
}


// step 5:  Digital signature helper fn() ------> 
function createDigitalSignature(payloadBase64) {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(payloadBase64, 'utf8');
    const signature = signer.sign(userPrivateKey, "base64");
    return signature;
}


// RSA encryption with OAEP parameters
function encryptAESKey(secretKey) {
    console.log("=== ENCRYPTING SECRET KEY ===");
    console.log("Secret key:", secretKey);
    console.log("Char length:", secretKey.length);
    console.log("Byte length:", Buffer.byteLength(secretKey, 'utf8'));

    if (secretKey.length !== 32) {
        throw new Error(`Secret key must be 32 characters, got ${secretKey.length}`);
    }
    if (Buffer.byteLength(secretKey, 'utf8') !== 32) {
        throw new Error(`Secret key must be 32 bytes in UTF-8`);
    }
    if (!/^[\x20-\x7E]{32}$/.test(secretKey)) {
        throw new Error("Secret key must be 32 printable ASCII characters");
    }

    const secretKeyBuffer = Buffer.from(secretKey, 'utf8');
    console.log("Secret key hex:", secretKeyBuffer.toString('hex'));

    const encryptedKey = crypto.publicEncrypt(
        {
            key: dgftPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
            oaepMgf1Hash: "sha256",
            oaepLabel: Buffer.alloc(0),
        },
        secretKeyBuffer
    );

    const encryptedKeyBase64 = encryptedKey.toString('base64');
    
    console.log("Encrypted secretVal length:", encryptedKeyBase64.length);
    console.log("Encrypted secretVal sample:", encryptedKeyBase64.substring(0, 60) + "...");
    return encryptedKeyBase64;
}

//  encryption process 
async function encryptPayload(payload) {

    // Step 1: json data -----> 
    const payloadJson = JSON.stringify(payload);
    console.log("Step 1: JSON created, length:", payloadJson.length);

    // Step 2: Base64 encode of Json ---->
    const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64');
    console.log("Step 2: Base64 encoded, length:", payloadBase64.length);

    // Step 3: Generate 32-char secret key
    const secretKey = await generateDynamic32CharSecretKey();
    console.log("Step 3: Secret key generated");

    // Step 4: AES-GCM encryption
    const encryptionResult = await encryptPayloadAESGCM(payloadBase64, secretKey);
    console.log("Step 4: AES-GCM encrypted");

    // Step 5: Sign the Base64 JSON (Step 2 output)
    const digitalSignature = createDigitalSignature(payloadBase64);
    console.log("Step 5: Digital signature created", "The signature is -------------------------------> ", digitalSignature);
    console.log("Step 5: Digital signature length is,  -------------------------------> ", digitalSignature.length);
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

        // Step 4: Encrypt secret key for DGFT 
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

        //  API call
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

// for local testing : 

// Helper: Decrypt encrypted data using secret key to validate :
function decryptForValidation(encryptedDataBase64, secretKey) {
    const buf = Buffer.from(encryptedDataBase64, 'base64');
    const iv = buf.subarray(0, 12);
    const salt = buf.subarray(12, 44); // 32 bytes salt
    const ciphertextWithTag = buf.subarray(44);

    // GCM auth tag is typically 16 bytes (128 bits)
    const tag = ciphertextWithTag.subarray(-16);
    const ciphertext = ciphertextWithTag.subarray(0, -16);

    const aesKey = createAES256Key(secretKey, salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);

    const decrypted = decipher.update(ciphertext);
    const final = decipher.final();
    return Buffer.concat([decrypted, final]).toString('utf8');
}
