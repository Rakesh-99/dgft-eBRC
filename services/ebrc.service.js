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



// Valid currency codes from PDF (Annexure 6.4) - Complete list
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


const VALID_PURPOSE_CODES = [
    // Inward Remittance
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
    'P1001', // ADD THIS - it was missing
    'P1002', 'P1003', 'P1004', 'P1005', 'P1006', 'P1007', 'P1008', 'P1009',
    'P1010', 'P1011', 'P1013', 'P1014', 'P1015', 'P1016', 'P1017', 'P1018',
    'P1019', 'P1020', 'P1021', 'P1022', 'P1099',
    'P1101', 'P1103', 'P1104', 'P1105', 'P1106', 'P1107', 'P1108', 'P1109',
    'P1201', 'P1203',
    'P1505',
    'P1601', 'P1602',
    'P1701',
    // Outward Remittance
    'S1501', 'S1502', 'S1504'
];



export const checkCurrentIP = async () => {
    try {
        const response = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
        console.log("=== CURRENT SYSTEM IP ===");
        console.log("Public IP:", response.data.ip);
        return response.data;
    } catch (error) {
        console.error("IP check failed:", error.message);
        return { ip: 'unknown' };
    }
};



// Generating Sandbox Token: --->
export const getSandboxToken = async () => {
    try {


        const salt = crypto.randomBytes(32);
        // CORRECT: Use PBKDF2 here too as per PDF
        const derivedKey = crypto.pbkdf2Sync(clientSecret, salt, 65536, 32, "sha256");
        const finalSecret = Buffer.concat([salt, derivedKey]).toString("base64");

        console.log("=== TOKEN REQUEST DETAILS ===");
        console.log("Client ID:", clientId);
        console.log("Final Secret Length:", finalSecret.length);

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
                    "Accept": "application/json",
                    "Cache-Control": "no-cache"
                },
                timeout: 15000
            }
        );

        console.log("Token response status:", response.status);
        return response;
    } catch (error) {
        console.error("=== TOKEN GENERATION ERROR ===");
        console.error("Status:", error.response?.status);
        console.error("Response:", error.response?.data);
        throw new Error(`Authentication failed with DGFT Sandbox: ${error.message}`);
    }
};

// Helper: printable 32-char secret (keyboard characters)
function generatePrintableSecret32() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const rnd = crypto.randomBytes(32);
    let s = '';
    for (let i = 0; i < 32; i++) s += chars[rnd[i] % chars.length];
    return s;
}

// Helper function to generate dynamic AES key and encrypt payload
function encryptPayload(payload) {
    try {
        const payloadJson = JSON.stringify(payload);
        const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64');

        // Generate a 32-char printable secret
        const secretPlain = generatePrintableSecret32();

        // 32-byte random salt per spec
        const salt = crypto.randomBytes(32);

        // 12-byte IV for AES-GCM
        const iv = crypto.randomBytes(12);

        // CORRECT: Use PBKDF2 as per PDF specification
        const saltedKey = crypto.pbkdf2Sync(secretPlain, salt, 65536, 32, "sha256");

        const cipher = crypto.createCipheriv('aes-256-gcm', saltedKey, iv);
        const encrypted = Buffer.concat([
            cipher.update(payloadBase64, 'utf8'),
            cipher.final()
        ]);
        const authTag = cipher.getAuthTag();

        // Combine iv + salt + ciphertext + authTag
        const combined = Buffer.concat([iv, salt, encrypted, authTag]);
        const encodedData = combined.toString('base64');

        return {
            secretPlain,
            encodedData,
            payloadBase64
        };
    } catch (encryptError) {
        console.error("Encryption error:", encryptError);
        throw new Error(`Payload encryption failed: ${encryptError.message}`);
    }
}

// Helper function to create digital signature
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

// Encrypt AES key with DGFT public key using OAEP-SHA256
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

// Decrypt and verify DGFT response using same secret and dgftPublicKey
function decryptResponse(responseBody, secretPlain) {
    try {
        const combined = Buffer.from(responseBody.data, 'base64');
        const iv = combined.slice(0, 12);
        const salt = combined.slice(12, 44);
        const authTag = combined.slice(combined.length - 16);
        const ciphertext = combined.slice(44, combined.length - 16);

        // PBKDF2 for response decryption
        const saltedKey = crypto.pbkdf2Sync(secretPlain, salt, 65536, 32, "sha256");

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

// Validate payload : 

function validatePayload(payload) {
    const errors = [];

    // According to PDF, these are the EXACT required fields
    const requiredFields = [
        'messageId',      // String, max 50 chars
        'purposeCode',    // From valid purpose codes
        'irmNumber',      // String
        'irmDate',        // ddMMYYYY format
        'adCode',         // String
        'amount'          // Number
    ];

    requiredFields.forEach(field => {
        if (!payload[field]) {
            errors.push(`ERR02: Invalid header parameters, mandatory ${field} parameter is missing`);
        }
    });

    // Validate purpose code (ERR21)
    if (payload.purposeCode && !VALID_PURPOSE_CODES.includes(payload.purposeCode)) {
        errors.push('ERR21: Invalid purpose code');
    }

    // Validate currency code if provided
    if (payload.currencyCode && !VALID_CURRENCY_CODES.includes(payload.currencyCode)) {
        errors.push('Invalid currency code');
    }

    // Validate messageId length (ERR07)
    if (payload.messageId && payload.messageId.length > 50) {
        errors.push('ERR07: Invalid messageId, its length shall not be greater than 50');
    }

    // Validate IFSC code (ERR14) - if provided
    if (payload.ifscCode && payload.ifscCode.length !== 11) {
        errors.push('ERR14: Invalid IFSC code, its length shall be 11 digit');
    }

    // Validate date format (ERR17, ERR24, ERR28)
    const dateFields = [
        { field: 'irmDate', errorCode: 'ERR17', required: true },
        { field: 'paymentDate', errorCode: 'ERR24', required: false },
        { field: 'shippingBillDate', errorCode: 'ERR28', required: false },
        { field: 'softexDate', errorCode: 'ERR28', required: false },
        { field: 'invoiceDate', errorCode: 'ERR28', required: false }
    ];

    dateFields.forEach(({ field, errorCode, required }) => {
        if (payload[field]) {
            if (!/^\d{8}$/.test(payload[field])) {
                errors.push(`${errorCode}: Invalid ${field} field. Date shall be in ddMMYYYY format`);
            }
        } else if (required) {
            errors.push(`ERR02: Invalid header parameters, mandatory ${field} parameter is missing`);
        }
    });

    // Validate nested object dates if present
    if (payload.shipmentDetails?.invoiceDate) {
        if (!/^\d{8}$/.test(payload.shipmentDetails.invoiceDate)) {
            errors.push('ERR28: Invalid invoiceDate in shipmentDetails. Date shall be in ddMMYYYY format');
        }
    }

    // Validate shipping bill number (ERR25)
    if (payload.shippingBillNumber && payload.shippingBillNumber.toString().length > 7) {
        errors.push('ERR25: Invalid shipping bill number. It cannot be greater than 7 digit');
    }

    // Validate port code (ERR29)
    if (payload.portCode && payload.portCode.toString().length > 6) {
        errors.push('ERR29: Invalid port code mentioned. Port code cannot be greater than 6 digit in length');
    }

    // Validate billNo (ERR31)
    if (payload.billNo && payload.billNo.toString().length > 20) {
        errors.push('ERR31: Invalid billNo its values cannot be greater than 20 digit length');
    }

    // Validate Vostro flag (ERR32)
    if (payload.isVostro && !['Y', 'N'].includes(payload.isVostro)) {
        errors.push('ERR32: Invalid values for isVostro flag. Allowed values are Y/N');
    }

    // Validate Vostro type (ERR33)
    if (payload.vostroType && !['SVRA', 'NVRA'].includes(payload.vostroType)) {
        errors.push('ERR33: Invalid vostro type specified. Allowed values are SVRA/NVRA');
    }

    // Validate 3rd party export flag (ERR34)
    if (payload.thirdPartyExport && !['Y', 'N'].includes(payload.thirdPartyExport)) {
        errors.push('ERR34: Invalid 3rd party export flag. Allowed values are Y/N');
    }

    // Validate amount (ERR35)
    if (payload.amount && (isNaN(payload.amount) || payload.amount <= 0)) {
        errors.push('ERR35: Invalid amount specified');
    }

    if (errors.length > 0) {
        throw new Error(errors.join('; '));
    }
}

// Main function to file/submit data on eBRC DGFT in sandbox environment
export const fileEbrcService = async (payload) => {
    try {
        console.log("=== eBRC FILING REQUEST STARTED ===");
        console.log("Client ID:", clientId);
        console.log("Base URL:", baseUrl);

        let systemIP = await checkCurrentIP();
        console.log(" System Public IP:", systemIP.ip);


        // Comprehensive payload validation against PDF specs
        console.log("Validating payload...");
        validatePayload(payload);
        console.log("Payload validation successful");

        // Get access token
        console.log("Obtaining access token...");
        const tokenResponse = await getSandboxToken();
        const accessToken = tokenResponse.data.accessToken;

        try {
            const tokenPayload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
            console.log("=== TOKEN PAYLOAD ===");
            console.log("Token issued at:", new Date(tokenPayload.iat * 1000));
            console.log("Token expires at:", new Date(tokenPayload.exp * 1000));
        } catch (e) {
            console.error("Failed to decode access token:", e.message);
        }

        console.log("Access token obtained successfully");

        const endpoint = `${baseUrl}/pushIRMToGenEBRC`;
        console.log("Endpoint:", endpoint);

        // Encrypt payload using AES-256-GCM
        console.log("Encrypting payload...");
        const encryptionResult = encryptPayload(payload);
        console.log("Payload encrypted successfully ----> ", encryptionResult.encodedData);

        // CRITICAL FIX: Sign the base64 payload, not the encrypted data
        console.log("Creating digital signature...");
        const signature = createDigitalSignature(encryptionResult.payloadBase64);
        console.log("Signature created successfully");

        // Encrypt AES key with DGFT's public key
        console.log("Encrypting AES key...");
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
            "x-api-key": apiKey,
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": "eBRC-Integration/1.0"
        };

        console.log("=== SENDING REQUEST TO DGFT ===");
        console.log("Endpoint:", endpoint);
        console.log("Headers (sanitized):", {
            "Content-Type": headers["Content-Type"],
            "client_id": headers["client_id"],
            "x-api-key": headers["x-api-key"] ? `${headers["x-api-key"].substring(0, 8)}...` : 'MISSING',
            "accessToken": headers["accessToken"] ? `${headers["accessToken"].substring(0, 20)}...` : 'MISSING',
            "secretVal": headers["secretVal"] ? `${headers["secretVal"].substring(0, 20)}...` : 'MISSING'
        });
        console.log("Request body data length:", requestBody.data.length);
        console.log("Request body sign length:", requestBody.sign.length);
        const response = await axios.post(endpoint, requestBody, {
            headers: headers,
            timeout: 30000
        });

        console.log("Response received from DGFT");
        console.log("Response status:", response.status);

        // Decrypt and verify the response
        console.log("Decrypting response...");
        const decryptedData = decryptResponse(response.data, encryptionResult.secretPlain);

        console.log("=== eBRC FILING SUCCESSFUL ===");
        console.log("Response decrypted and verified successfully");
        return {
            success: true,
            data: decryptedData,
            message: "eBRC data filed successfully"
        };

    } catch (error) {
        console.error("=== eBRC FILING ERROR ===");
        console.error("Error type:", error.constructor.name);
        console.error("Error message:", error.message);

        if (error.response) {
            console.error("HTTP Status:", error.response.status);
            console.error("Response data:", JSON.stringify(error.response.data, null, 2));
            console.error("Response headers:", JSON.stringify(error.response.headers, null, 2));

            // Enhanced error mapping based on PDF error codes
            const status = error.response.status.toString();
            const responseData = error.response.data;
            let errorMsg = ERROR_CODES[status];

            // Check for specific error codes in response
            if (responseData?.errorCode) {
                errorMsg = ERROR_CODES[responseData.errorCode] || responseData.errorCode;
            } else if (responseData?.error) {
                errorMsg = responseData.error;
            } else if (responseData?.message) {
                errorMsg = responseData.message;
            }

            throw new Error(errorMsg || `HTTP ${status}: ${error.message}`);
        } else if (error.request) {
            console.error("No response received from server");
            console.error("Request timeout or network error");
            throw new Error("Network error: No response received from DGFT server");
        } else {
            console.error("Request setup error:", error.message);
            throw new Error(`Request configuration error: ${error.message}`);
        }
    }
};

