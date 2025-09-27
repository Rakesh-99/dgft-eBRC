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

// Error codes from DGFT specification (Annexure 6.3)
const ERROR_CODES = {
    '401': 'Unauthorized. Client Id and client secret not matched.',
    '403': 'Access forbidden, please verify the IP, client Id and client secret',
    'ERR01': 'Invalid client_Id and client_secret.',
    'ERR02': 'Invalid header parameters, mandatory parameter is missing',
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
        const response = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
        console.log("=== CURRENT SYSTEM IP ===");
        console.log("Public IP:", response.data.ip);
        return response.data;
    } catch (error) {
        console.error("IP check failed:", error.message);
        return { ip: 'unknown' };
    }
};

export const validateEnvironmentSetup = () => {
    console.log("=== ENVIRONMENT VALIDATION ===");

    const requiredEnvVars = {
        'CLIENT_SECRET': clientSecret,
        'DGFT_SANDBOX_URL': baseUrl,
        'X_API_KEY': apiKey,
        'CLIENT_ID': clientId,
        'USER_PRIVATE_KEY': userPrivateKey,
        'DGFT_PUBLIC_KEY': dgftPublicKey,
        'ACCESS_TOKEN_URL': accessTokenBaseUrl
    };

    let hasErrors = false;

    Object.entries(requiredEnvVars).forEach(([key, value]) => {
        if (!value) {
            console.error(` ${key} is missing or empty`);
            hasErrors = true;
        } else {
            console.log(` ${key} is configured (length: ${value.length})`);
        }
    });

    // Validate key formats
    if (userPrivateKey) {
        const hasPrivateKeyHeaders = userPrivateKey.includes('-----BEGIN') && userPrivateKey.includes('-----END');
        console.log(`Private Key Format: ${hasPrivateKeyHeaders ? ' Valid' : ' Missing headers'}`);
    }

    if (dgftPublicKey) {
        const hasPublicKeyHeaders = dgftPublicKey.includes('-----BEGIN') && dgftPublicKey.includes('-----END');
        console.log(`DGFT Public Key Format: ${hasPublicKeyHeaders ? ' Valid' : ' Missing headers'}`);
    }

    return !hasErrors;
};

// Access token generation : 
export const getSandboxToken = async () => {
    try {
        // Generate salt and encrypt client_secret as per DGFT specification
        const salt = crypto.randomBytes(32);
        const derivedKey = crypto.pbkdf2Sync(clientSecret, salt, 65536, 32, "sha256");
        const finalSecret = Buffer.concat([salt, derivedKey]).toString("base64");

        const response = await axios.post(
            `${accessTokenBaseUrl}/getAccessToken`,
            {
                client_id: clientId,
                client_secret: finalSecret,  // Encrypted secret as per DGFT spec
            },
            {
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": apiKey,
                },
                timeout: 15000
            }
        );
        console.log("Token generated successfully ");

        return response;
    } catch (error) {
        const status = error.response?.status?.toString();
        const errorMsg = ERROR_CODES[status] || error.response?.data?.message || error.message;

        // Check for IP issues
        if (status === "403") {
            const systemIP = await checkCurrentIP();
            console.error("403 Error - IP may need whitelisting:", systemIP.ip);
        }
        throw new Error(`Authentication failed: ${errorMsg}`);
    }
};

function formatIPForKey(ip) {

    const ipParts = ip.split('.');
    const formattedIP = ipParts
        .map(part => part.padStart(3, '0'))
        .join('.');
    return formattedIP;
}

async function generateDynamic32CharSecretPair() {
    try {
        const appName = "dgft";
        const systemIP = await checkCurrentIP();

        if (!systemIP.ip) {
            throw new Error('Could not determine system IP');
        }

        const formattedIP = formatIPForKey(systemIP.ip);
        const timestamp = Date.now().toString().slice(-10);


        const secretPlain = `${appName}-${formattedIP}${timestamp}`;


        if (secretPlain.length !== 32) {
            throw new Error(`Invalid secret key length: ${secretPlain.length}`);
        }

        // Generate salt by changing last digit
        const saltString = secretPlain.slice(0, -1) + '5';

        console.log(`Generated secret key (32 chars): "${secretPlain}"`);
        console.log(`Generated salt (32 chars): "${saltString}"`);

        return { secretPlain, saltString };
    } catch (error) {
        throw new Error(`Secret key generation failed: ${error.message}`);
    }
}


//  AES key generation by salting secret key with 32 bytes using PBKDF2 
function generateAESKey(secretKey, saltString) {
    // Convert salt string to bytes for PBKDF2
    const saltBytes = Buffer.from(saltString, 'utf8');
    const aesKey = crypto.pbkdf2Sync(secretKey, saltBytes, 65536, 32, 'sha256');
    console.log("AES 256-bit key generated using PBKDF2WithHmacSHA256 (65536 iterations)");
    return aesKey;
}

//  encryption process 
async function encryptPayload(payload) {
    // Step 1: Create JSON
    console.log("=== ENCRYPTION PROCESS ===");
    const payloadJson = JSON.stringify(payload);
    console.log("1. JSON payload created", payloadJson);

    // Step 2: Base64 encode JSON
    const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64');
    console.log("2. Base64 encoded JSON:", payloadBase64.slice(0, 50) + "...");

    // Step 3: Generate 32-char secret key (you're doing this correctly)
    const { secretPlain, saltString } = await generateDynamic32CharSecretPair();
    console.log("3. Secret key and salt generated");


    // Step 4: AES encrypt the BASE64 JSON (not the raw JSON)
    const aesKey = crypto.pbkdf2Sync(secretPlain, Buffer.from(saltString, 'utf8'), 65536, 32, 'sha256');
    //  First 12 bytes of cryptographic key (Secret Key) 
    const iv = Buffer.from(secretPlain).slice(0, 12);
    console.log("4. IV (first 12 bytes of secret):", iv.toString('hex'));
    
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const encrypted = Buffer.concat([
        cipher.update(payloadBase64, 'utf8'),  // Encrypt the Base64 string
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    // Step 5: Sign the BASE64 JSON (before encryption)
    const digitalSignature = createDigitalSignature(payloadBase64);

    // Combine 
    const finalData = Buffer.concat([
        iv,                             // 12 bytes from secret key
        Buffer.from(saltString, 'utf8'), // 32 bytes salt
        encrypted,                      // AES encrypted data
        authTag                         // 16 bytes GCM tag
    ]).toString('base64');

    return {
        secretPlain,
        encodedData: finalData,
        digitalSignature,
        payloadBase64,
        saltString,
        aesKey,
        iv
    };
}

// Digital signature using RSA-SHA256. Sign the ENCODED ENCRYPTED MESSAGE
function createDigitalSignature(payloadBase64) {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(payloadBase64);  // Sign the Base64 encoded JSON
    const signature = signer.sign(userPrivateKey, "base64");
    return signature;
}

// Encrypt secret key using DGFT public key with RSA
function encryptAESKey(secretPlain) {
    try {
        console.log("=== AES KEY ENCRYPTION (Step 6) ===");

        if (!dgftPublicKey) {
            throw new Error("DGFT_PUBLIC_KEY not found in environment");
        }

        // RSA encryption with OAEP and SHA256 padding as per Algorithm Specification
        const encryptedKey = crypto.publicEncrypt(
            {
                key: dgftPublicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(secretPlain, 'utf8')
        ).toString('base64');

        console.log("Secret key encrypted using RSA-OAEP-SHA256");
        return encryptedKey;
    } catch (error) {
        console.error("AES key encryption failed:", error);
        throw new Error(`AES key encryption failed: ${error.message}`);
    }
}

// Response decryption
function decryptResponse(responseBody, secretPlain, requestSaltString) {
    try {
        console.log("=== RESPONSE DECRYPTION (Section 3.2) ===");

        // Step 1: Decode the response data
        const combined = Buffer.from(responseBody.data, 'base64');

        // Extract components: IV (12) + salt (32) + encrypted data
        const iv = combined.slice(0, 12);
        const responseSaltBytes = combined.slice(12, 44);
        const encryptedData = combined.slice(44);

        // For GCM, we need to separate the authTag (last 16 bytes)
        const authTag = encryptedData.slice(-16);
        const ciphertext = encryptedData.slice(0, -16);

        console.log("Step 1: Response data components extracted");

        // Step 2: Generate AES key using response salt
        const responseSaltString = responseSaltBytes.toString('utf8');
        const aesKey = generateAESKey(secretPlain, responseSaltString);
        console.log("Step 2: AES key regenerated for decryption");

        // Step 3: Decrypt the data using AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        console.log("Step 3: Data decrypted using AES-256-GCM");

        // The decrypted data should be Base64 encoded JSON
        const payloadBase64 = decrypted.toString('utf8');
        const payloadJson = Buffer.from(payloadBase64, 'base64').toString('utf8');

        // Step 4: Verify digital signature - Verify against the ENCRYPTED DATA
        if (!dgftPublicKey) {
            throw new Error("DGFT_PUBLIC_KEY required for signature verification");
        }

        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(responseBody.data);  // Verify against the encrypted data
        const isVerified = verifier.verify(dgftPublicKey, responseBody.sign, 'base64');

        if (!isVerified) {
            throw new Error('Response digital signature verification failed');
        }
        console.log("Step 4: Digital signature verified successfully");

        return JSON.parse(payloadJson);
    } catch (error) {
        console.error("Response decryption failed:", error);
        throw new Error(`Response decryption failed: ${error.message}`);
    }
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

    // FIXED: Handle DGFT's typo - accept both correct and incorrect spellings
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

            // Date format validation (ERR17, ERR24, ERR28)
            function isValidDateFormat(dateStr) {
                if (!/^\d{8}$/.test(dateStr)) return false;
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

            if (dto.irmDt && !isValidDateFormat(dto.irmDt)) {
                errors.push(`ERR17: Invalid IRM Date. Date shall be in ddMMYYYY format in record ${recordNum}`);
            }

            if (dto.paymentDate && !isValidDateFormat(dto.paymentDate)) {
                errors.push(`ERR24: Invalid paymentDate field in request JSON. Field is null or not in format ddMMyyyy in record ${recordNum}`);
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

            // Shipping bill number validation (ERR25)
            if (dto.shippingBillNo && dto.shippingBillNo.toString().length > 7) {
                errors.push(`ERR25: Invalid shipping bill number. It cannot be greater than 7 digit in record ${recordNum}`);
            }

            // Port code validation (ERR29)
            if (dto.portCode && dto.portCode.toString().length > 6) {
                errors.push(`ERR29: Invalid port code mentioned. Port code cannot be greater than 6 digit in length in record ${recordNum}`);
            }

            // Bill number validation (ERR31)
            if (dto.billNo && dto.billNo.toString().length > 20) {
                errors.push(`ERR31: Invalid billNo its values cannot be greater than 20 digit length in record ${recordNum}`);
            }

            // Vostro flag validation (ERR32)
            if (dto.isVostro && !['Y', 'N'].includes(dto.isVostro.toUpperCase())) {
                errors.push(`ERR32: Invalid values for isVostro flag. Allowed values are Y/N in record ${recordNum}`);
            }

            // Vostro type validation (ERR33)
            if (dto.vostroType && !['SVRA', 'NVRA'].includes(dto.vostroType.toUpperCase())) {
                errors.push(`ERR33: Invalid vostro type specified. Allowed values are SVRA/NVRA in record ${recordNum}`);
            }

            // Amount validation (ERR35)
            if (dto.irmRemitAmtFCC && (isNaN(dto.irmRemitAmtFCC) || dto.irmRemitAmtFCC <= 0)) {
                errors.push(`ERR35: Invalid ORM amount specified in record ${recordNum}`);
            }

            // Amount calculation for ERR38
            if (dto.irmRemitAmtFCC && !isNaN(dto.irmRemitAmtFCC)) {
                totalIrmMappedAmount += parseFloat(dto.irmRemitAmtFCC);
            }

            // Invoice and purpose code mapping validation for ERR39
            if (dto.sbCumInvoiceNumber && dto.irmPurposeCode) {
                const key = `${dto.sbCumInvoiceNumber}_${dto.irmPurposeCode}`;
                if (invoicePurposeMapping.has(key)) {
                    const existingRecord = invoicePurposeMapping.get(key);
                    if (existingRecord.irmRemitAmtFCC !== dto.irmRemitAmtFCC) {
                        errors.push(`ERR39: Invoice and purpose code mapping is not correct in record ${recordNum}`);
                    }
                } else {
                    invoicePurposeMapping.set(key, {
                        irmRemitAmtFCC: dto.irmRemitAmtFCC,
                        recordNum: recordNum
                    });
                }
            }
        });

        // Validate total amounts for ERR38
        if (payload.totalAvailableAmount && totalIrmMappedAmount > payload.totalAvailableAmount) {
            errors.push('ERR38: Total IRM mapped is more than available amount. Please check the calculation');
        }
    }

    if (errors.length > 0) {
        throw new Error(errors.join('; '));
    }

    console.log("Payload validation successful");
}

// File eBRC data
export const fileEbrcService = async (payload) => {
    try {
        const systemIP = await checkCurrentIP();

        // Validate payload against DGFT specifications
        validatePayload(payload);

        // Step 4: Get access token (valid for 5 minutes)
        const tokenResponse = await getSandboxToken();
        const accessToken = tokenResponse.data.accessToken;

        // Steps 1-5: Encryption and signature process 
        const encryptionResult = await encryptPayload(payload);

        const encryptedAESKey = encryptAESKey(encryptionResult.secretPlain);

        // Generate messageID if not provided
        const messageID = payload.requestId || crypto.randomUUID().substring(0, 50);

        // API call 
        const response = await axios.post(`${baseUrl}/pushIRMToGenEBRC`,
            {
                data: encryptionResult.encodedData,
                sign: encryptionResult.digitalSignature
            },
            {
                headers: {
                    "Content-Type": "application/json",
                    "accessToken": accessToken,
                    "client_id": clientId,
                    "secretVal": encryptedAESKey,
                },
                timeout: 30000,
            }
        );

        if (response.status !== 200) {

            console.error("Status Code:", response.status);
            console.error("Status Text:", response.statusText);

            const status = response.status.toString();
            const errorMsg = ERROR_CODES[status] || response.data?.message || `HTTP ${response.status}`;

            if (response.status === 403) {
                console.error("403 Access forbidden !");

            }
            throw new Error(`eBRC filing failed: ${errorMsg}`);
        }

        // Step 7: Decrypt and verify response - CORRECTED
        console.log("Decrypting and verifying response...");
        const decryptedData = decryptResponse(response.data, encryptionResult.secretPlain, encryptionResult.saltString);

        console.log("=== eBRC FILING SUCCESSFUL ===");
        return {
            success: true,
            messageID: messageID,
            data: decryptedData,
            message: "eBRC data filed successfully with DGFT",
            timestamp: new Date().toISOString(),
            systemIP: systemIP.ip
        };

    } catch (error) {
        console.error("=== eBRC FILING ERROR ===");
        console.error("Error type:", error.constructor.name);
        console.error("Error message:", error.message);
        console.error("Timestamp:", new Date().toISOString());

        if (error.response) {
            console.error("HTTP Status:", error.response.status);
            console.error("Response Headers:", JSON.stringify(error.response.headers, null, 2));
            console.error("Response Data:", JSON.stringify(error.response.data, null, 2));

            const status = error.response.status.toString();
            const errorMsg = ERROR_CODES[status] || error.response.data?.message || error.message;

            return {
                success: false,
                error: errorMsg,
                httpStatus: error.response.status,
                timestamp: new Date().toISOString(),
                details: error.response.data,
                headers: error.response.headers
            };
        }

        if (error.code) {
            console.error("Network error code:", error.code);
        }
        return {
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
};     
