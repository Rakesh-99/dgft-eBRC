import ErrorHandler from "../utils/ErrorHandler.js";
import expressAsyncHandler from 'express-async-handler';
import { fileEbrcService, getSandboxToken } from "../services/ebrc.service.js";






// for fetching sandbox token : 
export const getToken = async (req, res) => {
    try {
        const token = await getSandboxToken();
        return res.json({ success: true, token });
    } catch (error) {
        console.error("Controller error:", error.message);
        return res.status(500).json({ success: false, message: error.message });
    }
};



export const fileEbrc = async (req, res) => {
    try {

        // Validate request body
        if (!req.body || Object.keys(req.body).length === 0) {
            return res.status(400).json({
                success: false,
                message: "Request body is required"
            });
        }
        const response = await fileEbrcService(req.body);
        return res.json({ success: true, data: response });
    } catch (error) {
        // Return more detailed error information
        return res.status(500).json({
            success: false,
            message: error.message,
            details: error.response?.data
        });
    }
};


export const testEbrcWithSampleData = async (req, res) => {
    try {
        // Sample data matching DGFT documentation format
        const testPayload = {
            "iecNumber": "1234567890", // Replace with your actual IEC
            "requestId": `TEST_${Date.now()}`,
            "recordResCount": 1,
            "uploadType": 101, // Direct Export
            "decalarationFlag": "Y",
            "ebrcBulkGenDtos": [
                {
                    "serialNo": 1,
                    "uploadType": 101,
                    "branchSlNo": 0,
                    "irmIfscCode": "TEST0000001",
                    "irmAdCode": "TEST01",
                    "irmNumber": "TEST_IRM_001",
                    "irmDt": "15122023",
                    "irmFCC": "USD",
                    "irmPurposeCode": "P0101",
                    "irmRemitAmtFCC": 1000.00,
                    "sbCumInvoiceNumber": "TEST_SB_001",
                    "sbCumInvoiceDate": "15122023",
                    "portCode": "INNSA1",
                    "billNo": "TEST_BILL_001",
                    "sbCumInvoiceFCC": "USD",
                    "sbCumInvoiceValueinFCC": 1000.00,
                    "mappedIRMAmountFCC": 1000.00,
                    "isVostro": "N",
                    "vostroType": null,
                    "mappedORMAmountFCC": 0,
                    "isThirdPartyExport": "N"
                }
            ]
        };

        const response = await fileEbrcService(testPayload);
        return res.json({ 
            success: true, 
            message: "Test eBRC filed successfully",
            data: response 
        });
    } catch (error) {
        console.error("Test eBRC Error:", error.message);
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
};