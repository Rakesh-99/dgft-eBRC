import ErrorHandler from "../utils/ErrorHandler.js";
import expressAsyncHandler from 'express-async-handler';
import {
    fileEbrcService,
    getSandboxToken,

} from "../services/ebrc.service.js";

// For fetching sandbox token
export const getToken = async (req, res) => {
    try {
        const { data } = await getSandboxToken();
        return res.json({
            success: true,
            data,
            message: "Token generated successfully"
        });
    } catch (error) {
        console.error("Controller error:", error.message);
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

// Main eBRC filing function
export const fileEbrc = async (req, res) => {
    try {
        // Validate request body
        if (!req.body || Object.keys(req.body).length === 0) {
            return res.status(400).json({
                success: false,
                message: "Request body is required"
            });
        }

        console.log("=== INCOMING REQUEST ===");
        console.log("Request body:", JSON.stringify(req.body, null, 2));

        const response = await fileEbrcService(req.body);

        if (response.success) {
            return res.json({
                success: true,
                data: response,
                message: "eBRC filed successfully"
            });
        } else {
            console.log("Response ------------------------------------------>", response);

            return res.status(response.httpStatus).json({
                success: response.success,
                message: response.error || "Failed to file eBRC",
                details: response.headers || response.data || null
            });
        }
    } catch (error) {
        console.error("=== CONTROLLER ERROR ===", error);
        console.error("Error message:", error.message);

        return res.status(error.httpStatus).json({
            success: error.response?.status === 400 ? 400 : 500,
            message: error.message,
            details: error.response?.data
        });
    }
};
