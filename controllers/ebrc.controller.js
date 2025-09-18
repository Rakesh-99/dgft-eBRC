import ErrorHandler from "../utils/ErrorHandler.js";
import expressAsyncHandler from 'express-async-handler';
import { fileEbrcService, getSandboxToken } from "../services/ebrc.service.js";






// for fetching sandbox token : 
export const getToken = async (req, res) => {
    try {
        const { data } = await getSandboxToken();
        return res.json({ success: true, data });
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


