import axios from "axios";


const ICEGATE_BASE_URL = process.env.ICEGATE_BASE_URL; // e.g. https://enquiry.icegate.gov.in
const ICEGATE_CLIENT_ID = process.env.ICEGATE_CLIENT_ID;
const ICEGATE_CLIENT_SECRET = process.env.ICEGATE_CLIENT_SECRET;

export async function getIncentivesByShippingBill(sbNo, sbDate, iec) {
    try {
        // Replace with actual ICEGATE endpoint and parameters as per API documentation
        const url = `${ICEGATE_BASE_URL}/api/incentives`;

        const params = {
            sbNo,
            sbDate, // format: DDMMYYYY or as required by ICEGATE
            iec
        };

        const headers = {
            "Content-Type": "application/json",
            "client_id": ICEGATE_CLIENT_ID,
            "client_secret": ICEGATE_CLIENT_SECRET
        };

        const { data } = await axios.post(url, params, { headers });
        return data;
    } catch (error) {
        throw new Error(
            error.response?.data?.message ||
            error.message ||
            "Failed to fetch incentives from ICEGATE"
        );
    }
}