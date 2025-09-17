import axios from 'axios';

const testEbrcAPI = async () => {
    const testData = {
        // Add sample eBRC data based on DGFT requirements
        exporterDetails: {
            iecCode: "TEST123456789",
            exporterName: "Test Exporter",
            address: "Test Address"
        },
        shipmentDetails: {
            invoiceNumber: "INV001",
            invoiceDate: "2025-09-15",
            exportValue: 100000
        }
        // Add more fields as per DGFT eBRC schema
    };

    try {
        const response = await axios.post('http://localhost:8000/api/v1/file', testData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        console.log('Success:', response.data);
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
    }
};

testEbrcAPI();