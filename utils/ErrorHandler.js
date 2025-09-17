class ErrorHandler extends Error {
    constructor(errMessage, statusCode) {
        super(errMessage)
        this.statusCode = statusCode
    }
};


export default ErrorHandler; 